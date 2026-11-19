//! Backend for the "Svalinn Gauge" — a small RAM/CPU readout for the desktop
//! client. See README.md's "The Svalinn Gauge" section for the product intent.
//!
//! Tauri's webview isn't a single OS process: on Linux the WebKitGTK renderer
//! (and on some platforms helper/GPU processes) run as children of the main
//! process. A reading of just `std::process::id()` would understate real
//! usage, so this sums RSS and CPU% across the current process and every
//! descendant in the OS process tree.
//!
//! **Known limitation (macOS):** this walk uses `Process::parent()`, which
//! reflects the OS-reported PPID. On Linux, WebKitGTK's WebProcess/
//! NetworkProcess helpers are true child processes of the app, so the walk
//! finds them. On macOS, Tauri's webview is `WKWebView`, and its actual
//! content-rendering/networking/GPU processes
//! (`com.apple.WebKit.WebContent` etc.) are spawned by `launchd` via XPC —
//! their real PPID is `launchd` (pid 1), not ours, even though Activity
//! Monitor visually nests them under the app. So on macOS this will
//! currently undercount, reporting close to just the thin Rust shell rather
//! than the full app — the exact failure mode this README calls out
//! ("memory reporting must account for the relevant app process tree, not
//! just the Rust process"). Fixing it needs a macOS-specific approach
//! (matching candidate processes by executable path/bundle identifier, or
//! an XPC-aware API) that cannot be written with confidence or verified
//! without a macOS environment, which this project doesn't yet have in CI
//! or in the sandbox. Left as a known gap rather than a silent,
//! unverified "fix" — revisit once macOS builds exist.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Persistent `System` handle, refreshed on every call rather than rebuilt
/// from scratch — `sysinfo::System::new_all()` is comparatively expensive,
/// and process CPU-usage figures only become accurate once a process has
/// been refreshed at least twice with time between each refresh (see
/// `sysinfo::MINIMUM_CPU_UPDATE_INTERVAL`), which a persistent handle gives
/// us for free across polls.
pub struct GaugeState(Mutex<Option<System>>);

impl GaugeState {
    pub fn new() -> Self {
        // Lazily constructed on first use (see `get_gauge_stats`) rather than
        // here, since `System::new()` can fail on unsupported platforms and
        // a monitoring feature failing to init shouldn't take the app's
        // startup down with it.
        Self(Mutex::new(None))
    }
}

#[derive(Serialize)]
pub struct ProcessGroup {
    /// Executable name as reported by the OS (e.g. "msedgewebview2.exe").
    pub name: String,
    /// How many processes with this name are in our tree (webview engines
    /// commonly spawn several: browser/renderer/GPU/network, etc.).
    pub process_count: u32,
    /// Resident-set size, in bytes, summed across those processes.
    pub memory_bytes: u64,
}

#[derive(Serialize)]
pub struct GaugeStats {
    /// Resident-set size, in bytes, of just our own process — the Rust
    /// binary itself, excluding any webview/GPU helper processes. This is
    /// the number comparable to the README's memory target.
    pub app_memory_bytes: u64,
    /// CPU usage in percent of just our own process.
    pub app_cpu_percent: f32,
    /// Resident-set size, in bytes, summed across our entire process tree
    /// (our own process plus every descendant: webview renderer/GPU/network
    /// helpers, etc.). This is what a user's Task Manager/Activity Monitor
    /// total actually reflects.
    pub total_memory_bytes: u64,
    /// CPU usage in percent, summed across our entire process tree. May
    /// exceed 100% on a multi-core machine if more than one core's worth of
    /// work is in flight — intentional, matches what tools like Activity
    /// Monitor / Task Manager show for multi-threaded processes.
    pub total_cpu_percent: f32,
    /// How many OS processes (main + any webview/GPU helpers) were summed
    /// into `total_memory_bytes`.
    pub process_count: u32,
    /// Everything in the tree other than our own process, grouped by
    /// executable name and sorted largest-first — e.g. so the UI can show
    /// "msedgewebview2.exe (4 processes): 390 MB" when a user asks why
    /// total usage is higher than the app's own footprint.
    pub other_processes: Vec<ProcessGroup>,
}

fn get_gauge_stats_impl(state: tauri::State<'_, GaugeState>) -> Result<GaugeStats, String> {
    let mut guard = state
        .0
        .lock()
        .map_err(|_| "gauge state lock was poisoned".to_string())?;

    if guard.is_none() {
        let sys = System::new().map_err(|e| format!("failed to init sysinfo: {e}"))?;
        *guard = Some(sys);
    }

    // `is_none()` was just ruled out above, so this always has a value.
    let sys = guard.as_mut().expect("gauge system was just initialized");
    Ok(compute_stats(sys))
}

/// Does the actual refresh + process-tree summation. Split out from the
/// `#[tauri::command]` wrapper so it's callable from tests without needing
/// a real `tauri::State` (which has no public constructor outside the
/// framework's own command-dispatch machinery).
fn compute_stats(sys: &mut System) -> GaugeStats {
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_memory().with_cpu(),
    );

    let our_pid = Pid::from_u32(std::process::id());
    let processes = sys.processes();

    // Build a child -> parent map once, then walk out from our own pid to
    // find every descendant, however deep (webview helpers spawning their
    // own helpers, etc.).
    let mut children_of: HashMap<Pid, Vec<Pid>> = HashMap::new();
    for (pid, process) in processes {
        if let Some(parent) = process.parent() {
            children_of.entry(parent).or_default().push(*pid);
        }
    }

    let mut tree = vec![our_pid];
    let mut frontier = vec![our_pid];
    while let Some(pid) = frontier.pop() {
        if let Some(children) = children_of.get(&pid) {
            for &child in children {
                tree.push(child);
                frontier.push(child);
            }
        }
    }

    let mut app_memory_bytes = 0u64;
    let mut app_cpu_percent = 0f32;
    let mut total_memory_bytes = 0u64;
    let mut total_cpu_percent = 0f32;
    let mut process_count = 0u32;
    // name -> (process_count, memory_bytes), for everything that isn't us.
    let mut other_groups: HashMap<String, (u32, u64)> = HashMap::new();

    for pid in &tree {
        if let Some(process) = processes.get(pid) {
            let memory = process.memory();
            let cpu = process.cpu_usage();

            total_memory_bytes = total_memory_bytes.saturating_add(memory);
            total_cpu_percent += cpu;
            process_count += 1;

            if *pid == our_pid {
                app_memory_bytes = memory;
                app_cpu_percent = cpu;
            } else {
                let name = process.name().to_string_lossy().into_owned();
                let entry = other_groups.entry(name).or_insert((0, 0));
                entry.0 += 1;
                entry.1 = entry.1.saturating_add(memory);
            }
        }
    }

    let mut other_processes: Vec<ProcessGroup> = other_groups
        .into_iter()
        .map(|(name, (process_count, memory_bytes))| ProcessGroup {
            name,
            process_count,
            memory_bytes,
        })
        .collect();
    other_processes.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));

    GaugeStats {
        app_memory_bytes,
        app_cpu_percent,
        total_memory_bytes,
        total_cpu_percent,
        process_count,
        other_processes,
    }
}

#[tauri::command]
pub fn get_gauge_stats(state: tauri::State<'_, GaugeState>) -> Result<GaugeStats, String> {
    reject_if_empty(get_gauge_stats_impl(state)?)
}

/// If our own process never showed up in the just-refreshed table (e.g. a
/// permission-restricted platform, or a race on the very first refresh),
/// returning an all-zero `Ok` would render as a plausible-looking but wrong
/// "[ 0 MB | 0.0% CPU ]" instead of the frontend's "unavailable" state. Fail
/// loudly instead. Split out as a pure function so it's unit-testable
/// without a real `tauri::State`.
fn reject_if_empty(stats: GaugeStats) -> Result<GaugeStats, String> {
    if stats.process_count == 0 {
        Err("could not find our own process in the system process table".to_string())
    } else {
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_at_least_our_own_process() {
        let mut sys = System::new().expect("sysinfo should initialize in the test environment");

        // First call: CPU% isn't meaningful yet (needs two refreshes with a
        // gap between them per sysinfo's docs), but memory and process count
        // should already be sane.
        let first = compute_stats(&mut sys);
        assert!(
            first.app_memory_bytes > 0,
            "our own process should report nonzero RSS"
        );
        assert!(
            first.total_memory_bytes >= first.app_memory_bytes,
            "total should never be less than our own process's share of it"
        );
        assert!(
            first.process_count >= 1,
            "should at least find our own process"
        );

        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);

        let second = compute_stats(&mut sys);
        assert!(second.app_memory_bytes > 0);
        assert!(second.total_memory_bytes > 0);
        assert!(second.process_count >= 1);
        assert!(
            second.total_cpu_percent >= 0.0,
            "cpu usage should never be negative"
        );
    }

    #[test]
    fn reject_if_empty_errors_on_zero_processes() {
        let empty = GaugeStats {
            app_memory_bytes: 0,
            app_cpu_percent: 0.0,
            total_memory_bytes: 0,
            total_cpu_percent: 0.0,
            process_count: 0,
            other_processes: Vec::new(),
        };
        assert!(
            reject_if_empty(empty).is_err(),
            "zero processes found should be an error, not a misleadingly-zero success"
        );
    }

    #[test]
    fn reject_if_empty_passes_through_real_stats() {
        let real = GaugeStats {
            app_memory_bytes: 1000,
            app_cpu_percent: 2.0,
            total_memory_bytes: 1234,
            total_cpu_percent: 5.0,
            process_count: 2,
            other_processes: vec![ProcessGroup {
                name: "helper.exe".to_string(),
                process_count: 1,
                memory_bytes: 234,
            }],
        };
        let result = reject_if_empty(real).expect("nonzero process_count should pass through");
        assert_eq!(result.total_memory_bytes, 1234);
        assert_eq!(result.app_memory_bytes, 1000);
        assert_eq!(result.other_processes.len(), 1);
    }
}
