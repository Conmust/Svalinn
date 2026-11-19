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
pub struct GaugeStats {
    /// Resident-set size, in bytes, summed across our process tree.
    pub memory_bytes: u64,
    /// CPU usage in percent, summed across our process tree. May exceed
    /// 100% on a multi-core machine if more than one core's worth of work
    /// is in flight — intentional, matches what tools like Activity
    /// Monitor / Task Manager show for multi-threaded processes.
    pub cpu_percent: f32,
    /// How many OS processes (main + any webview/GPU helpers) were summed.
    pub process_count: u32,
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

    let mut memory_bytes = 0u64;
    let mut cpu_percent = 0f32;
    let mut process_count = 0u32;

    for pid in &tree {
        if let Some(process) = processes.get(pid) {
            memory_bytes = memory_bytes.saturating_add(process.memory());
            cpu_percent += process.cpu_usage();
            process_count += 1;
        }
    }

    GaugeStats {
        memory_bytes,
        cpu_percent,
        process_count,
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
            first.memory_bytes > 0,
            "our own process should report nonzero RSS"
        );
        assert!(
            first.process_count >= 1,
            "should at least find our own process"
        );

        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);

        let second = compute_stats(&mut sys);
        assert!(second.memory_bytes > 0);
        assert!(second.process_count >= 1);
        assert!(
            second.cpu_percent >= 0.0,
            "cpu usage should never be negative"
        );
    }

    #[test]
    fn reject_if_empty_errors_on_zero_processes() {
        let empty = GaugeStats {
            memory_bytes: 0,
            cpu_percent: 0.0,
            process_count: 0,
        };
        assert!(
            reject_if_empty(empty).is_err(),
            "zero processes found should be an error, not a misleadingly-zero success"
        );
    }

    #[test]
    fn reject_if_empty_passes_through_real_stats() {
        let real = GaugeStats {
            memory_bytes: 1234,
            cpu_percent: 5.0,
            process_count: 2,
        };
        let result = reject_if_empty(real).expect("nonzero process_count should pass through");
        assert_eq!(result.memory_bytes, 1234);
    }
}
