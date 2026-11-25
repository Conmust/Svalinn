#[cfg(desktop)]
mod gauge;

#[cfg(desktop)]
use tauri::Manager;

/// Shared entry point for every Tauri target (desktop binary and, once
/// `tauri android init` / `tauri ios init` have been run on a machine with
/// the relevant SDKs, the generated mobile app shells call this too).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();

    // Desktop-only, and registered FIRST per the plugin's own setup
    // instructions. Without this, launching the app a second time (two
    // separate OS processes, each with its own webview and local storage)
    // let both processes race to set up encryption from scratch on first
    // ever launch -- each generating and registering its OWN device
    // keypair with the server for what the user thinks of as one install.
    // This closes that off at the root by refusing the second launch
    // outright and focusing the window that's already open, rather than
    // trying to coordinate two already-running, separate native processes
    // after the fact. See `crypto.ts`'s `ensureDeviceKeypair` doc comment
    // for the matching client-side guard, which covers the one case this
    // plugin can't: two tabs of the web (non-Tauri) build sharing one
    // browser's `localStorage`.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.set_focus();
            if window.is_minimized().unwrap_or(false) {
                let _ = window.unminimize();
            }
        }
    }));

    #[cfg(desktop)]
    let builder = builder
        .manage(gauge::GaugeState::new())
        .invoke_handler(tauri::generate_handler![gauge::get_gauge_stats]);

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
