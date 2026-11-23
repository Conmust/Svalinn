#[cfg(desktop)]
mod gauge;

/// Shared entry point for every Tauri target (desktop binary and, once
/// `tauri android init` / `tauri ios init` have been run on a machine with
/// the relevant SDKs, the generated mobile app shells call this too).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();

    #[cfg(desktop)]
    let builder = builder
        .manage(gauge::GaugeState::new())
        .invoke_handler(tauri::generate_handler![gauge::get_gauge_stats]);

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
