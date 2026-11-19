#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod gauge;

fn main() {
    tauri::Builder::default()
        .manage(gauge::GaugeState::new())
        .invoke_handler(tauri::generate_handler![gauge::get_gauge_stats])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
