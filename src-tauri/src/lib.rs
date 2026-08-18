mod commands;
mod gauth;
mod import;
mod otpauth;
mod totp;
mod vault;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            app.manage(commands::AppState::new(dir.join("vault.dat")));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let state = window.app_handle().state::<commands::AppState>();
                let _ = state.lock_now();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::setup,
            commands::unlock,
            commands::lock,
            commands::change_password,
            commands::list_accounts,
            commands::add_account,
            commands::import_uri,
            commands::update_account,
            commands::delete_account,
            commands::get_code,
            commands::export_backup,
            commands::import_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
