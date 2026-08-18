use serde::Serialize;
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;

use crate::commands::AppState;

#[derive(Serialize)]
pub struct UpdateInfo {
    pub version: String,
}

#[tauri::command]
pub async fn check_update(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    let Ok(updater) = app.updater() else {
        return Ok(None);
    };
    match updater.check().await {
        Ok(Some(update)) => Ok(Some(UpdateInfo {
            version: update.version,
        })),
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(state) = app.try_state::<AppState>() {
        let _ = state.lock_now();
    }
    let updater = app.updater().map_err(|_| "Update failed".to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|_| "Update failed".to_string())?
        .ok_or_else(|| "Update failed".to_string())?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|_| "Update failed".to_string())?;
    app.restart();
}
