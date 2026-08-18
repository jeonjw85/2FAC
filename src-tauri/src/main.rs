#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    totp_vault_lib::run()
}
