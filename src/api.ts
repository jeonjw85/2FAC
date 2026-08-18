import { invoke } from "@tauri-apps/api/core";
import type { AccountMeta, CodeInfo, ImportSummary, Status, UpdateInfo } from "./types";

export const api = {
  status: () => invoke<Status>("status"),
  setup: (password: string) => invoke<void>("setup", { password }),
  unlock: (password: string) => invoke<void>("unlock", { password }),
  lock: () => invoke<void>("lock"),
  changePassword: (current: string, newPassword: string) =>
    invoke<void>("change_password", { current, new: newPassword }),
  listAccounts: () => invoke<AccountMeta[]>("list_accounts"),
  addAccount: (input: {
    issuer: string;
    name: string;
    secret: string;
    algorithm: string;
    digits: number;
    period: number;
  }) => invoke<AccountMeta>("add_account", input),
  importUri: (uri: string) => invoke<ImportSummary>("import_uri", { uri }),
  updateAccount: (input: {
    id: string;
    issuer: string;
    name: string;
    algorithm: string;
    digits: number;
    period: number;
    secret?: string;
  }) => invoke<AccountMeta>("update_account", input),
  deleteAccount: (id: string) => invoke<void>("delete_account", { id }),
  getCode: (id: string) => invoke<CodeInfo>("get_code", { id }),
  exportBackup: (path: string) => invoke<void>("export_backup", { path }),
  importFile: (path: string, password?: string) =>
    invoke<ImportSummary>("import_file", { path, password }),
  checkUpdate: () => invoke<UpdateInfo | null>("check_update"),
  installUpdate: () => invoke<void>("install_update"),
};
