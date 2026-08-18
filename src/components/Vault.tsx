import { useCallback, useEffect, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api } from "../api";
import { deleteMessage, failMessage, summaryText, t } from "../i18n";
import type { AccountMeta, CodeInfo } from "../types";
import AccountCard from "./AccountCard";
import AccountDialog from "./AccountDialog";
import ChangePasswordDialog from "./ChangePasswordDialog";
import ConfirmDialog from "./ConfirmDialog";
import ImportPasswordDialog from "./ImportPasswordDialog";
import Toast from "./Toast";

export default function Vault({ onLock }: { onLock: () => void }) {
    const [accounts, setAccounts] = useState<AccountMeta[]>([]);
    const [codes, setCodes] = useState<Record<string, CodeInfo>>({});
    const [dialog, setDialog] = useState<
        { mode: "add" } | { mode: "edit"; account: AccountMeta } | null
    >(null);
    const [deleting, setDeleting] = useState<AccountMeta | null>(null);
    const [importPath, setImportPath] = useState<string | null>(null);
    const [changingPassword, setChangingPassword] = useState(false);
    const [toast, setToast] = useState("");
    const toastTimer = useRef(0);
    const accountsRef = useRef(accounts);
    accountsRef.current = accounts;

    const loadAccounts = useCallback(async () => {
        setAccounts(await api.listAccounts());
    }, []);

    useEffect(() => {
        loadAccounts();
    }, [loadAccounts]);

    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            const list = accountsRef.current;
            const entries = await Promise.all(
                list.map(async (a) => {
                    try {
                        return [a.id, await api.getCode(a.id)] as const;
                    } catch {
                        return null;
                    }
                }),
            );
            if (cancelled) return;
            const next: Record<string, CodeInfo> = {};
            for (const e of entries) {
                if (e) next[e[0]] = e[1];
            }
            setCodes(next);
        };
        tick();
        const timer = window.setInterval(tick, 1000);
        return () => {
            cancelled = true;
            window.clearInterval(timer);
        };
    }, [accounts]);

    const flash = (msg: string, ms = 2500) => {
        setToast(msg);
        window.clearTimeout(toastTimer.current);
        toastTimer.current = window.setTimeout(() => setToast(""), ms);
    };

    const lock = async () => {
        await api.lock();
        onLock();
    };

    const exportBackup = async () => {
        const path = await save({
            defaultPath: "2fac-backup.dat",
            filters: [{ name: "2FAC backup", extensions: ["dat"] }],
        });
        if (!path) return;
        try {
            await api.exportBackup(path);
            flash(t.backupExported, 4000);
        } catch (e) {
            flash(failMessage(t.exportFailed, e), 4000);
        }
    };

    const tryImport = async (
        path: string,
        password?: string,
    ): Promise<string | null> => {
        try {
            const summary = await api.importFile(path, password);
            setImportPath(null);
            await loadAccounts();
            flash(summaryText(summary), 4000);
            return null;
        } catch (e) {
            const msg = String(e);
            if (msg === "PASSWORD_REQUIRED") {
                setImportPath(path);
                return null;
            }
            return msg;
        }
    };

    const importFile = async () => {
        const path = await open({
            filters: [
                {
                    name: "Authenticator data",
                    extensions: ["dat", "json", "txt"],
                },
            ],
        });
        if (!path || typeof path !== "string") return;
        const err = await tryImport(path);
        if (err) flash(failMessage(t.importFailed, err), 4000);
    };

    const submitImportPassword = async (
        password: string,
    ): Promise<string | null> => {
        if (!importPath) return null;
        return tryImport(importPath, password);
    };

    return (
        <div className="screen">
            <div className="header">
                <h1 className="wordmark">2FAC</h1>
                <button className="icon" onClick={exportBackup}>
                    {t.export}
                </button>
                <button className="icon" onClick={importFile}>
                    {t.import}
                </button>
                <button
                    className="icon"
                    onClick={() => setChangingPassword(true)}
                >
                    {t.changePassword}
                </button>
                <button className="icon" onClick={lock}>
                    {t.lock}
                </button>
            </div>

            <div className="list">
                {accounts.length === 0 && (
                    <div className="empty">
                        <div className="empty-title">{t.emptyTitle}</div>
                        {t.emptyDesc}
                    </div>
                )}
                {accounts.map((a) => (
                    <AccountCard
                        key={a.id}
                        account={a}
                        code={codes[a.id]}
                        onEdit={() => setDialog({ mode: "edit", account: a })}
                        onDelete={() => setDeleting(a)}
                        onCopied={() => flash(t.copied)}
                    />
                ))}
            </div>

            <div className="toolbar">
                <button
                    className="primary"
                    onClick={() => setDialog({ mode: "add" })}
                >
                    {t.addAccount}
                </button>
            </div>

            <Toast message={toast} />

            {dialog && (
                <AccountDialog
                    account={
                        dialog.mode === "edit" ? dialog.account : undefined
                    }
                    onClose={() => setDialog(null)}
                    onSaved={async (note) => {
                        setDialog(null);
                        await loadAccounts();
                        if (note) flash(note, 4000);
                    }}
                />
            )}

            {deleting && (
                <ConfirmDialog
                    title={t.deleteTitle}
                    message={deleteMessage(deleting.issuer || deleting.name)}
                    confirmLabel={t.delete}
                    onCancel={() => setDeleting(null)}
                    onConfirm={async () => {
                        await api.deleteAccount(deleting.id);
                        setDeleting(null);
                        await loadAccounts();
                    }}
                />
            )}

            {importPath && (
                <ImportPasswordDialog
                    onSubmit={submitImportPassword}
                    onCancel={() => setImportPath(null)}
                />
            )}

            {changingPassword && (
                <ChangePasswordDialog
                    onClose={() => setChangingPassword(false)}
                />
            )}
        </div>
    );
}
