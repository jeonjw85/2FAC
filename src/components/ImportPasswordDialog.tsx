import { useState } from "react";
import { localizeError, t } from "../i18n";

export default function ImportPasswordDialog({
  onSubmit,
  onCancel,
}: {
  onSubmit: (password: string) => Promise<string | null>;
  onCancel: () => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!password || busy) return;
    setBusy(true);
    setError("");
    const err = await onSubmit(password);
    if (err) {
      setError(localizeError(err));
      setBusy(false);
    }
  };

  return (
    <div className="overlay" onClick={onCancel}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h2>{t.encryptedBackup}</h2>
        <p className="footer-note">{t.importPasswordNote}</p>
        <input
          type="password"
          placeholder={t.backupPassword}
          value={password}
          autoFocus
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <div className="error">{error}</div>
        <div className="row">
          <button className="primary" onClick={submit} disabled={busy || !password}>
            {busy ? t.importing : t.import}
          </button>
          <button onClick={onCancel}>{t.cancel}</button>
        </div>
      </div>
    </div>
  );
}
