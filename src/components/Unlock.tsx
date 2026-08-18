import { useState } from "react";
import { api } from "../api";
import { localizeError, t } from "../i18n";

export default function Unlock({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError("");
    if (!password) return;
    setBusy(true);
    try {
      await api.unlock(password);
      onDone();
    } catch (e) {
      setError(localizeError(e));
    } finally {
      setBusy(false);
      setPassword("");
    }
  };

  return (
    <div className="auth">
      <div className="auth-card">
        <h1>{t.locked}</h1>
        <p>{t.unlockDesc}</p>
        <input
          type="password"
          placeholder={t.masterPassword}
          value={password}
          autoFocus
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <div className="error">{error}</div>
        <button className="primary" onClick={submit} disabled={busy || !password}>
          {busy ? t.unlocking : t.unlock}
        </button>
      </div>
    </div>
  );
}
