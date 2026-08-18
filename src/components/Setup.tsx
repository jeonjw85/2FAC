import { useState } from "react";
import { api } from "../api";
import { localizeError, t } from "../i18n";

export default function Setup({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError("");
    if (password.length < 8) {
      setError(t.errPasswordShort);
      return;
    }
    if (password !== confirm) {
      setError(t.errPasswordMismatch);
      return;
    }
    setBusy(true);
    try {
      await api.setup(password);
      onDone();
    } catch (e) {
      setError(localizeError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <div className="auth-card">
        <h1>2fac</h1>
        <p>{t.setupDesc}</p>
        <input
          type="password"
          placeholder={t.masterPassword}
          value={password}
          autoFocus
          onChange={(e) => setPassword(e.target.value)}
        />
        <input
          type="password"
          placeholder={t.confirmPassword}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <div className="error">{error}</div>
        <button className="primary" onClick={submit} disabled={busy}>
          {busy ? t.creating : t.createVault}
        </button>
      </div>
    </div>
  );
}
