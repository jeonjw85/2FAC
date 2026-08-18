import { useState } from "react";
import { api } from "../api";
import { localizeError, t } from "../i18n";

export default function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError("");
    if (!current || !next) return;
    if (next.length < 8) {
      setError(t.errPasswordShort);
      return;
    }
    if (next !== confirm) {
      setError(t.errPasswordMismatch);
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(current, next);
      onClose();
    } catch (e) {
      setError(localizeError(e));
      setBusy(false);
    }
  };

  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h2>{t.changePasswordTitle}</h2>
        <p className="footer-note">{t.changePasswordNote}</p>
        <input
          type="password"
          placeholder={t.currentPassword}
          value={current}
          autoFocus
          onChange={(e) => setCurrent(e.target.value)}
        />
        <input
          type="password"
          placeholder={t.newPassword}
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
        <input
          type="password"
          placeholder={t.confirmPassword}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
        <div className="error">{error}</div>
        <div className="row">
          <button className="primary" onClick={submit} disabled={busy || !current || !next}>
            {busy ? t.changing : t.change}
          </button>
          <button onClick={onClose}>{t.cancel}</button>
        </div>
      </div>
    </div>
  );
}
