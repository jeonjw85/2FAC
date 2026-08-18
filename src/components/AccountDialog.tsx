import { useRef, useState } from "react";
import { api } from "../api";
import { localizeError, summaryText, t } from "../i18n";
import { decodeQrFromFile } from "../qr";
import type { AccountMeta, Algorithm } from "../types";

type Tab = "manual" | "uri" | "qr";

export default function AccountDialog({
  account,
  onClose,
  onSaved,
}: {
  account?: AccountMeta;
  onClose: () => void;
  onSaved: (note?: string) => void;
}) {
  const editing = !!account;
  const [tab, setTab] = useState<Tab>("manual");
  const [issuer, setIssuer] = useState(account?.issuer ?? "");
  const [name, setName] = useState(account?.name ?? "");
  const [secret, setSecret] = useState("");
  const [algorithm, setAlgorithm] = useState<Algorithm>((account?.algorithm as Algorithm) ?? "SHA1");
  const [digits, setDigits] = useState(account?.digits ?? 6);
  const [period, setPeriod] = useState(account?.period ?? 30);
  const [uri, setUri] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const saveManual = async () => {
    setError("");
    if (!name.trim()) return setError(t.errNameRequired);
    if (!editing && !secret.trim()) return setError(t.errSecretRequired);
    setBusy(true);
    try {
      if (editing && account) {
        await api.updateAccount({
          id: account.id,
          issuer: issuer.trim(),
          name: name.trim(),
          algorithm,
          digits,
          period,
          secret: secret.trim() || undefined,
        });
      } else {
        await api.addAccount({
          issuer: issuer.trim(),
          name: name.trim(),
          secret: secret.trim(),
          algorithm,
          digits,
          period,
        });
      }
      onSaved();
    } catch (e) {
      setError(localizeError(e));
    } finally {
      setBusy(false);
    }
  };

  const saveUri = async () => {
    setError("");
    if (!uri.trim()) return setError(t.errUriRequired);
    setBusy(true);
    try {
      const summary = await api.importUri(uri.trim());
      onSaved(summaryText(summary));
    } catch (e) {
      setError(localizeError(e));
    } finally {
      setBusy(false);
    }
  };

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setError("");
    setBusy(true);
    try {
      const data = await decodeQrFromFile(file);
      const summary = await api.importUri(data);
      onSaved(summaryText(summary));
    } catch (e) {
      setError(localizeError(e));
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h2>{editing ? t.editAccount : t.addAccountTitle}</h2>

        {!editing && (
          <div className="tabs">
            <button className={tab === "manual" ? "active" : ""} onClick={() => setTab("manual")}>{t.tabManual}</button>
            <button className={tab === "uri" ? "active" : ""} onClick={() => setTab("uri")}>{t.tabUri}</button>
            <button className={tab === "qr" ? "active" : ""} onClick={() => setTab("qr")}>{t.tabQr}</button>
          </div>
        )}

        {(editing || tab === "manual") && (
          <div className="col">
            <label>{t.issuer}<input value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="GitHub" /></label>
            <label>{t.accountName}<input value={name} onChange={(e) => setName(e.target.value)} placeholder="you@example.com" /></label>
            <label>
              {editing ? t.newSecretKeep : t.base32Secret}
              <input value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="JBSWY3DPEHPK3PXP" />
            </label>
            <div className="grid2">
              <label>{t.algorithm}
                <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as Algorithm)}>
                  <option value="SHA1">SHA1</option>
                  <option value="SHA256">SHA256</option>
                  <option value="SHA512">SHA512</option>
                </select>
              </label>
              <label>{t.period}<input type="number" min={5} max={600} value={period} onChange={(e) => setPeriod(Number(e.target.value))} /></label>
            </div>
            <label>{t.digits}<input type="number" min={4} max={9} value={digits} onChange={(e) => setDigits(Number(e.target.value))} /></label>
            <div className="error">{error}</div>
            <div className="row">
              <button className="primary" onClick={saveManual} disabled={busy}>{busy ? t.saving : t.save}</button>
              <button onClick={onClose}>{t.cancel}</button>
            </div>
          </div>
        )}

        {!editing && tab === "uri" && (
          <div className="col">
            <label>otpauth:// URI<textarea value={uri} onChange={(e) => setUri(e.target.value)} placeholder="otpauth://totp/Example:you@example.com?secret=…" /></label>
            <p className="footer-note">{t.uriNote}</p>
            <div className="error">{error}</div>
            <div className="row">
              <button className="primary" onClick={saveUri} disabled={busy}>{busy ? t.adding : t.add}</button>
              <button onClick={onClose}>{t.cancel}</button>
            </div>
          </div>
        )}

        {!editing && tab === "qr" && (
          <div className="col">
            <p className="footer-note">{t.qrNote}</p>
            <input ref={fileRef} type="file" accept="image/*" onChange={(e) => onFile(e.target.files?.[0])} />
            <div className="error">{error}</div>
            <div className="row">
              <button onClick={onClose}>{t.cancel}</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
