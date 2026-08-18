import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import Setup from "./components/Setup";
import Unlock from "./components/Unlock";
import Vault from "./components/Vault";
import { localizeError, t, updateMessage } from "./i18n";
import "./styles.css";

type Phase = "loading" | "setup" | "locked" | "unlocked";

const IDLE_LOCK_MS = 5 * 60 * 1000;

export default function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [updateVersion, setUpdateVersion] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);
  const [updateError, setUpdateError] = useState("");

  const refresh = useCallback(async () => {
    const s = await api.status();
    setPhase(!s.initialized ? "setup" : s.unlocked ? "unlocked" : "locked");
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    let cancelled = false;
    api.checkUpdate().then((info) => {
      if (!cancelled && info) setUpdateVersion(info.version);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (phase !== "unlocked") return;
    let timer: number | undefined;
    const arm = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        api.lock().then(() => setPhase("locked"));
      }, IDLE_LOCK_MS);
    };
    const events = ["pointerdown", "keydown", "wheel"] as const;
    events.forEach((e) => window.addEventListener(e, arm));
    arm();
    return () => {
      events.forEach((e) => window.removeEventListener(e, arm));
      window.clearTimeout(timer);
    };
  }, [phase]);

  const prompt = updateVersion ? (
    <div className="overlay">
      <div className="dialog">
        <h2>{t.updateTitle}</h2>
        <p className="footer-note">{updateMessage(updateVersion)}</p>
        {updateError ? <div className="error">{updateError}</div> : null}
        <div className="row">
          <button
            className="primary"
            disabled={updating}
            onClick={() => {
              setUpdating(true);
              setUpdateError("");
              api.installUpdate()
                .catch((e) => {
                  setUpdating(false);
                  setUpdateError(localizeError(e) || t.updateFailed);
                });
            }}
          >
            {updating ? t.updateInstalling : t.updateInstall}
          </button>
          <button disabled={updating} onClick={() => setUpdateVersion(null)}>
            {t.cancel}
          </button>
        </div>
      </div>
    </div>
  ) : null;

  if (phase === "loading") return <div className="screen center" />;
  if (phase === "setup") {
    return (
      <>
        <Setup onDone={() => setPhase("unlocked")} />
        {prompt}
      </>
    );
  }
  if (phase === "locked") {
    return (
      <>
        <Unlock onDone={() => setPhase("unlocked")} />
        {prompt}
      </>
    );
  }
  return (
    <>
      <Vault onLock={() => setPhase("locked")} />
      {prompt}
    </>
  );
}
