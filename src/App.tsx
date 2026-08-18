import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import Setup from "./components/Setup";
import Unlock from "./components/Unlock";
import Vault from "./components/Vault";
import "./styles.css";

type Phase = "loading" | "setup" | "locked" | "unlocked";

const IDLE_LOCK_MS = 5 * 60 * 1000;

export default function App() {
  const [phase, setPhase] = useState<Phase>("loading");

  const refresh = useCallback(async () => {
    const s = await api.status();
    setPhase(!s.initialized ? "setup" : s.unlocked ? "unlocked" : "locked");
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

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

  if (phase === "loading") return <div className="screen center" />;
  if (phase === "setup") return <Setup onDone={() => setPhase("unlocked")} />;
  if (phase === "locked") return <Unlock onDone={() => setPhase("unlocked")} />;
  return <Vault onLock={() => setPhase("locked")} />;
}
