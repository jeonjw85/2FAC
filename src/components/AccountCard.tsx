import { copyCode } from "../clipboard";
import { t } from "../i18n";
import type { AccountMeta, CodeInfo } from "../types";

const RADIUS = 12.5;
const CIRC = 2 * Math.PI * RADIUS;

function formatCode(code: string): string {
  const size = code.length <= 6 ? 3 : 4;
  return code.match(new RegExp(`.{1,${size}}`, "g"))?.join(" ") ?? code;
}

export default function AccountCard({
  account,
  code,
  onEdit,
  onDelete,
  onCopied,
}: {
  account: AccountMeta;
  code?: CodeInfo;
  onEdit: () => void;
  onDelete: () => void;
  onCopied: () => void;
}) {
  const copy = async () => {
    if (!code) return;
    try {
      await copyCode(code.code);
      onCopied();
    } catch {
      return;
    }
  };

  const frac = code ? code.remaining / code.period : 0;
  const low = !!code && code.remaining <= 5;

  return (
    <div
      className="card"
      onClick={copy}
      title={code ? t.clickToCopy : undefined}
    >
      <div className="card-info">
        <span className="issuer">{account.issuer || account.name}</span>
        {account.issuer && <span className="name">{account.name}</span>}
      </div>

      <div className="card-totp">
        <span className={`code${code ? "" : " placeholder"}`}>
          {code ? (
            <span key={code.code} className="code-inner">
              {formatCode(code.code)}
            </span>
          ) : (
            "··· ···"
          )}
        </span>
        <div className={`ring${low ? " low" : ""}`}>
          <svg width="32" height="32" viewBox="0 0 32 32">
            <circle className="ring-track" cx="16" cy="16" r={RADIUS} />
            {code && (
              <circle
                className="ring-fg"
                cx="16"
                cy="16"
                r={RADIUS}
                strokeDasharray={CIRC}
                strokeDashoffset={CIRC * (1 - frac)}
              />
            )}
          </svg>
          <span className="ring-num">{code ? code.remaining : ""}</span>
        </div>
      </div>

      <div className="card-actions">
        <button className="icon" onClick={(e) => { e.stopPropagation(); onEdit(); }}>{t.edit}</button>
        <button className="icon danger" onClick={(e) => { e.stopPropagation(); onDelete(); }}>{t.delete}</button>
      </div>
    </div>
  );
}
