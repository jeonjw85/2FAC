# 2FAC

[한국어](README.ko.md)

[![CI](https://github.com/jeonjw85/2FAC/actions/workflows/ci.yml/badge.svg)](https://github.com/jeonjw85/2FAC/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jeonjw85/2FAC)](https://github.com/jeonjw85/2FAC/releases/latest)

Local-first TOTP authenticator for the desktop. Secrets never leave this machine.

The vault is encrypted with Argon2id and AES-256-GCM. Codes are computed in Rust. The UI never sees raw secrets. There is no cloud, no account, and no telemetry. The only network use is a signed update check against GitHub Releases.

UI language follows the OS (English / Korean).

## Install

Download a build from [Releases](https://github.com/jeonjw85/2FAC/releases).

| macOS                            | Windows     | Linux                 |
| -------------------------------- | ----------- | --------------------- |
| `.dmg` (Apple Silicon and Intel) | NSIS `.exe` | `.AppImage` or `.deb` |

macOS builds are ad-hoc signed (not Developer ID, not notarized). Gatekeeper still blocks first launch: System Settings → Privacy & Security → Open Anyway. Windows and Linux builds are unsigned; SmartScreen may warn on first run.

In-app updates are minisign-verified against GitHub Releases. That is not Apple or Microsoft code signing.

Installing a newer build over the same `kr.jjw.2fac` app keeps the vault. Do not run a second copy from Downloads.

## Updates

On launch, 2FAC checks GitHub Releases. If a newer signed build exists, it asks before replacing the current app in place and restarting. The vault stays on disk.

A published release (not a draft) is required for that check to see the new version.

## Features

- TOTP (RFC 6238): SHA-1 / SHA-256 / SHA-512, custom digits and period
- Add by secret, `otpauth://` URI, or QR image (file / clipboard)
- Import: 2FAC encrypted backup, Aegis JSON, andOTP JSON, otpauth URI lists, Google Authenticator transfer QR (`otpauth-migration://`)
- Encrypted backup export (same vault format)
- Clipboard auto-clears 30 seconds after copying a code
- Auto-lock on idle and when the window closes

## Build

Needs Rust stable, pnpm, and the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
pnpm install
pnpm lint
pnpm build
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
pnpm tauri build
```

## License

[GPL-3.0-only](LICENSE)
