import type { ImportSummary } from "./types";

const en = {
    setupDesc:
        "Set a master password to encrypt your vault. It is never stored and cannot be recovered.",
    masterPassword: "Master password",
    confirmPassword: "Confirm password",
    createVault: "Create vault",
    creating: "Creating..",
    errPasswordShort: "Password must be at least 8 characters.",
    errPasswordMismatch: "Passwords do not match.",
    locked: "Locked",
    unlockDesc: "Enter your master password to unlock.",
    unlock: "Unlock",
    unlocking: "Unlocking..",
    export: "Export",
    import: "Import",
    changePassword: "Password",
    changePasswordTitle: "Change password",
    lock: "Lock",
    addAccount: "Add account",
    emptyTitle: "Your vault is empty",
    emptyDesc:
        "Add an account, or import from Aegis, andOTP, an otpauth:// list, or a 2fac backup.",
    backupExported: "Backup exported.",
    exportFailed: "Export failed",
    importFailed: "Import failed",
    copied: "Copied",
    clickToCopy: "Click to copy",
    edit: "Edit",
    delete: "Delete",
    editAccount: "Edit account",
    addAccountTitle: "Add account",
    tabManual: "Manual",
    tabUri: "URI",
    tabQr: "QR image",
    issuer: "Issuer",
    accountName: "Account name",
    base32Secret: "Base32 secret",
    newSecretKeep: "New secret (leave empty to keep current)",
    algorithm: "Algorithm",
    period: "Period (s)",
    digits: "Digits",
    uriNote:
        "Also accepts Google Authenticator transfer links (otpauth-migration://).",
    qrNote: "Choose a screenshot or photo of a QR code, including the transfer QR shown by Google Authenticator's “Export accounts”. Decoded locally; never leaves this device.",
    errNameRequired: "Account name is required.",
    errSecretRequired: "Secret is required.",
    errUriRequired: "Paste an otpauth:// or otpauth-migration:// URI.",
    save: "Save",
    saving: "Saving..",
    add: "Add",
    adding: "Adding..",
    cancel: "Cancel",
    deleteTitle: "Delete account?",
    encryptedBackup: "Encrypted backup",
    importPasswordNote:
        "This file is protected. Enter the password it was encrypted with to import it.",
    backupPassword: "Backup password",
    importing: "Importing..",
    currentPassword: "Current password",
    newPassword: "New password",
    changePasswordNote:
        "The vault is re-encrypted with a new key. At least 8 characters.",
    change: "Change",
    changing: "Changing..",
};

const ko: typeof en = {
    setupDesc:
        "암호화할 마스터 비밀번호를 설정하세요. 이 비밀번호는 복구할 수 없습니다",
    masterPassword: "마스터 비밀번호",
    confirmPassword: "비밀번호 확인",
    createVault: "Vault 만들기",
    creating: "만드는 중..",
    errPasswordShort: "8자 이상이여야 합니다",
    errPasswordMismatch: "비밀번호가 서로 다릅니다",
    locked: "Locked",
    unlockDesc: "마스터 비밀번호를 입력하세요",
    unlock: "잠금 해제",
    unlocking: "해제 중..",
    export: "내보내기",
    import: "가져오기",
    changePassword: "비밀번호",
    changePasswordTitle: "비밀번호 변경",
    lock: "잠금",
    addAccount: "계정 추가",
    emptyTitle: "Vault가 비어있습니다",
    emptyDesc:
        "계정을 추가하거나 Aegis, andOTP, otpauth:// 목록, 2fac 백업에서 가져오세요",
    backupExported: "백업을 내보냈습니다",
    exportFailed: "내보내기 실패",
    importFailed: "가져오기 실패",
    copied: "복사 완료!",
    clickToCopy: "클릭해서 복사",
    edit: "수정",
    delete: "삭제",
    editAccount: "계정 수정",
    addAccountTitle: "계정 추가",
    tabManual: "직접 입력",
    tabUri: "URI",
    tabQr: "QR 이미지",
    issuer: "발급자",
    accountName: "계정 이름",
    base32Secret: "Base32 비밀키",
    newSecretKeep: "새 비밀키 (비우면 유지)",
    algorithm: "알고리즘",
    period: "주기(초)",
    digits: "자리 수",
    uriNote:
        "Google Authenticator 전송 링크(otpauth-migration://)도 지원합니다",
    qrNote: "QR 코드 캡처나 사진을 선택하세요.",
    errNameRequired: "계정 이름을 입력하세요",
    errSecretRequired: "비밀키를 입력하세요",
    errUriRequired: "otpauth:// 또는 otpauth-migration:// 주소를 붙여넣으세요",
    save: "저장",
    saving: "저장 중..",
    add: "추가",
    adding: "추가 중..",
    cancel: "취소",
    deleteTitle: "계정을 삭제할까요?",
    encryptedBackup: "암호화된 백업",
    importPasswordNote:
        "비밀번호로 보호된 파일입니다. 백업 비밀번호를 입력하면 가져올 수 있습니다",
    backupPassword: "백업 비밀번호",
    importing: "가져오는 중..",
    currentPassword: "현재 비밀번호",
    newPassword: "새 비밀번호",
    changePasswordNote:
        "Vault를 새 키로 다시 암호화합니다. 8자 이상이어야 합니다",
    change: "변경",
    changing: "변경 중..",
};

export const lang = (navigator.language || "en").toLowerCase().startsWith("ko")
    ? "ko"
    : "en";

export const t = lang === "ko" ? ko : en;

const errors: Record<string, { en: string; ko: string }> = {
    "Wrong password": { en: "Wrong password.", ko: "비밀번호가 틀렸습니다" },
    "Vault is locked": { en: "Vault is locked.", ko: "Vault가 잠겨 있어요" },
    "Vault already initialized": {
        en: "Vault already initialized.",
        ko: "Vault가 이미 있어요",
    },
    "Vault not initialized": {
        en: "Vault not initialized.",
        ko: "Vault가 아직 없습니다",
    },
    "Password is too short (minimum 8 characters)": {
        en: "Password must be at least 8 characters.",
        ko: "비밀번호는 8자 이상이어야 합니다",
    },
    "Vault file is corrupted": {
        en: "Vault file is corrupted.",
        ko: "Vault 파일이 손상됐습니다",
    },
    "Invalid base32 secret": {
        en: "Invalid base32 secret.",
        ko: "잘못된 base32 비밀키입니다",
    },
    "Invalid otpauth URI": {
        en: "Invalid otpauth URI.",
        ko: "잘못된 otpauth URI입니다",
    },
    "Account not found": {
        en: "Account not found.",
        ko: "계정을 찾을 수 없습니다",
    },
    "Invalid account data": {
        en: "Invalid account data.",
        ko: "계정 정보가 올바르지 않습니다",
    },
    "Storage error": { en: "Storage error.", ko: "저장 오류가 발생했습니다" },
    "Unrecognized file format": {
        en: "Unrecognized file format.",
        ko: "알 수 없는 파일 형식입니다",
    },
    "No valid accounts found": {
        en: "No valid accounts found.",
        ko: "가져올 계정이 없습니다",
    },
    "Could not read file": {
        en: "Could not read file.",
        ko: "파일을 읽을 수 없습니다",
    },
    "Could not parse this code": {
        en: "Could not parse this code.",
        ko: "이 코드는 읽을 수 없습니다",
    },
};

export function localizeError(e: unknown): string {
    const s = String(e);
    const hit = errors[s];
    return hit ? hit[lang] : s;
}

export function deleteMessage(name: string): string {
    return lang === "ko"
        ? `${name} 계정을 이 기기에서 삭제합니다. 이 작업은 되돌릴 수 없습니다.`
        : `${name} will be removed from this device. This cannot be undone.`;
}

export function failMessage(prefix: string, e: unknown): string {
    return `${prefix}: ${localizeError(e)}`;
}

const formats: Record<string, { en: string; ko: string }> = {
    "2fac backup": { en: "2fac backup", ko: "2fac 백업" },
    "Aegis export": { en: "Aegis export", ko: "Aegis 내보내기" },
    "andOTP export": { en: "andOTP export", ko: "andOTP 내보내기" },
    "otpauth URI list": { en: "otpauth URI list", ko: "otpauth URI 목록" },
    "Google Authenticator export": {
        en: "Google Authenticator export",
        ko: "Google Authenticator 내보내기",
    },
    "otpauth URI": { en: "otpauth URI", ko: "otpauth URI" },
};

export function summaryText(s: ImportSummary): string {
    const format = formats[s.format]?.[lang] ?? s.format;
    const batch =
        s.batch_size !== null && s.batch_size > 1 && s.batch_index !== null
            ? lang === "ko"
                ? ` · QR ${s.batch_index + 1}/${s.batch_size}`
                : ` · QR ${s.batch_index + 1} of ${s.batch_size}`
            : "";
    if (lang === "ko") {
        const parts = [`${s.imported}개 가져옴`];
        if (s.skipped > 0) parts.push(`${s.skipped}개 건너뜀`);
        return `${format} · ${parts.join(", ")}${s.replaced ? " (전체 교체)" : ""}${batch}`;
    }
    const parts = [`${s.imported} imported`];
    if (s.skipped > 0) parts.push(`${s.skipped} skipped`);
    return `${format}: ${parts.join(", ")}${s.replaced ? " (vault replaced)" : ""}${batch}`;
}
