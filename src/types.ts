export interface Status {
  initialized: boolean;
  unlocked: boolean;
}

export interface AccountMeta {
  id: string;
  issuer: string;
  name: string;
  algorithm: string;
  digits: number;
  period: number;
  created_at: number;
}

export interface CodeInfo {
  code: string;
  remaining: number;
  period: number;
}

export interface ImportSummary {
  format: string;
  imported: number;
  skipped: number;
  replaced: boolean;
  batch_index: number | null;
  batch_size: number | null;
}

export type Algorithm = "SHA1" | "SHA256" | "SHA512";
