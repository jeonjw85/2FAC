import { writeText, readText } from "@tauri-apps/plugin-clipboard-manager";

const CLEAR_AFTER_MS = 30000;

export async function copyCode(code: string): Promise<void> {
  await writeText(code);
  window.setTimeout(async () => {
    const current = await readText().catch(() => null);
    if (current === code) {
      await writeText("");
    }
  }, CLEAR_AFTER_MS);
}
