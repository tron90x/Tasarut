import { test, expect, type Page } from "@playwright/test";

async function native(page: Page, volume = false) {
  await page.addInitScript(({ volume }) => {
    const w = window as unknown as Record<string, unknown>;
    let callback = 0;
    w.isTauri = true; w.cipherRequests = [];
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: () => ++callback,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "revocable_status") return { available: false, reason: "revocable_no_tpm", device: null };
        if (command === "plugin:dialog|open") return (args.options as { directory: boolean }).directory ? "/output" : [volume ? "/input/volume.tasarut" : "/input/source.bin"];
        if (command === "collect_files") return [{ path: volume ? "/input/volume.tasarut" : "/input/source.bin", relativePath: volume ? "volume.tasarut" : "source.bin", volume, size: 1000 }];
        if (command === "inspect_volume") return { algorithm: "threefish1024", comment: "public", compressed: false, paranoid: false, formatVersion: 5, originalSize: 842, reedSolomon: false, revocable: false };
        if (command === "run_batch") {
          (w.cipherRequests as unknown[]).push(args.request);
          return [{ source: volume ? "/input/volume.tasarut" : "/input/source.bin", output: "/output/result", error: null, repair: null, recovery: null }];
        }
        return 0;
      },
    };
  }, { volume });
}

test("Threefish is a distinct, translated encryption choice with the strengthened KDF", async ({ page }) => {
  await native(page);
  await page.goto("/");
  await expect(page.locator("#cipher-algorithm")).toHaveValue("xchacha20");
  await page.locator("#paranoid").check();
  await page.locator("#password").fill("kept cipher password");
  await page.locator("#confirmation").fill("kept cipher password");
  await page.locator("#cipher-algorithm").selectOption("threefish1024");
  await expect(page.locator("#paranoid")).not.toBeChecked();
  await expect(page.locator("#paranoid")).toBeDisabled();
  await expect(page.locator(".crypto-card h3")).toContainText("Threefish-1024-CTR");
  await expect(page.locator(".crypto-card")).toContainText("HMAC-SHA3-512");
  await expect(page.locator(".crypto-card")).toContainText("256 Mio");
  await expect(page.locator(".profile-costs")).toContainText("256 Mio");
  for (const [language, label] of [["en", "Encryption algorithm"], ["kab", "Alguritm n uwgelhen"], ["fr", "Algorithme de chiffrement"]]) {
    await page.locator("#language").selectOption(language);
    await expect(page.getByLabel(label, { exact: true })).toHaveValue("threefish1024");
    await expect(page.locator("#password")).toHaveValue("kept cipher password");
  }
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await page.locator("#compress").check();
  await page.locator("#reed-solomon").check();
  await page.locator("#start").click();
  const request = await page.evaluate(() => (window as unknown as { cipherRequests: Record<string, unknown>[] }).cipherRequests[0]);
  expect(request).toMatchObject({ algorithm: "threefish1024", paranoid: false, compress: true, reedSolomon: true });
  await expect(page.locator("#password")).toHaveValue("");
  await page.locator('[data-page="roadmap"]').click();
  await page.locator("#enable-paranoid").click();
  await expect(page.locator("#cipher-algorithm")).toHaveValue("xchacha20");
  await expect(page.locator("#paranoid")).toBeChecked();
});

test("decryption detects Threefish from the volume, regardless of encryption preferences", async ({ page }) => {
  await native(page, true);
  await page.goto("/");
  await page.locator('[data-mode="decrypt"]').click();
  await page.locator("#add-files").click();
  await expect(page.locator("#cipher-algorithm")).toHaveCount(0);
  await expect(page.locator(".cipher-auto")).toContainText("détecté automatiquement");
  await expect(page.locator(".volume-profile")).toContainText("Threefish-1024 · v5");
  await expect(page.locator(".crypto-card h3")).toContainText("Threefish-1024-CTR");
  await page.locator("#password").fill("volume secret");
  await page.locator("#output-folder").click();
  await page.locator("#start").click();
  const request = await page.evaluate(() => (window as unknown as { cipherRequests: Record<string, unknown>[] }).cipherRequests[0]);
  expect(request).toMatchObject({ mode: "decrypt", algorithm: "xchacha20", paranoid: false });
});

test("profiles persist the cipher without secrets and retain the old default", async ({ page }) => {
  await page.goto("/");
  await page.locator("#password").fill("never stored cipher secret");
  await page.locator("#profile-actions summary").click();
  await page.locator("#profile-create").click();
  await page.locator("#profile-name").fill("Threefish backup");
  await page.locator("#profile-algorithm").selectOption("threefish1024");
  await expect(page.locator("#profile-option-paranoid")).toBeDisabled();
  await page.locator("#save-profile-dialog").click();
  await expect(page.locator("#cipher-algorithm")).toHaveValue("threefish1024");
  const text = await page.evaluate(() => localStorage.getItem("tasarut-profiles-v1"));
  expect(text).not.toContain("never stored cipher secret");
  const saved = JSON.parse(text!);
  expect(saved.profiles[0].settings).toMatchObject({ algorithm: "threefish1024", paranoid: false });
  await page.reload();
  await expect(page.locator("#cipher-algorithm")).toHaveValue("xchacha20");
  await page.locator("#profile-select").selectOption(saved.profiles[0].id);
  await expect(page.locator("#cipher-algorithm")).toHaveValue("threefish1024");
  await page.locator("#profile-select").selectOption("preset-strong");
  await expect(page.locator("#cipher-algorithm")).toHaveValue("xchacha20");
  await expect(page.locator("#paranoid")).toBeChecked();
});
