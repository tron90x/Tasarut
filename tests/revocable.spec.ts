import { test, expect } from "@playwright/test";

test("hardware-bound mode uses explicit credentials and revocation, without storing TPM authorization", async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    let encrypted = false;
    w.isTauri = true; w.requests = []; w.revocations = [];
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: () => 1,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "revocable_status") return { available: true, reason: "", device: "/dev/tpmrm0" };
        if (command === "plugin:dialog|open") return (args.options as { directory: boolean }).directory ? "/output" : [encrypted ? "/input/document.tasarut.rev" : "/input/document"];
        if (command === "collect_files") return [{ path: encrypted ? "/input/document.tasarut.rev" : "/input/document", relativePath: encrypted ? "document.tasarut.rev" : "document", size: 1000, volume: encrypted, revocable: encrypted }];
        if (command === "inspect_volume") return { comment: "", originalSize: 800, paranoid: false, compressed: false, formatVersion: 4, reedSolomon: false, revocable: true, revocableId: "abc123", revocableIndex: "0x015a0001" };
        if (command === "run_batch") {
          (w.requests as unknown[]).push(args.request); encrypted = true;
          return [{ source: "/input/document", output: "/output/document.tasarut.rev", error: null, repair: null, recovery: null }];
        }
        if (command === "prepare_revocation") return { token: "review-key", items: [{ source: "/input/document.tasarut.rev", identifier: "abc123", index: "0x015a0001", error: null }] };
        if (command === "run_revocation") {
          (w.revocations as unknown[]).push(args.request);
          return [{ source: "/input/document.tasarut.rev", identifier: "abc123", index: "0x015a0001", revoked: true, hardwareAbsenceConfirmed: true, error: null }];
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await expect(page.locator("#revocable")).toBeEnabled();
  await page.locator("#comment").fill("public comment from the previous mode");
  await page.locator("#revocable").check();
  await expect(page.locator("#deniability, #chunks").first()).toBeDisabled();
  await expect(page.locator("#chunks")).toBeDisabled();
  await expect(page.locator("#comment")).not.toBeVisible();
  await page.locator("#password").fill("volume password");
  await page.locator("#confirmation").fill("volume password");
  await page.locator("#tpm-owner-auth").fill("owner password");
  await page.locator("#profile-actions summary").click();
  await page.locator("#profile-create").click();
  await page.locator("#profile-name").fill("TPM profile");
  await page.locator("#save-profile-dialog").click();
  const storage = await page.evaluate(() => localStorage.getItem("tasarut-profiles-v1"));
  expect(storage).toContain('"revocable":true');
  expect(storage).not.toContain("owner password");
  expect(storage).not.toContain("volume password");
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await page.locator("#start").click();
  await expect(page.locator(".result-row")).toContainText(".tasarut.rev");
  const request = await page.evaluate(() => (window as unknown as { requests: { revocable: boolean; comment: string; tpmOwnerAuth: string }[] }).requests[0]);
  expect(request).toMatchObject({ revocable: true, comment: "", tpmOwnerAuth: "owner password" });
  await page.locator("#clear-files").click();
  await page.locator("#add-files").click();
  await expect(page.locator('[data-mode="decrypt"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#force-decrypt")).toBeDisabled();
  await page.locator("#password").fill("volume password");
  await page.locator("#tpm-owner-auth").fill("owner password");
  await page.locator("#prepare-revocation").click();
  await expect(page.getByRole("dialog")).toContainText("abc123");
  await expect(page.getByRole("dialog")).toContainText("0x015a0001");
  await page.keyboard.press("Control+Enter");
  expect(await page.evaluate(() => (window as unknown as { revocations: unknown[] }).revocations.length)).toBe(0);
  await page.locator("#confirm-revocation").click();
  await expect(page.locator(".revocation-report")).toContainText("Absence de l’index TPM confirmée");
  await expect(page.locator(".file-row")).toHaveCount(1);
  await expect(page.locator("#password")).toHaveValue("");
  await expect(page.locator("#tpm-owner-auth")).toHaveValue("");
  const revoke = await page.evaluate(() => (window as unknown as { revocations: { token: string; password: string; tpmOwnerAuth: string }[] }).revocations[0]);
  expect(revoke).toMatchObject({ token: "review-key", password: "volume password", tpmOwnerAuth: "owner password" });
});

test("persistent swap or unavailable hardware cannot silently become software revocation", async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.isTauri = true;
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: () => 1,
      invoke: async (command: string) => command === "revocable_status" ? { available: false, reason: "revocable_persistent_swap", device: "/dev/tpmrm0" } : 0,
    };
  });
  await page.goto("/");
  await expect(page.locator("#revocable")).toBeDisabled();
  await expect(page.locator(".tpm-status")).toContainText("swap persistant");
  await page.locator("#revocable").dispatchEvent("change");
  await expect(page.locator("#revocable")).not.toBeChecked();
  await expect(page.locator("#tpm-owner-auth")).toHaveCount(0);
  await page.locator("#profile-actions summary").click();
  await page.locator("#profile-create").click();
  await page.locator("#profile-name").fill("Future hardware profile");
  await page.locator("#profile-option-revocable").check();
  await page.locator("#save-profile-dialog").click();
  await expect(page.getByRole("alert")).toContainText("swap persistant");
  await expect(page.locator("#revocable")).not.toBeChecked();
  await expect(page.locator("#start")).toHaveText(/Chiffrer les fichiers/);
});
