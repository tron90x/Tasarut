import { test, expect } from "@playwright/test";

test("opaque mode hides public metadata, excludes incompatible options and explicitly decrypts unknown input", async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    let encrypted = false;
    w.isTauri = true;
    w.batches = [];
    w.inspections = 0;
    w.__TAURI_INTERNALS__ = {
      metadata: {
        currentWindow: { label: "main" },
        currentWebview: { windowLabel: "main", label: "main" },
      },
      transformCallback: () => 1,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:dialog|open") return (args.options as { directory: boolean }).directory
          ? "/output" : [encrypted ? "/input/report.bin" : "/input/report"];
        if (command === "collect_files") return [{
          path: encrypted ? "/input/report.bin" : "/input/report",
          relativePath: encrypted ? "report.bin" : "report",
          size: 530000, volume: false,
        }];
        if (command === "inspect_volume") {
          w.inspections = Number(w.inspections) + 1;
          throw "invalid_volume";
        }
        if (command === "run_batch") {
          const request = args.request as { mode: string };
          (w.batches as unknown[]).push(request);
          encrypted = true;
          return [{ source: "/input/report", output: request.mode === "encrypt" ? "/output/report.bin" : "/output/report", error: null }];
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await page.locator("#comment").fill("public metadata from the previous mode");
  await page.locator("#chunks").check();
  await page.locator("#paranoid").check();
  await page.locator("#reed-solomon").check();
  await page.locator("#compress").check();
  await page.locator('[data-page="roadmap"]').click();
  await page.locator("#enable-deniability").click();
  await expect(page.locator("#deniability")).toBeChecked();
  await expect(page.locator("#chunks")).not.toBeChecked();
  await expect(page.locator("#chunks")).toBeDisabled();
  await expect(page.locator("#chunk-size, #comment")).toHaveCount(0);
  await expect(page.locator(".deniability-details")).toContainText("Noms et tailles restent visibles");
  await expect(page.locator(".crypto-card")).toContainText("Enveloppe opaque");
  for (const language of ["en", "kab", "fr"]) {
    await page.locator("#language").selectOption(language);
    await expect(page.locator("#deniability")).toBeChecked();
    await expect(page.locator("#paranoid")).toBeChecked();
  }
  await page.locator("#add-files").click();
  await page.locator("#password").fill("password");
  await page.locator("#confirmation").fill("password");
  await page.locator("#output-folder").click();
  await page.locator("#start").click();
  await expect(page.locator(".result-row")).toContainText("report.bin");
  await page.locator("#clear-files").click();
  await page.locator('[data-mode="decrypt"]').click();
  await expect(page.locator("#deniability")).toBeChecked();
  await expect(page.locator("#force-decrypt")).toBeDisabled();
  await expect(page.locator(".auto-mode")).toContainText("nécessite le mot de passe");
  await page.locator("#add-files").click();
  await expect(page.locator(".file-row")).toContainText("Entrée opaque");
  await expect(page.locator(".inspection")).toHaveCount(0);
  await page.locator("#password").fill("password");
  await page.locator("#start").click();
  await expect(page.locator(".result-row")).toContainText("/output/report");
  const { batches, inspections } = await page.evaluate(() => {
    const w = window as unknown as {
      batches: { deniability: boolean; mode: string; comment: string; chunkSizeMiB: number | null; forceDecrypt: boolean; paranoid: boolean; reedSolomon: boolean }[];
      inspections: number;
    };
    return { batches: w.batches, inspections: w.inspections };
  });
  expect(inspections).toBe(0);
  expect(batches).toHaveLength(2);
  expect(batches[0]).toMatchObject({ deniability: true, mode: "encrypt", comment: "", chunkSizeMiB: null, forceDecrypt: false, paranoid: true, reedSolomon: true });
  expect(batches[1]).toMatchObject({ deniability: true, mode: "decrypt", chunkSizeMiB: null, forceDecrypt: false, paranoid: false, reedSolomon: false });
  await expect(page.locator("#password")).toHaveValue("");
  await page.locator('[data-page="roadmap"]').click();
  await page.locator("#enable-force").click();
  await expect(page.locator("#deniability")).not.toBeChecked();
  await expect(page.locator("#force-decrypt")).toBeChecked();
  await page.locator('[data-mode="encrypt"]').click();
  await expect(page.locator("#comment")).toHaveValue("public metadata from the previous mode");
});
