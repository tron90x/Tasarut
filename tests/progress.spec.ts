import { test, expect } from "@playwright/test";

test("byte progress follows streaming stages, handles unknown totals and ignores stale jobs without rebuilding credentials", async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    const callbacks = new Map<number, (event: unknown) => void>();
    let next = 0;
    w.isTauri = true;
    w.__TAURI_INTERNALS__ = {
      metadata: {
        currentWindow: { label: "main" },
        currentWebview: { windowLabel: "main", label: "main" },
      },
      transformCallback: (callback: (event: unknown) => void) => {
        callbacks.set(++next, callback);
        return next;
      },
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:event|listen") {
          if (args.event === "tasarut-progress") {
            w.emitProgress = (payload: unknown) => callbacks.get(args.handler as number)?.({ event: "tasarut-progress", id: 1, payload });
          }
          return 1;
        }
        if (command === "plugin:dialog|open") return (args.options as { directory: boolean }).directory ? "/output" : ["/input/large.tasarut", "/input/small.tasarut"];
        if (command === "collect_files") return [
          { path: "/input/large.tasarut", relativePath: "large.tasarut", size: 1048717, volume: true },
          { path: "/input/small.tasarut", relativePath: "small.tasarut", size: 1141, volume: true },
        ];
        if (command === "inspect_volume") return { comment: "", compressed: false, originalSize: 1048576, paranoid: false, formatVersion: 1, reedSolomon: false };
        if (command === "run_batch") {
          w.jobId = (args.request as { id: string }).id;
          w.passwordNode = document.getElementById("password");
          return new Promise((resolve) => {
            w.finishBatch = () => resolve([
              { source: "/input/large.tasarut", output: "/output/large", error: null, repair: null, recovery: null },
              { source: "/input/small.tasarut", output: "/output/small", error: null, repair: null, recovery: null },
            ]);
          });
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#password").fill("password");
  await page.locator("#output-folder").click();
  await page.locator("#start").click();
  const panel = page.locator(".progress-panel");
  await expect(panel).toBeVisible();
  await expect(panel.locator("progress")).not.toHaveAttribute("value");
  const emit = async (phase: string, processedBytes: number, totalBytes: number | null, completed = 0, stale = false) => {
    await page.evaluate(({ phase, processedBytes, totalBytes, completed, stale }) => {
      const w = window as unknown as { jobId: string; emitProgress: (payload: unknown) => void };
      w.emitProgress({ id: stale ? "old-job" : w.jobId, completed, total: 2,
        current: completed ? "/input/small.tasarut" : "/input/large.tasarut", result: null,
        byteProgress: { phase, processedBytes, totalBytes },
      });
    }, { phase, processedBytes, totalBytes, completed, stale });
  };
  await emit("keyDerivation", 0, null);
  await expect(panel.locator(".progress-phase")).toContainText("Dérivation de la clé");
  await expect(panel.locator(".progress-percent")).toHaveText("");
  await emit("authenticating", 524288, 1048576);
  await expect(panel.locator("progress")).toHaveAttribute("value", "0.5");
  await expect(panel.locator(".progress-percent")).toHaveText("50 %");
  await expect(panel.locator(".progress-bytes")).toHaveText("512 KiB / 1 MiB");
  await expect(panel.locator(".progress-files")).toHaveText("0 / 2 fichiers traités");
  expect(await page.evaluate(() => (window as unknown as { passwordNode: unknown }).passwordNode === document.getElementById("password"))).toBe(true);
  await emit("decrypting", 131072, 1048576);
  await expect(panel.locator(".progress-phase")).toContainText("Déchiffrement");
  await expect(panel.locator("progress")).toHaveAttribute("value", "0.125");
  await emit("decrypting", 1048576, 1048576, 0, true);
  await expect(panel.locator("progress")).toHaveAttribute("value", "0.125");
  await emit("publishing", 0, null);
  await expect(panel.locator("progress")).not.toHaveAttribute("value");
  await emit("authenticating", 250, 1000, 1);
  await expect(panel.locator(".progress-files")).toHaveText("1 / 2 fichiers traités");
  await expect(panel.locator(".progress-percent")).toHaveText("25 %");
  await emit("recovering", 512, null, 1);
  await expect(panel.locator("progress")).not.toHaveAttribute("value");
  await expect(panel.locator(".progress-bytes")).toHaveText("512 B");
  await expect(panel.locator(".progress-percent")).toHaveText("");
  await emit("decrypting", 0, 0, 1);
  await expect(panel.locator("progress")).not.toHaveAttribute("value");
  await expect(panel.locator(".progress-bytes")).toHaveText("0 B / 0 B");
  await page.evaluate(() => (window as unknown as { finishBatch: () => void }).finishBatch());
  await expect(panel).toHaveCount(0);
  await expect(page.locator(".result-row")).toHaveCount(2);
  await expect(page.locator("#password")).toHaveValue("");
});
