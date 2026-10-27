import { test, expect, type Page } from "@playwright/test";

async function mockCancellation(page: Page, options = { failFirstCancel: false, preflight: false }) {
  await page.addInitScript(({ failFirstCancel, preflight }) => {
    const w = window as unknown as Record<string, unknown>;
    const callbacks = new Map<number, (event: unknown) => void>();
    let next = 0;
    let rejectBatch: (error: unknown) => void = () => {};
    w.isTauri = true;
    w.cancelCalls = [];
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: (callback: (event: unknown) => void) => { callbacks.set(++next, callback); return next; },
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:event|listen") {
          if (args.event === "tasarut-progress") w.emitProgress = (payload: unknown) => callbacks.get(args.handler as number)?.({ event: "tasarut-progress", id: 1, payload });
          return 1;
        }
        if (command === "plugin:dialog|open") return (args.options as { directory: boolean }).directory ? "/output" : ["/input/one", "/input/two", "/input/three"];
        if (command === "collect_files") return ["one", "two", "three"].map((name) => ({ path: `/input/${name}`, relativePath: name, size: 1000000, volume: false }));
        if (command === "run_batch") {
          w.jobId = (args.request as { id: string }).id;
          return new Promise((resolve, reject) => {
            rejectBatch = reject;
            w.finishBatch = (successful: boolean) => resolve(["one", "two", "three"].map((name, i) => ({
              source: `/input/${name}`, output: successful || i === 0 ? `/output/${name}.tasarut` : null,
              error: successful || i === 0 ? null : i === 1 ? "operation_cancelled" : "not_processed",
              repair: null, recovery: null,
            })));
          });
        }
        if (command === "cancel_batch") {
          (w.cancelCalls as string[]).push(args.id as string);
          if (failFirstCancel) { failFirstCancel = false; throw "cancel transport unavailable"; }
          return new Promise((resolve) => {
            w.acceptCancel = () => {
              if (preflight) rejectBatch("operation_cancelled");
              resolve(true);
            };
          });
        }
        return 0;
      },
    };
  }, options);
}

async function startBatch(page: Page) {
  await page.locator("#password").fill("password");
  await page.locator("#confirmation").fill("password");
  await page.locator("#start").click();
  await expect(page.locator(".progress-panel")).toBeVisible();
}

test("cancellation can be retried, waits for cleanup and keeps completed and skipped results distinct", async ({ page }) => {
  await mockCancellation(page, { failFirstCancel: true, preflight: false });
  await page.goto("/");
  await page.locator("#language").selectOption("kab");
  await page.locator("#language").selectOption("fr");
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await startBatch(page);
  await page.evaluate(() => { (window as unknown as Record<string, unknown>).cancelNode = document.getElementById("cancel-job"); });
  const emit = async () => page.evaluate(() => {
    const w = window as unknown as { jobId: string; emitProgress: (payload: unknown) => void };
    w.emitProgress({ id: w.jobId, completed: 1, total: 3, current: "/input/two", result: null,
      byteProgress: { phase: "encrypting", processedBytes: 500000, totalBytes: 1000000 },
    });
  });
  await emit();
  expect(await page.evaluate(() => (window as unknown as { cancelNode: unknown }).cancelNode === document.getElementById("cancel-job"))).toBe(true);
  await page.locator("#cancel-job").click();
  await expect(page.getByRole("alert")).toContainText("cancel transport unavailable");
  await expect(page.locator("#cancel-job")).toBeEnabled();
  await page.locator("#cancel-job").click();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.locator("#cancel-job")).toBeDisabled();
  await expect(page.locator("#cancel-job")).toHaveText("Annulation en cours…");
  await expect(page.locator("#cancel-notice")).toContainText("suppression des temporaires");
  await emit();
  await page.locator("#cancel-job").dispatchEvent("click");
  await page.evaluate(() => (window as unknown as { acceptCancel: () => void }).acceptCancel());
  await expect(page.locator("#start")).toBeDisabled();
  await expect(page.locator("#password")).toHaveValue("password");
  const calls = await page.evaluate(() => {
    const w = window as unknown as { cancelCalls: string[]; jobId: string };
    return { ids: w.cancelCalls, current: w.jobId };
  });
  expect(calls.ids).toEqual([calls.current, calls.current]);
  await page.evaluate(() => (window as unknown as { finishBatch: (successful: boolean) => void }).finishBatch(false));
  await expect(page.locator(".progress-panel")).toHaveCount(0);
  await expect(page.locator(".cancelled-banner")).toContainText("résultats déjà terminés sont conservés");
  await expect(page.locator(".result-row")).toHaveCount(3);
  await expect(page.locator(".result-row > span")).toHaveText(["Terminé", "Annulé", "Non traité"]);
  await expect(page.locator(".result-error")).toHaveCount(0);
  await expect(page.locator(".result-row").first()).toContainText("/output/one.tasarut");
  await expect(page.locator("#password")).toHaveValue("");
  await expect(page.locator("#confirmation")).toHaveValue("");
  await expect(page.locator("#start")).toBeEnabled();
});

test("cancelling during preparation is a neutral outcome rather than an error", async ({ page }) => {
  await mockCancellation(page, { failFirstCancel: false, preflight: true });
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await startBatch(page);
  await page.locator("#cancel-job").click();
  await page.evaluate(() => (window as unknown as { acceptCancel: () => void }).acceptCancel());
  await expect(page.locator(".cancelled-banner")).toContainText("Opération annulée");
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.locator(".result-row, .progress-panel")).toHaveCount(0);
  await expect(page.locator("#password")).toHaveValue("");
  await expect(page.locator("#start")).toBeEnabled();
});

test("a late cancellation acknowledgment cannot change a new batch", async ({ page }) => {
  await mockCancellation(page);
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await startBatch(page);
  await page.locator("#cancel-job").click();
  await page.evaluate(() => (window as unknown as { finishBatch: (successful: boolean) => void }).finishBatch(true));
  await expect(page.locator(".cancelled-banner")).toHaveCount(0);
  await expect(page.locator("#start")).toBeEnabled();
  await startBatch(page);
  await page.evaluate(() => (window as unknown as { acceptCancel: () => void }).acceptCancel());
  await expect(page.locator("#cancel-job")).toBeEnabled();
  await expect(page.locator("#cancel-job")).toHaveText("Annuler l’opération");
  await expect(page.locator("#cancel-notice")).not.toBeVisible();
  await page.evaluate(() => (window as unknown as { finishBatch: (successful: boolean) => void }).finishBatch(true));
  await expect(page.locator(".result-row > span")).toHaveText(["Terminé", "Terminé", "Terminé"]);
});
