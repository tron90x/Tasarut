import { test, expect, type Page } from "@playwright/test";

async function nativeKeyboard(page: Page, options = { deferredDialogs: false, deferredGenerator: false, mac: false }) {
  await page.addInitScript(({ deferredDialogs, deferredGenerator, mac }) => {
    if (mac) Object.defineProperty(navigator, "platform", { get: () => "MacIntel" });
    const w = window as unknown as Record<string, unknown>;
    const callbacks = new Map<number, (event: unknown) => void>();
    const generators: ((value: string) => void)[] = [];
    let next = 0;
    w.isTauri = true;
    w.dialogs = [];
    w.requests = [];
    w.cancelIds = [];
    w.generatorCalls = 0;
    w.resolveGenerator = (index: number, value: string) => generators[index](value);
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: (callback: (event: unknown) => void) => { callbacks.set(++next, callback); return next; },
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:event|listen") {
          if (args.event === "tasarut-progress") w.emitProgress = (payload: unknown) => callbacks.get(args.handler as number)?.({ event: "tasarut-progress", id: 1, payload });
          return 1;
        }
        if (command === "plugin:dialog|open") {
          const settings = args.options as { directory: boolean; multiple: boolean; title: string };
          (w.dialogs as unknown[]).push(settings);
          const result = settings.directory ? settings.multiple ? ["/input/folder"] : "/output" : settings.title === "Ajouter des fichiers-clés" ? ["/key"] : ["/input/one"];
          if (!deferredDialogs) return result;
          return new Promise((resolve) => { w.resolveDialog = (value: unknown = result) => resolve(value); });
        }
        if (command === "collect_files") {
          w.lastCollect = args;
          return ["one", "two"].map((name) => ({ path: `/input/${name}`, relativePath: name, size: 1000000, volume: false }));
        }
        if (command === "generate_password") {
          w.generatorCalls = Number(w.generatorCalls) + 1;
          if (!deferredGenerator) return "n".repeat(args.length as number);
          return new Promise<string>((resolve) => generators.push(resolve));
        }
        if (command === "run_batch") {
          (w.requests as unknown[]).push(args.request);
          w.jobId = (args.request as { id: string }).id;
          return new Promise((resolve) => {
            w.finishBatch = (cancelled: boolean) => resolve(["one", "two"].map((name, i) => ({
              source: `/input/${name}`, output: cancelled ? null : `/output/${name}.tasarut`,
              error: cancelled ? i === 0 ? "operation_cancelled" : "not_processed" : null,
              repair: null, recovery: null,
            })));
          });
        }
        if (command === "cancel_batch") { (w.cancelIds as string[]).push(args.id as string); return true; }
        return 0;
      },
    };
  }, options);
}

test("shortcut help is translated, traps focus and restores the password selection", async ({ page }) => {
  await page.goto("/");
  const password = "phrase de passe conservée";
  await page.locator("#password").fill(password);
  for (const [language, title, mode] of [["fr", "Raccourcis clavier", "Chiffrer"], ["en", "Keyboard shortcuts", "Encrypt"], ["kab", "Inegzumen n unasiw", "Wgelhen"]]) {
    await page.locator("#language").selectOption(language);
    await page.locator("#password").focus();
    await page.locator("#password").evaluate((input: HTMLInputElement) => input.setSelectionRange(3, 8, "backward"));
    await page.keyboard.press("F1");
    const dialog = page.getByRole("dialog", { name: title });
    await expect(dialog).toBeVisible();
    await expect(dialog.locator("tbody tr")).toHaveCount(15);
    await expect(dialog.locator("table")).toContainText(mode);
    await expect(page.locator("main")).toHaveAttribute("inert", "");
    await expect(page.locator("#close-shortcuts")).toBeFocused();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Shift+Tab");
    await expect(page.locator("#close-shortcuts")).toBeFocused();
    await page.keyboard.press("Control+o");
    await page.keyboard.press("Control+Enter");
    await expect(page.getByRole("alert")).toHaveCount(0);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.locator("#password")).toBeFocused();
    await expect(page.locator("#password")).toHaveValue(password);
    expect(await page.locator("#password").evaluate((input: HTMLInputElement) => [input.selectionStart, input.selectionEnd, input.selectionDirection])).toEqual([3, 8, "backward"]);
  }
});

test("native shortcuts share the file pickers and lock out duplicate dialogs", async ({ page }) => {
  await nativeKeyboard(page, { deferredDialogs: true, deferredGenerator: false, mac: false });
  await page.goto("/");
  await page.locator("#password").fill("preserved");
  await page.locator("#password").dispatchEvent("keydown", { key: "o", code: "KeyO", ctrlKey: true, repeat: true });
  expect(await page.evaluate(() => (window as unknown as { dialogs: unknown[] }).dialogs.length)).toBe(0);
  await page.keyboard.press("Control+o");
  for (const key of ["Control+o", "Control+Shift+o", "Control+Shift+k", "Control+Shift+s", "Control+Enter", "F1"]) await page.keyboard.press(key);
  expect(await page.evaluate(() => (window as unknown as { dialogs: unknown[] }).dialogs.length)).toBe(1);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.evaluate(() => (window as unknown as { resolveDialog: (value?: unknown) => void }).resolveDialog(null));
  await expect(page.locator("#add-files")).toBeEnabled();
  await expect(page.locator("#password")).toHaveValue("preserved");
  await page.keyboard.press("Control+o");
  await page.evaluate(() => (window as unknown as { resolveDialog: () => void }).resolveDialog());
  await expect(page.locator(".file-row")).toHaveCount(2);
  await page.locator('[data-inspect="0"]').click();
  await page.keyboard.press("F1");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator('[data-inspect="0"]')).toBeFocused();
  await page.keyboard.press("Control+Shift+o");
  await page.evaluate(() => (window as unknown as { resolveDialog: () => void }).resolveDialog());
  await expect(page.locator("#recursive")).toBeChecked();
  expect(await page.evaluate(() => (window as unknown as { lastCollect: { recursive: boolean } }).lastCollect.recursive)).toBe(true);
  await page.keyboard.press("Control+Shift+k");
  await page.evaluate(() => (window as unknown as { resolveDialog: () => void }).resolveDialog());
  await expect(page.locator(".keyfile-chip")).toContainText("key");
  await page.keyboard.press("Control+Shift+s");
  await page.evaluate(() => (window as unknown as { resolveDialog: () => void }).resolveDialog());
  await expect(page.locator("#output-folder")).toContainText("/output");
  const dialogs = await page.evaluate(() => (window as unknown as { dialogs: { directory: boolean; multiple: boolean; title: string }[] }).dialogs);
  expect(dialogs.slice(1)).toEqual([
    { directory: false, multiple: true, title: "Ajouter des fichiers" },
    { directory: true, multiple: true, title: "Ajouter un dossier" },
    { directory: false, multiple: true, title: "Ajouter des fichiers-clés" },
    { directory: true, multiple: false, title: "Choisir un dossier" },
  ]);
  await page.locator(".intro h1").click();
  await page.keyboard.press("Control+k");
  await expect(page.locator("#password")).toBeFocused();
  await expect(page.locator("#password")).toHaveValue("preserved");
  await page.keyboard.press("Control+Shift+g");
  await expect(page.locator("#generated-password")).toHaveValue("n".repeat(32));
  await page.locator("#use-password").click();
  await expect(page.locator("#confirmation")).toHaveValue("n".repeat(32));
  await expect(page.locator("#add-files")).toHaveAttribute("aria-keyshortcuts", "Control+O");
  await expect(page.locator("#output-folder")).toHaveAttribute("title", /Ctrl \+ Maj \+ S/);
});

test("typing, IME and repeat events are respected, and keyboard start keeps the normal validation", async ({ page }) => {
  await nativeKeyboard(page);
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await page.locator("#password").fill("original");
  await page.keyboard.press("Control+a");
  await page.keyboard.insertText("texte conservé");
  await page.locator("#confirmation").fill("different");
  await page.locator("#password").focus();
  for (const event of [
    { key: "d", code: "KeyD", ctrlKey: true },
    { key: "é", code: "Digit2", ctrlKey: true },
    { key: "G", ctrlKey: true, shiftKey: true, isComposing: true },
    { key: "G", ctrlKey: true, shiftKey: true, altKey: true },
    { key: "G", ctrlKey: true, shiftKey: true, repeat: true },
  ]) await page.locator("#password").dispatchEvent("keydown", event);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator('[data-mode="encrypt"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#password")).toHaveValue("texte conservé");
  await page.keyboard.press("Control+Enter");
  await expect(page.getByRole("alert")).toContainText("Les mots de passe ne correspondent pas");
  await expect(page.locator("#password")).toBeFocused();
  expect(await page.evaluate(() => (window as unknown as { requests: unknown[] }).requests.length)).toBe(0);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.locator("#password")).toBeFocused();
  await page.locator(".intro h1").click();
  await page.locator("body").dispatchEvent("keydown", { key: "é", code: "Digit2", ctrlKey: true });
  await expect(page.locator('[data-page="roadmap"]')).toHaveClass(/active/);
  await page.keyboard.press("Control+Enter");
  await expect(page.getByRole("alert")).toHaveCount(0);
  await page.keyboard.press("Control+3");
  await expect(page.locator('[data-page="about"]')).toHaveClass(/active/);
  await page.keyboard.press("Control+1");
  await page.keyboard.press("Control+d");
  await expect(page.locator('[data-mode="decrypt"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#password")).toHaveValue("texte conservé");
  await page.keyboard.press("Control+e");
  await page.locator("#confirmation").fill("texte conservé");
  await page.keyboard.press("Control+Enter");
  await expect(page.locator(".progress-panel")).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { requests: unknown[] }).requests.length)).toBe(1);
  await page.evaluate(() => (window as unknown as { finishBatch: (cancelled: boolean) => void }).finishBatch(false));
});

test("help remains usable during a batch and Escape never cancels it", async ({ page }) => {
  await nativeKeyboard(page);
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await page.locator("#password").fill("password");
  await page.locator("#confirmation").fill("password");
  await page.keyboard.press("Control+Enter");
  await expect(page.locator(".progress-panel")).toBeVisible();
  for (const key of ["Control+o", "Control+Shift+g", "Control+d", "Control+Enter"]) await page.keyboard.press(key);
  expect(await page.evaluate(() => (window as unknown as { requests: unknown[] }).requests.length)).toBe(1);
  await page.keyboard.press("F1");
  await expect(page.getByRole("dialog", { name: "Raccourcis clavier" })).toBeVisible();
  await page.keyboard.press("Control+Period");
  expect(await page.evaluate(() => (window as unknown as { cancelIds: unknown[] }).cancelIds.length)).toBe(0);
  await page.evaluate(() => {
    const w = window as unknown as { emitProgress: (value: unknown) => void; jobId: string };
    w.emitProgress({ id: w.jobId, completed: 0, total: 2, current: "/input/one", result: null, byteProgress: { phase: "encrypting", processedBytes: 250000, totalBytes: 1000000 } });
  });
  await expect(page.locator("#close-shortcuts")).toBeFocused();
  await page.evaluate(() => (window as unknown as { finishBatch: (cancelled: boolean) => void }).finishBatch(false));
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.locator("#close-shortcuts")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.locator(".progress-panel")).toHaveCount(0);
  await expect(page.locator(".result-row")).toHaveCount(2);
  await expect(page.locator("#open-shortcuts")).toBeFocused();
});

test("cancellation shortcut works from another page and supports the shifted AZERTY period", async ({ page }) => {
  await nativeKeyboard(page);
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#output-folder").click();
  await page.locator("#password").fill("password");
  await page.locator("#confirmation").fill("password");
  await page.keyboard.press("Control+Enter");
  await expect(page.locator(".progress-panel")).toBeVisible();
  await page.keyboard.press("Escape");
  expect(await page.evaluate(() => (window as unknown as { cancelIds: unknown[] }).cancelIds.length)).toBe(0);
  await page.keyboard.press("Control+3");
  await expect(page.locator('[data-page="about"]')).toHaveClass(/active/);
  await page.locator("body").dispatchEvent("keydown", { key: ".", code: "Semicolon", ctrlKey: true, shiftKey: true });
  await expect(page.locator("#cancel-job")).toHaveText("Annulation en cours…");
  await expect(page.locator('[data-page="workspace"]')).toHaveClass(/active/);
  await page.keyboard.press("Control+Period");
  const data = await page.evaluate(() => { const w = window as unknown as { cancelIds: string[]; jobId: string }; return { ids: w.cancelIds, current: w.jobId }; });
  expect(data.ids).toEqual([data.current]);
  await page.evaluate(() => (window as unknown as { finishBatch: (cancelled: boolean) => void }).finishBatch(true));
  await expect(page.locator(".cancelled-banner")).toBeVisible();
  await expect(page.locator(".result-row > span")).toHaveText(["Annulé", "Non traité"]);
});

test("Escape discards late generator responses and Cmd shortcuts are described on macOS", async ({ page }) => {
  await nativeKeyboard(page, { deferredDialogs: false, deferredGenerator: true, mac: true });
  await page.goto("/");
  await expect(page.locator("#add-files")).toHaveAttribute("aria-keyshortcuts", "Meta+O");
  await page.locator("#password").fill("unchanged");
  await page.locator("#password").evaluate((input: HTMLInputElement) => input.setSelectionRange(2, 5));
  await page.keyboard.press("Meta+Shift+g");
  await expect(page.locator("#generator-length")).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(page.locator("#password")).toBeFocused();
  await expect(page.locator("#password")).toHaveValue("unchanged");
  await page.keyboard.press("Meta+Shift+g");
  await page.evaluate(() => (window as unknown as { resolveGenerator: (index: number, value: string) => void }).resolveGenerator(0, "a".repeat(32)));
  await expect(page.locator("#generated-password")).toHaveValue("");
  await expect(page.locator("#generate-password")).toBeDisabled();
  await page.evaluate(() => (window as unknown as { resolveGenerator: (index: number, value: string) => void }).resolveGenerator(1, "b".repeat(32)));
  await expect(page.locator("#generated-password")).toHaveValue("b".repeat(32));
  await page.locator("#use-password").click();
  await expect(page.locator("#password")).toHaveValue("b".repeat(32));
  await page.keyboard.press("F1");
  await expect(page.locator(".shortcuts-table kbd").filter({ hasText: /^Cmd$/ }).first()).toBeVisible();
  await page.keyboard.press("Escape");
  await page.keyboard.press("Meta+o");
  await expect(page.locator(".file-row")).toHaveCount(2);
});
