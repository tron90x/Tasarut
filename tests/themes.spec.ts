import { test, expect } from "@playwright/test";

const ids = ["default", "desert", "kabylie", "ocean", "space", "arctic"];

test("six local landscapes preserve the workspace, have distinct glass and readable surfaces", async ({ page }, testInfo) => {
  const remoteImages: string[] = [];
  page.on("request", (request) => {
    if (request.resourceType() === "image" && !request.url().startsWith("http://127.0.0.1:1437/")) remoteImages.push(request.url());
  });
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "default");
  await page.locator("#password").fill("theme preview password");
  await page.locator("#confirmation").fill("theme preview password");
  await page.locator("#comment").fill("public test comment");
  await page.locator("#compress").check();
  const treatments: string[] = [];
  for (const id of ids) {
    await page.locator("#theme-select").focus();
    await page.locator("#theme-select").selectOption(id);
    await expect(page.locator("html")).toHaveAttribute("data-theme", id);
    await expect(page.locator("#theme-select")).toBeFocused();
    await expect(page.locator("#password")).toHaveValue("theme preview password");
    await expect(page.locator("#confirmation")).toHaveValue("theme preview password");
    await expect(page.locator("#comment")).toHaveValue("public test comment");
    await expect(page.locator("#compress")).toBeChecked();
    const observations = await page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const card = getComputedStyle(document.querySelector(".credentials")!);
      const input = getComputedStyle(document.querySelector("#password")!);
      const hint = getComputedStyle(document.querySelector(".credentials > .hint")!);
      const action = getComputedStyle(document.querySelector("#start")!);
      const rgba = (color: string) => color.match(/[\d.]+/g)!.map(Number);
      const luminance = (color: number[]) => {
        const channels = color.slice(0, 3).map((value) => { const c = value / 255; return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; });
        return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
      };
      // A white scene behind a translucent surface is a conservative contrast bound.
      const contrast = (foreground: string, background: string) => {
        const fg = luminance(rgba(foreground));
        const bg = rgba(background); const alpha = bg[3] ?? 1;
        const light = luminance(bg.slice(0, 3).map((value) => value * alpha + 255 * (1 - alpha)));
        return (Math.max(fg, light) + 0.05) / (Math.min(fg, light) + 0.05);
      };
      return {
        wallpaper: getComputedStyle(document.body, "::before").backgroundImage,
        treatment: `${card.backgroundColor}|${card.backdropFilter}|${card.borderRadius}`,
        textContrast: contrast(card.color, card.backgroundColor),
        hintContrast: contrast(hint.color, card.backgroundColor),
        inputContrast: contrast(input.color, input.backgroundColor),
        buttonContrast: contrast(action.color, action.backgroundColor),
        base: root.getPropertyValue("--base").trim(),
      };
    });
    expect(observations.wallpaper).toContain(`/themes/${id}.svg`);
    for (const value of [observations.textContrast, observations.hintContrast, observations.inputContrast, observations.buttonContrast]) expect(value).toBeGreaterThanOrEqual(4.5);
    await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", observations.base);
    treatments.push(observations.treatment);
    const wallpaper = await page.request.get(`/themes/${id}.svg`);
    expect(wallpaper.ok()).toBe(true);
    expect(await wallpaper.text()).toContain("<svg");
    await page.screenshot({ path: testInfo.outputPath(`${id}-workspace.png`) });
    await page.locator("#open-generator").click();
    await expect(page.getByRole("dialog")).toBeVisible();
    const modal = await page.locator(".modal").evaluate((element) => getComputedStyle(element).backgroundColor);
    expect(modal).not.toContain("rgba");
    await page.keyboard.press("Escape");
  }
  expect(new Set(treatments).size).toBe(6);
  expect(remoteImages).toEqual([]);
  expect(await page.evaluate(() => localStorage.getItem("tasarut-theme-v1"))).toBe("arctic");
  await page.reload();
  await expect(page.locator("#theme-select")).toHaveValue("arctic");
});

test("the gallery supports keyboard selection, translations and compact window layouts", async ({ page }, testInfo) => {
  await page.goto("/");
  await page.locator('[data-page="themes"]').click();
  await expect(page.locator(".theme-card")).toHaveCount(6);
  await page.locator('.theme-card[data-theme="kabylie"]').focus();
  await page.keyboard.press("Enter");
  await expect(page.locator('.theme-card[data-theme="kabylie"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator('.theme-card[data-theme="kabylie"]')).toBeFocused();
  await expect(page.locator("#theme-select")).toHaveValue("kabylie");
  await expect(page.locator('.theme-card[aria-pressed="true"]')).toHaveCount(1);
  for (const [language, heading, name] of [
    ["fr", "Un paysage à votre image.", "Montagnes de Kabylie"],
    ["en", "A place of your own.", "Kabylie mountains"],
    ["kab", "Tawennaḍt i k·m-iwulmen.", "Idurar n Leqbayel"],
  ]) {
    await page.locator("#language").selectOption(language);
    await expect(page.locator("h1")).toHaveText(heading);
    await expect(page.locator("#theme-name-kabylie")).toHaveText(name);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "kabylie");
  }
  await page.locator("#language").selectOption("fr");
  await page.screenshot({ path: testInfo.outputPath("landscape-gallery.png"), fullPage: true });
  for (const width of [860, 480]) {
    await page.setViewportSize({ width, height: 750 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await expect(page.locator("#theme-select")).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`gallery-${width}.png`), fullPage: true });
  }
  await page.keyboard.press("Control+1");
  await expect(page.locator("#password")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(480);
  await page.emulateMedia({ reducedMotion: "reduce" });
  expect(await page.locator("#start").evaluate((element) => getComputedStyle(element).transitionDuration)).toBe("0s");
  const session = await page.context().newCDPSession(page);
  await session.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-transparency", value: "reduce" }, { name: "prefers-reduced-motion", value: "reduce" }] });
  const surface = await page.locator(".credentials").evaluate((element) => {
    const style = getComputedStyle(element);
    return { background: style.backgroundColor, filter: style.backdropFilter };
  });
  expect(surface.background).not.toContain("rgba");
  expect(surface.filter).toBe("none");
});

test("invalid preferences fall back to default and unavailable storage still permits theme selection", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("tasarut-theme-v1", "../../untrusted-theme");
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key: string, value: string) {
      if (key === "tasarut-theme-v1") throw new Error("storage unavailable");
      original.call(this, key, value);
    };
  });
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "default");
  await page.locator('[data-page="themes"]').click();
  await page.locator('.theme-card[data-theme="space"]').click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "space");
  await expect(page.locator(".theme-preference-note")).toContainText("pour cette session");
  await page.locator("#theme-select").selectOption("default");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "default");
});

test("a theme is an appearance preference and does not enter native encryption requests", async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    let callback = 0;
    w.isTauri = true;
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: () => ++callback,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "revocable_status") return { available: false, reason: "revocable_no_tpm", device: null };
        if (command === "plugin:dialog|open") return (args.options as { directory: boolean }).directory ? "/output" : ["/input/test.txt"];
        if (command === "collect_files") return [{ path: "/input/test.txt", relativePath: "test.txt", size: 100, volume: false }];
        if (command === "run_batch") {
          w.themeBatch = args.request;
          return new Promise((resolve) => { w.finishThemeBatch = () => resolve([]); });
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await page.locator("#theme-select").selectOption("ocean");
  await page.locator("#add-files").click();
  await page.locator("#password").fill("native test password");
  await page.locator("#confirmation").fill("native test password");
  await page.locator("#output-folder").click();
  await page.locator("#start").click();
  await expect(page.locator("#theme-select")).toBeDisabled();
  const request = await page.evaluate(() => (window as unknown as { themeBatch: Record<string, unknown> }).themeBatch);
  expect(request).not.toHaveProperty("theme");
  expect(request).not.toHaveProperty("wallpaper");
  await page.locator('[data-page="themes"]').click();
  await expect(page.locator(".theme-card:disabled")).toHaveCount(6);
  await page.evaluate(() => (window as unknown as { finishThemeBatch: () => void }).finishThemeBatch());
  await expect(page.locator("#theme-select")).toBeEnabled();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "ocean");
});
