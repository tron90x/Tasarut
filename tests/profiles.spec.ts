import { test, expect, type Page } from "@playwright/test";

const storeKey = "tasarut-profiles-v1";
const settings = {
  algorithm: "xchacha20",
  compress: false, paranoid: false, reedSolomon: false, chunks: false,
  chunkSizeMiB: 100, deniability: false, recursive: false,
  generatorLength: 32, generatorSymbols: true,
  revocable: false,
};
const profileDocument = (profiles: { name: string; settings: object }[]) => JSON.stringify({ format: "tasarut-profiles", version: 1, profiles });

async function nativeProfiles(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.isTauri = true;
    w.requests = [];
    w.importDocument = "";
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: () => 1,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:dialog|open") {
          const options = args.options as { directory: boolean; multiple: boolean; title: string };
          if (options.title === "Importer un JSON") return "/profiles.json";
          if (options.directory) return options.multiple ? ["/input/folder"] : "/output";
          return options.title === "Ajouter des fichiers-clés" ? ["/key"] : ["/input/one"];
        }
        if (command === "plugin:dialog|save") return "/exports/profiles";
        if (command === "collect_files") {
          if ((args.paths as string[]).includes("/input/folder") && !args.recursive) throw "invalid_input";
          return [{ path: "/input/one", relativePath: "one", size: 1000000, volume: false }];
        }
        if (command === "generate_password") return "g".repeat(args.length as number);
        if (command === "read_profile_document") return w.importDocument;
        if (command === "write_profile_document") { w.exported = args; return null; }
        if (command === "run_batch") {
          (w.requests as unknown[]).push(args.request);
          return new Promise((resolve) => { w.finishBatch = () => resolve([{ source: "/input/one", output: "/output/one.tasarut", error: null }]); });
        }
        return 0;
      },
    };
  });
}
async function manage(page: Page) {
  if (!(await page.locator("#profile-actions").evaluate((details: HTMLDetailsElement) => details.open))) await page.locator("#profile-actions summary").click();
}
async function stored(page: Page) { return page.evaluate((key) => localStorage.getItem(key), storeKey); }

test("templates apply compatible options without starting or replacing secrets, and dirty settings can be restored", async ({ page }) => {
  await nativeProfiles(page);
  await page.goto("/");
  await page.locator("#password").fill("private password");
  await page.locator("#confirmation").fill("private password");
  await page.locator("#comment").fill("public note");
  await page.locator("#add-keyfiles").click();
  await page.locator("#profile-select").selectOption("preset-backup");
  await expect(page.locator("#compress")).toBeChecked();
  await expect(page.locator("#reed-solomon")).toBeChecked();
  await expect(page.locator("#recursive")).toBeChecked();
  await expect(page.locator("#profile-live")).toContainText("6,25 %");
  await page.locator("#profile-select").selectOption("preset-transfer");
  await expect(page.locator("#chunk-size")).toHaveValue("100");
  await page.locator("#chunk-size").fill("250");
  await expect(page.locator(".profile-state")).toHaveText("Profil modifié");
  await expect(page.locator(".profile-summary")).toContainText("250 MiB");
  await page.locator("#profile-revert").click();
  await expect(page.locator("#chunk-size")).toHaveValue("100");
  await page.locator("#profile-select").selectOption("preset-strong");
  await expect(page.locator("#paranoid")).toBeChecked();
  await expect(page.locator("#profile-live")).toContainText("256 Mio");
  await page.locator("#open-generator").click();
  await expect(page.locator("#generator-length")).toHaveValue("64");
  await page.keyboard.press("Escape");
  await page.locator("#profile-select").selectOption("preset-opaque");
  await expect(page.locator("#deniability")).toBeChecked();
  await expect(page.locator("#chunks")).toBeDisabled();
  await expect(page.locator("#comment")).toHaveCount(0);
  await page.locator('[data-mode="decrypt"]').click();
  await expect(page.locator("#force-decrypt")).toBeDisabled();
  await page.locator("#profile-select").selectOption("preset-simple");
  await page.locator("#force-decrypt").check();
  await page.locator("#profile-select").selectOption("preset-strong");
  await expect(page.locator("#force-decrypt")).not.toBeChecked();
  await expect(page.locator('[data-mode="decrypt"]')).toHaveAttribute("aria-pressed", "true");
  await page.locator('[data-mode="encrypt"]').click();
  await expect(page.locator("#password")).toHaveValue("private password");
  await expect(page.locator("#confirmation")).toHaveValue("private password");
  await expect(page.locator("#comment")).toHaveValue("public note");
  await expect(page.locator(".keyfile-chip")).toHaveCount(1);
  expect(await page.evaluate(() => (window as unknown as { requests: unknown[] }).requests.length)).toBe(0);
  expect(await stored(page)).toBeNull();
  for (const [language, title, backup] of [["en", "Usage profiles", "Backup"], ["kab", "Imaɣnuyen n useqdec", "Aḥraz"], ["fr", "Profils d’utilisation", "Sauvegarde"]]) {
    await page.locator("#language").selectOption(language);
    await expect(page.locator(".profiles-card h2")).toHaveText(title);
    await expect(page.locator('#profile-select option[value="preset-backup"]')).toHaveText(backup);
  }
});

test("custom profiles persist only their settings and names are rendered as text", async ({ page }) => {
  await page.goto("/");
  await page.locator("#password").fill("never-store-this-password");
  await page.locator("#confirmation").fill("never-store-this-password");
  await page.locator("#comment").fill("never-store-this-comment");
  await manage(page);
  await expect(page.locator("#profile-save")).toBeDisabled();
  await expect(page.locator("#profile-delete")).toBeDisabled();
  await page.locator("#profile-create").click();
  const name = "<img src=x onerror=alert(1)> & documents";
  await page.locator("#profile-name").fill(name);
  await page.locator("#profile-option-paranoid").check();
  await page.locator("#profile-option-chunks").check();
  await page.locator("#profile-chunk-size").fill("250");
  await page.locator("#profile-generator-length").fill("64");
  await page.locator("#profile-remember-output").check();
  await page.locator("#profile-folder").fill("/backup/documents");
  await page.locator("#save-profile-dialog").click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("#paranoid")).toBeChecked();
  await expect(page.locator("#chunk-size")).toHaveValue("250");
  await expect(page.locator(".profile-state")).toHaveText("Réglages du profil");
  await expect(page.locator(".profiles-card img")).toHaveCount(0);
  const document = JSON.parse((await stored(page))!);
  expect(document.profiles).toHaveLength(1);
  expect(document.profiles[0]).toMatchObject({ name, settings: { paranoid: true, chunks: true, chunkSizeMiB: 250, generatorLength: 64, outputDirectory: "/backup/documents" } });
  expect(JSON.stringify(document)).not.toContain("never-store");
  expect(Object.keys(document.profiles[0].settings).sort()).toEqual([...Object.keys(settings), "outputDirectory"].sort());
  const id = document.profiles[0].id;
  await page.reload();
  await expect(page.locator("#profile-select")).toHaveValue("preset-simple");
  await expect(page.locator("#password")).toHaveValue("");
  await page.locator("#profile-select").selectOption(id);
  await expect(page.locator("#paranoid")).toBeChecked();
  await expect(page.locator("#chunk-size")).toHaveValue("250");
  await expect(page.locator("#output-folder")).toContainText("/backup/documents");
  await manage(page);
  await page.locator("#profile-save").click();
  await page.locator("#profile-name").fill("Renamed documents");
  await page.locator("#save-profile-dialog").click();
  await expect(page.locator(`#profile-select option[value="${id}"]`)).toHaveText("Renamed documents");
  await page.locator("#profile-duplicate").click();
  await page.locator("#profile-name").fill("Second variant");
  await page.locator("#save-profile-dialog").click();
  expect(JSON.parse((await stored(page))!).profiles).toHaveLength(2);
  await page.locator("#profile-delete").click();
  await page.locator("#confirm-profile-delete").click();
  expect(JSON.parse((await stored(page))!).profiles).toHaveLength(1);
  await expect(page.locator("#paranoid")).toBeChecked();
  await expect(page.locator("#chunk-size")).toHaveValue("250");
  await expect(page.locator("#profile-select")).toHaveValue("");
});

test("native JSON exchanges are versioned, atomic in the library and never apply imported profiles implicitly", async ({ page }) => {
  await nativeProfiles(page);
  await page.goto("/");
  await page.locator("#password").fill("secret-not-exported");
  await page.locator("#confirmation").fill("secret-not-exported");
  await page.locator("#add-keyfiles").click();
  await page.locator("#add-files").click();
  await manage(page);
  await page.locator("#profile-export").click();
  const exported = await page.evaluate(() => (window as unknown as { exported: { path: string; document: string } }).exported);
  expect(exported.path).toBe("/exports/profiles.json");
  const parsed = JSON.parse(exported.document);
  expect(parsed).toMatchObject({ format: "tasarut-profiles", version: 1, profiles: [{ name: "Simple", settings }] });
  expect(exported.document).not.toContain("secret-not-exported");
  expect(exported.document).not.toContain("/key");
  const imported = profileDocument([{ name: "Simple", settings: { ...settings, paranoid: true } }]);
  await page.evaluate((text) => { (window as unknown as Record<string, unknown>).importDocument = text; }, imported);
  await page.locator("#profile-import").click();
  await expect(page.locator(".profile-notice")).toContainText("Profils ajoutés: 1");
  const first = JSON.parse((await stored(page))!).profiles[0];
  expect(first.name).toBe("Simple (2)");
  await expect(page.locator("#paranoid")).not.toBeChecked();
  await expect(page.locator("#password")).toHaveValue("secret-not-exported");
  await page.locator("#profile-import").click();
  const profiles = JSON.parse((await stored(page))!).profiles;
  expect(profiles.map((profile: { name: string }) => profile.name)).toEqual(["Simple (2)", "Simple (3)"]);
  expect(profiles[0].id).not.toBe(profiles[1].id);
  await page.locator("#profile-select").selectOption(first.id);
  await expect(page.locator("#paranoid")).toBeChecked();
  await page.locator("#profile-export-all").click();
  const all = JSON.parse(await page.evaluate(() => (window as unknown as { exported: { document: string } }).exported.document));
  expect(all.profiles).toHaveLength(2);
  expect(all.profiles.every((profile: object) => Object.keys(profile).sort().join() === "name,settings")).toBe(true);
  const before = await stored(page);
  for (const bad of [
    { ...settings, paranoid: "true" }, { ...settings, forceDecrypt: true },
    { ...settings, deniability: true, chunks: true }, { ...settings, chunkSizeMiB: 0 },
    { ...settings, generatorLength: 15 }, { ...settings, outputDirectory: "relative/path" },
  ]) {
    await page.evaluate((text) => { (window as unknown as Record<string, unknown>).importDocument = text; }, profileDocument([{ name: "bad", settings: bad }]));
    await page.locator("#profile-import").click();
    await expect(page.getByRole("alert")).toBeVisible();
    expect(await stored(page)).toBe(before);
    await expect(page.locator("#paranoid")).toBeChecked();
  }
  expect(await page.evaluate(() => (window as unknown as { requests: unknown[] }).requests.length)).toBe(0);
});

test("browser JSON files can be exchanged without native crypto or secret persistence", async ({ page }) => {
  await page.goto("/");
  await manage(page);
  const downloadPromise = page.waitForEvent("download");
  await page.locator("#profile-export").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("tasarut-profil.json");
  await page.locator("#profile-import-file").setInputFiles({ name: "profiles.json", mimeType: "application/json", buffer: Buffer.from(profileDocument([{ name: "Portable", settings: { ...settings, deniability: true } }])) });
  await expect(page.locator(".profile-notice")).toContainText("Profils ajoutés: 1");
  expect(JSON.parse((await stored(page))!).profiles[0].name).toBe("Portable");
  const before = await stored(page);
  await page.locator("#profile-import-file").setInputFiles({ name: "huge.json", mimeType: "application/json", buffer: Buffer.alloc(1024 * 1024 + 1, 32) });
  await expect(page.getByRole("alert")).toContainText("dépasse 1 Mio");
  expect(await stored(page)).toBe(before);
});

test("invalid local preferences are retained until reset and failed saves keep the editor and previous data", async ({ page }) => {
  await page.addInitScript((key) => localStorage.setItem(key, "unreadable original"), storeKey);
  await page.goto("/");
  await expect(page.locator(".profile-storage-error")).toContainText("illisibles ou incompatibles");
  expect(await stored(page)).toBe("unreadable original");
  await manage(page);
  await expect(page.locator("#profile-create")).toBeDisabled();
  await page.locator("#profile-select").selectOption("preset-opaque");
  await expect(page.locator("#deniability")).toBeChecked();
  await page.locator("#profile-reset").click();
  const before = await stored(page);
  expect(JSON.parse(before!).profiles).toEqual([]);
  await page.evaluate((key) => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (name, value) { if (name === key) throw new Error("quota"); return original.call(this, name, value); };
  }, storeKey);
  await page.locator("#profile-create").click();
  await page.locator("#profile-name").fill("Unsaved variant");
  await expect(page.locator("#profile-option-chunks")).toBeDisabled();
  await page.locator("#save-profile-dialog").click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("stockage local");
  await expect(page.locator("#profile-name")).toHaveValue("Unsaved variant");
  expect(await stored(page)).toBe(before);
  await page.keyboard.press("Escape");
});

test("profile application validates recursive selections before changing settings and is locked during processing", async ({ page }) => {
  await nativeProfiles(page);
  await page.goto("/");
  await page.locator("#add-folder").click();
  await page.locator("#profile-select").selectOption("preset-backup");
  await page.locator("#profile-select").selectOption("preset-simple");
  await expect(page.getByRole("alert")).toContainText("mode récursif");
  await expect(page.locator("#profile-select")).toHaveValue("preset-backup");
  await expect(page.locator("#recursive")).toBeChecked();
  await expect(page.locator("#compress")).toBeChecked();
  await page.locator("#password").fill("password");
  await page.locator("#confirmation").fill("password");
  await page.locator("#output-folder").click();
  await manage(page);
  await page.locator("#start").click();
  await expect(page.locator("#profile-select")).toBeDisabled();
  await expect(page.locator("#profile-create")).toBeDisabled();
  await expect(page.locator("#profile-import")).toBeDisabled();
  await page.locator("#profile-select").dispatchEvent("change");
  await expect(page.locator("#compress")).toBeChecked();
  await page.evaluate(() => (window as unknown as { finishBatch: () => void }).finishBatch());
  await expect(page.locator("#profile-select")).toBeEnabled();
});
