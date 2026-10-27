import { test, expect } from "@playwright/test";

test("switching languages preserves credentials and changes accessible labels", async ({
  page,
}) => {
  await page.goto("/");
  await page.locator("#password").fill("une phrase de passe unique");
  await page.locator("#confirmation").fill("une phrase de passe unique");
  await page.locator("#language").selectOption("kab");
  await expect(page.locator("html")).toHaveAttribute("lang", "kab");
  await expect(
    page.getByRole("button", { name: "Wgelhen ifuyla", exact: true }),
  ).toBeVisible();
  await expect(page.locator("#password")).toHaveValue(
    "une phrase de passe unique",
  );
  await page.locator("#language").selectOption("en");
  await expect(
    page.getByRole("button", { name: "Encrypt files", exact: true }),
  ).toBeVisible();
  await expect(page.locator("#confirmation")).toHaveValue(
    "une phrase de passe unique",
  );
  await page.locator("#language").selectOption("fr");
  await page.screenshot({
    path: "test-results/tasarut-fr.png",
    fullPage: true,
  });
});

test("generator fills both fields with the selected length and alphabet", async ({
  page,
}) => {
  await page.goto("/");
  await page.locator("#open-generator").click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.locator("#generator-length").fill("128");
  await page.locator("#generator-symbols").uncheck();
  await page.locator("#generate-password").click();
  const password = await page.locator("#generated-password").inputValue();
  expect(password).toMatch(/^[A-Za-z0-9]{128}$/);
  await page.locator("#use-password").click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("#password")).toHaveValue(password);
  await expect(page.locator("#confirmation")).toHaveValue(password);
});

test("preview cannot process local files and advanced modes show availability", async ({
  page,
}) => {
  await page.goto("/");
  await page.locator("#start").click();
  await expect(page.getByRole("alert")).toContainText(
    "Lancez l’application Tauri",
  );
  await page.locator('[data-page="roadmap"]').click();
  await expect(page.locator(".planned")).toHaveCount(0);
  await expect(page.locator(".available")).toHaveCount(5);
  await expect(page.locator(".roadmap-grid input")).toHaveCount(0);
  await page.locator("#enable-reed").click();
  await expect(page.locator("#reed-solomon")).toBeChecked();
  await expect(page.locator("#paranoid")).not.toBeChecked();
});

test("public comments and paths remain text, and removed recursive files stay excluded from a batch", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.isTauri = true;
    const files = [
      {
        path: "/input/one.tasarut",
        relativePath: "documents/one.tasarut",
        size: 200,
        volume: true,
      },
      {
        path: "/input/two.tasarut",
        relativePath: "documents/<img src=x onerror=alert(1)>.tasarut",
        size: 200,
        volume: true,
      },
    ];
    let callback = 0;
    w.__TAURI_INTERNALS__ = {
      metadata: {
        currentWindow: { label: "main" },
        currentWebview: { windowLabel: "main", label: "main" },
      },
      transformCallback: () => ++callback,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:dialog|open")
          return (args.options as { directory: boolean }).directory
            ? "/output"
            : ["/input"];
        if (command === "collect_files") return files;
        if (command === "inspect_volume")
          return {
            comment: "<img src=x onerror=alert(1)>",
            compressed: false,
            originalSize: 1,
            paranoid: true,
            formatVersion: 3,
            reedSolomon: true,
          };
        if (command === "run_batch") {
          w.lastBatch = args.request;
          return [
            {
              source: "/input/two.tasarut",
              output: "/output/two",
              error: null,
              repair: {
                reedSolomon: true,
                correctedBlocks: 2,
                correctedBytes: 7,
              },
            },
          ];
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await page.locator("#add-files").click();
  await expect(page.locator(".file-row")).toHaveCount(2);
  await expect(page.locator(".volume-profile")).toContainText(
    "Mode paranoïaque · v3 · Reed–Solomon",
  );
  await expect(page.locator("#paranoid")).toHaveCount(0);
  await expect(page.locator("#reed-solomon")).toHaveCount(0);
  await expect(page.locator(".auto-mode")).toContainText("automatiquement");
  await expect(page.locator(".comment-content")).toHaveText(
    "<img src=x onerror=alert(1)>",
  );
  await expect(page.locator(".inspection img, .file-row img")).toHaveCount(0);
  await page.locator('[data-remove="0"]').click();
  await page.locator("#password").fill("password");
  await page.locator("#output-folder").click();
  await page.locator("#start").click();
  await expect(page.locator(".result-row")).toHaveCount(1);
  await expect(page.locator(".repair-summary")).toContainText(
    "2 blocs corrigés · 7 octets corrigés",
  );
  const batch = await page.evaluate(
    () =>
      (
        window as unknown as {
          lastBatch: {
            selectedPaths: string[];
            paranoid: boolean;
            reedSolomon: boolean;
            forceDecrypt: boolean;
          };
        }
      ).lastBatch,
  );
  expect(batch.selectedPaths).toEqual(["/input/two.tasarut"]);
  expect(batch.paranoid).toBe(false); // Decryption always uses the volume's suite.
  expect(batch.reedSolomon).toBe(false); // Recovery is also automatic on decryption.
  expect(batch.forceDecrypt).toBe(false);
  await expect(page.locator("#password")).toHaveValue("");
});

test("encryption options and chunk size survive languages and reach native encryption", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.isTauri = true;
    w.__TAURI_INTERNALS__ = {
      metadata: {
        currentWindow: { label: "main" },
        currentWebview: { windowLabel: "main", label: "main" },
      },
      transformCallback: () => 1,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:dialog|open")
          return (args.options as { directory: boolean }).directory
            ? "/output"
            : ["/input/report"];
        if (command === "collect_files")
          return [
            {
              path: "/input/report",
              relativePath: "report",
              size: 42,
              volume: false,
            },
          ];
        if (command === "run_batch") {
          w.lastBatch = args.request;
          return [
            {
              source: "/input/report",
              output: "/output/report.tasarut",
              error: null,
            },
          ];
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await page.locator('[data-page="roadmap"]').click();
  await page.locator("#enable-paranoid").click();
  await expect(page.locator("#paranoid")).toBeChecked();
  await page.locator("#reed-solomon").check();
  await page.locator('[data-page="roadmap"]').click();
  await page.locator("#enable-chunks").click();
  await expect(page.locator("#chunks")).toBeChecked();
  await expect(page.locator("#chunk-size")).toHaveValue("100");
  await page.locator("#chunk-size").fill("2");
  await page.locator("#compress").check();
  await expect(page.locator(".crypto-card")).toContainText("HMAC-SHA3-512");
  await expect(page.locator(".paranoid-cost")).toContainText("256 Mio");
  for (const language of ["en", "kab", "fr"]) {
    await page.locator("#language").selectOption(language);
    await expect(page.locator("#paranoid")).toBeChecked();
    await expect(page.locator("#reed-solomon")).toBeChecked();
    await expect(page.locator("#compress")).toBeChecked();
    await expect(page.locator("#chunks")).toBeChecked();
    await expect(page.locator("#chunk-size")).toHaveValue("2");
  }
  await page.locator('[data-mode="decrypt"]').click();
  await expect(page.locator("#paranoid")).toHaveCount(0);
  await expect(page.locator("#chunks")).toHaveCount(0);
  await expect(page.locator("#force-decrypt")).not.toBeChecked();
  await page.locator('[data-mode="encrypt"]').click();
  await expect(page.locator("#paranoid")).toBeChecked();
  await page.locator("#add-files").click();
  await page.locator("#password").fill("paranoid password");
  await page.locator("#confirmation").fill("paranoid password");
  await page.locator("#output-folder").click();
  await page.locator("#chunk-size").fill("0");
  await page.locator("#start").click();
  await expect(page.getByRole("alert")).toContainText("Choisissez une taille entière");
  expect(await page.evaluate(() => (window as unknown as { lastBatch?: unknown }).lastBatch)).toBeUndefined();
  await page.locator("#chunk-size").fill("2");
  await page.locator("#start").click();
  await expect(page.locator(".result-row")).toHaveCount(1);
  const request = await page.evaluate(
    () =>
      (
        window as unknown as {
          lastBatch: {
            paranoid: boolean;
            reedSolomon: boolean;
            compress: boolean;
            mode: string;
            forceDecrypt: boolean;
            chunkSizeMiB: number;
          };
        }
      ).lastBatch,
  );
  expect(request.paranoid).toBe(true);
  expect(request.reedSolomon).toBe(true);
  expect(request.compress).toBe(true);
  expect(request.mode).toBe("encrypt");
  expect(request.forceDecrypt).toBe(false);
  expect(request.chunkSizeMiB).toBe(2);
  await expect(page.locator("#password")).toHaveValue("");
});

test("a selected part is presented and decrypted as one complete volume", async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.isTauri = true;
    w.__TAURI_INTERNALS__ = {
      metadata: {
        currentWindow: { label: "main" },
        currentWebview: { windowLabel: "main", label: "main" },
      },
      transformCallback: () => 1,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:dialog|open")
          return (args.options as { directory: boolean }).directory ? "/output" : ["/input/report.tasarut.parts/000002.part"];
        if (command === "collect_files") return [{ path: "/input/report.tasarut.parts", relativePath: "report.tasarut.parts", size: 3000000, volume: true }];
        if (command === "inspect_volume") return { comment: "public", compressed: false, originalSize: 2999000, paranoid: false, formatVersion: 1, reedSolomon: false, chunkCount: 3 };
        if (command === "run_batch") {
          w.lastBatch = args.request;
          return [{ source: "/input/report.tasarut.parts", output: "/output/report", error: null }];
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await page.locator("#add-files").click();
  await expect(page.locator(".file-row")).toHaveCount(1);
  await expect(page.locator(".volume-profile")).toContainText("3 parties");
  await expect(page.locator('[data-mode="decrypt"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#chunks")).toHaveCount(0);
  await page.locator("#password").fill("password");
  await page.locator("#output-folder").click();
  await page.locator("#start").click();
  await expect(page.locator(".result-row")).toContainText("/output/report");
  const request = await page.evaluate(() => (window as unknown as { lastBatch: { selectedPaths: string[]; chunkSizeMiB: number | null } }).lastBatch);
  expect(request.selectedPaths).toEqual(["/input/report.tasarut.parts"]);
  expect(request.chunkSizeMiB).toBeNull();
});

test("forced recovery is explicit, labelled untrusted, bounded, and reset on encryption", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.isTauri = true;
    w.calls = 0;
    w.__TAURI_INTERNALS__ = {
      metadata: {
        currentWindow: { label: "main" },
        currentWebview: { windowLabel: "main", label: "main" },
      },
      transformCallback: () => 1,
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:dialog|open")
          return (args.options as { directory: boolean }).directory
            ? "/output"
            : ["/input/damaged.tasarut"];
        if (command === "collect_files")
          return [
            {
              path: "/input/damaged.tasarut",
              relativePath: "damaged.tasarut",
              size: 1200,
              volume: true,
            },
          ];
        if (command === "inspect_volume") {
          w.lastInspectionForced = args.force;
          if (!args.force) throw "reed_solomon_uncorrectable";
          return {
            comment: "public",
            compressed: false,
            originalSize: 100,
            paranoid: false,
            reedSolomon: true,
            formatVersion: 3,
          };
        }
        if (command === "run_batch") {
          w.calls = Number(w.calls) + 1;
          w.lastBatch = args.request;
          if (!(args.request as { forceDecrypt: boolean }).forceDecrypt)
            throw "authentication_failed";
          return [
            {
              source: "/input/damaged.tasarut",
              output: "/output/damaged.recovered",
              error: null,
              repair: {
                reedSolomon: true,
                correctedBlocks: 2,
                correctedBytes: 5,
              },
              recovery: {
                authenticated: false,
                macStatus: "invalid",
                partial: true,
                declaredSize: 100,
                recoveredBytes: 7,
                outputLimit: 2097152,
                limitReached: false,
                decompressionFailed: false,
                trailingData: false,
                damage: {
                  uncorrectableBlocks: 1,
                  missingBytes: 40,
                  truncated: true,
                  descriptorDamaged: false,
                  noncanonicalPadding: false,
                  ranges: [{ offset: 256, length: 128 }],
                  rangesOmitted: false,
                },
              },
            },
          ];
        }
        return 0;
      },
    };
  });
  await page.goto("/");
  await page.locator("#add-files").click();
  await expect(page.locator("#force-decrypt")).not.toBeChecked();
  await page.locator('[data-page="roadmap"]').click();
  await page.locator("#enable-force").click();
  await expect(page.locator("#force-decrypt")).toBeChecked();
  await expect(page.locator(".force-notice")).toContainText(
    "ne garantit pas l’intégrité",
  );
  await expect(page.locator(".crypto-card")).not.toContainText(
    "Intégrité vérifiée",
  );
  for (const language of ["en", "kab", "fr"]) {
    await page.locator("#language").selectOption(language);
    await expect(page.locator("#force-decrypt")).toBeChecked();
  }
  await page.locator("#password").fill("password");
  await page.locator("#output-folder").click();
  await page.locator("#recovery-limit").fill("0");
  await page.locator("#start").click();
  expect(
    await page.evaluate(() => (window as unknown as { calls: number }).calls),
  ).toBe(0);
  await page.locator("#recovery-limit").fill("2");
  await page.locator("#start").click();
  await expect(page.locator(".result-recovery")).toHaveCount(1);
  await expect(page.locator(".recovery-report")).toContainText(
    "RÉCUPÉRATION NON AUTHENTIFIÉE",
  );
  await expect(page.locator(".recovery-report")).toContainText(
    "Récupération partielle",
  );
  await expect(page.locator(".recovery-report")).toContainText("MAC invalide");
  await expect(page.locator(".result-recovery > span")).toHaveText("Récupéré");
  const request = await page.evaluate(
    () =>
      (
        window as unknown as {
          lastBatch: { forceDecrypt: boolean; recoveryLimitMiB: number };
        }
      ).lastBatch,
  );
  expect(request.forceDecrypt).toBe(true);
  expect(request.recoveryLimitMiB).toBe(2);
  await page.locator('[data-page="roadmap"]').click();
  await page.locator("#enable-paranoid").click();
  await expect(page.locator("#force-decrypt")).toHaveCount(0);
  await page.locator('[data-mode="decrypt"]').click();
  await expect(page.locator("#force-decrypt")).not.toBeChecked();
  await page.locator("#password").fill("password");
  await page.locator("#start").click();
  await expect(page.getByRole("alert")).toContainText("Mot de passe incorrect");
  await expect(page.locator(".result-row")).toHaveCount(0);
});
