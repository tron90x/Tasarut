import { test, expect, type Page } from "@playwright/test";

const setPath = "/input/<img src=x onerror=alert(1)>.tasarut.parts";
interface Filesystem {
  directory: string; device: string; filesystem: string;
  storage?: { kind: "nvme" | "nonRotational" | "rotational" | "mixed" | "unknown"; blockDevice: string | null; backingDevices: { name: string; kind: "nvme" | "nonRotational" | "rotational" | "unknown" }[]; discardMaxBytes: number | null };
}
async function nativeDeletion(page: Page, options: { partial?: boolean; expired?: boolean; filesystems?: Filesystem[] } = {}) {
  const filesystems: Filesystem[] = options.filesystems ?? [{ directory: "/input", device: "123", filesystem: "ext4", storage: {
    kind: "nvme", blockDevice: "dm-0", backingDevices: [{ name: "nvme0n1", kind: "nvme" }], discardMaxBytes: 0,
  } }];
  await page.addInitScript(({ setPath, partial, expired, filesystems }) => {
    const w = window as unknown as Record<string, unknown>;
    const callbacks = new Map<number, (event: unknown) => void>();
    let callback = 0;
    let review = 0;
    const members = [`${setPath}/000001.part`, `${setPath}/manifest.tasarut`];
    w.isTauri = true; w.deletionRequests = []; w.prepareRequests = []; w.discarded = []; w.cancelIds = [];
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      transformCallback: (handler: (event: unknown) => void) => { callbacks.set(++callback, handler); return callback; },
      invoke: async (command: string, args: Record<string, unknown>) => {
        if (command === "plugin:event|listen") {
          if (args.event === "tasarut-deletion-progress") w.emitDeletion = (payload: unknown) => callbacks.get(args.handler as number)?.({ event: "tasarut-deletion-progress", id: 1, payload });
          return 1;
        }
        if (command === "plugin:dialog|open") return [setPath, "/input/source.txt"];
        if (command === "collect_files") return [
          { path: setPath, relativePath: "volume.tasarut.parts", size: 222, volume: true },
          { path: "/input/source.txt", relativePath: "source.txt", size: 1000, volume: false },
        ];
        if (command === "inspect_volume") return { comment: "public", compressed: false, originalSize: 100, paranoid: false, formatVersion: 1, reedSolomon: false, chunkCount: 1 };
        if (command === "prepare_deletion") {
          (w.prepareRequests as unknown[]).push(args.request);
          return { token: `review-${++review}`, preview: { totalFiles: 2, totalBytes: 222, filesystems, items: [
            { source: setPath, kind: "chunks", members, bytes: 222, missingParts: 0, error: null },
            { source: "/input/source.txt", kind: "unknown", members: [], bytes: 0, missingParts: 0, error: "deletion_unrecognized" },
          ] } };
        }
        if (command === "discard_deletion") { (w.discarded as string[]).push(args.token as string); return null; }
        if (command === "run_deletion") {
          (w.deletionRequests as unknown[]).push(args);
          if (expired) throw "deletion_review_expired";
          w.jobId = args.id;
          return new Promise((resolve) => {
            w.finishDeletion = () => resolve({ cancelled: partial, deletedFiles: partial ? 1 : 2, deletedBytes: partial ? 100 : 222, physicalErasureVerified: false,
              results: [
                { source: setPath, kind: "chunks", status: partial ? "cancelled" : "deleted", deletedFiles: partial ? 1 : 2, deletedBytes: partial ? 100 : 222,
                  remaining: partial ? [members[1]] : [], planned: members, disappearanceConfirmed: !partial, directoryRemoved: !partial, synchronizationError: null, error: null, recoveryPath: null },
                { source: "/input/source.txt", kind: "unknown", status: "refused", deletedFiles: 0, deletedBytes: 0, remaining: [], planned: [], disappearanceConfirmed: false, directoryRemoved: false, synchronizationError: null, error: "deletion_unrecognized", recoveryPath: null },
              ],
              trim: filesystems.map((filesystem) => ({ ...filesystem, status: partial ? "cancelled" : args.requestTrim ? "succeeded" : "notRequested", reportedBytes: !partial && args.requestTrim ? 9000000 : null, error: null })),
            });
          });
        }
        if (command === "refresh_deletion_selection") return { paths: partial ? [setPath, "/input/source.txt"] : ["/input/source.txt"], files: [
          ...(partial ? [{ path: setPath, relativePath: "volume.tasarut.parts", size: 122, volume: true }] : []),
          { path: "/input/source.txt", relativePath: "source.txt", size: 1000, volume: false },
        ] };
        if (command === "cancel_batch") { (w.cancelIds as unknown[]).push(args.id); return true; }
        return 0;
      },
    };
  }, { setPath, partial: options.partial ?? false, expired: options.expired ?? false, filesystems });
}

test("deletion requires an exact review and confirmation, with TRIM separate from physical erasure", async ({ page }) => {
  await nativeDeletion(page);
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#password").fill("keep until deletion is confirmed");
  await page.locator("#prepare-deletion").click();
  await expect(page.getByRole("dialog", { name: "Suppression renforcée" })).toBeVisible();
  await expect(page.locator("#deletion-trim")).not.toBeChecked();
  await expect(page.locator(".deletion-filesystems .storage-kind")).toContainText("NVMe non rotatif");
  await expect(page.locator(".deletion-filesystems")).toContainText("dm-0");
  await expect(page.locator(".deletion-filesystems")).toContainText("nvme0n1");
  await expect(page.locator(".deletion-filesystems .storage-discard")).toContainText("Discard non annoncé");
  await expect(page.locator(".deletion-filesystems")).toContainText("ne garantit ni TRIM");
  await expect(page.locator("#deletion-trim")).toBeEnabled();
  const preview = JSON.parse(await page.locator("#deletion-review-json").inputValue());
  expect(preview.filesystems[0].storage).toMatchObject({ kind: "nvme", blockDevice: "dm-0", discardMaxBytes: 0 });
  await expect(page.locator(".deletion-modal .deletion-total")).toContainText("2 fichiers listés pour suppression");
  await expect(page.locator("#deletion-warning")).toContainText("sans corbeille");
  await expect(page.locator(".deletion-preview")).toContainText(setPath);
  await expect(page.locator(".deletion-preview img")).toHaveCount(0);
  await expect(page.locator(".deletion-error")).toContainText("pas un volume Tasarut reconnaissable");
  await page.keyboard.press("Control+Enter");
  expect(await page.evaluate(() => (window as unknown as { deletionRequests: unknown[] }).deletionRequests.length)).toBe(0);
  await page.keyboard.press("Escape");
  await expect(page.locator("#prepare-deletion")).toBeFocused();
  await expect(page.locator("#password")).toHaveValue("keep until deletion is confirmed");
  expect(await page.evaluate(() => (window as unknown as { discarded: string[] }).discarded)).toEqual(["review-1"]);
  await page.locator("#prepare-deletion").click();
  await page.locator("#deletion-trim").check();
  await page.locator("#confirm-deletion").click();
  await expect(page.locator(".progress-panel")).toContainText("tailles logiques");
  const requests = await page.evaluate(() => (window as unknown as { deletionRequests: { token: string; requestTrim: boolean }[] }).deletionRequests);
  expect(requests).toHaveLength(1);
  expect(requests[0]).toMatchObject({ token: "review-2", requestTrim: true });
  await page.evaluate(() => (window as unknown as { finishDeletion: () => void }).finishDeletion());
  await expect(page.locator(".deletion-report")).toContainText("L’effacement physique n’est pas vérifié");
  await expect(page.locator(".trim-result")).toContainText("acceptée par le noyau");
  await expect(page.locator(".trim-result")).toContainText("non attribuables à ces fichiers");
  await expect(page.locator(".file-row")).toHaveCount(1);
  await expect(page.locator(".file-row")).toContainText("source.txt");
  await page.locator(".deletion-report > details summary").click();
  const report = JSON.parse(await page.locator("#deletion-report-json").inputValue());
  expect(report.physicalErasureVerified).toBe(false);
  expect(report.results[0].planned).toHaveLength(2);
  expect(report.trim[0].storage.backingDevices[0].name).toBe("nvme0n1");
  await expect(page.locator(".trim-result .storage-kind")).toContainText("NVMe non rotatif");
  await expect(page.locator("#password")).toHaveValue("");
});

test("cancelling removal reports already removed members and preserves pending selection", async ({ page }) => {
  await nativeDeletion(page, { partial: true, expired: false });
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#prepare-deletion").click();
  await page.locator("#confirm-deletion").click();
  await page.evaluate((source) => { const w = window as unknown as { jobId: string; emitDeletion: (payload: unknown) => void }; w.emitDeletion({ id: w.jobId, phase: "deleting", current: `${source}/000001.part`, deletedFiles: 1, totalFiles: 2, deletedBytes: 100, totalBytes: 222 }); }, setPath);
  await expect(page.locator(".progress-panel")).toContainText("1 / 2 fichiers supprimés");
  await page.keyboard.press("Control+Period");
  await expect(page.locator("#cancel-job")).toHaveText("Annulation en cours…");
  await page.evaluate(() => (window as unknown as { finishDeletion: () => void }).finishDeletion());
  await expect(page.locator(".deletion-report")).toContainText("Annulé");
  await expect(page.locator(".file-row")).toHaveCount(2);
  await page.locator(".deletion-report > details summary").click();
  const report = JSON.parse(await page.locator("#deletion-report-json").inputValue());
  expect(report.deletedFiles).toBe(1);
  expect(report.results[0].remaining[0]).toContain("manifest.tasarut");
  expect(report.trim[0].status).toBe("cancelled");
});

test("expired deletion reviews do not change the selection and opaque recognition is explicitly requested", async ({ page }) => {
  await nativeDeletion(page, { partial: false, expired: true });
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator('[data-mode="decrypt"]').click();
  await page.locator("#deniability").check();
  await page.locator("#password").fill("opaque secret");
  await page.locator("#prepare-deletion").click();
  const preparation = await page.evaluate(() => (window as unknown as { prepareRequests: { allowOpaque: boolean; password: string }[] }).prepareRequests[0]);
  expect(preparation).toMatchObject({ allowOpaque: true, password: "opaque secret" });
  await page.locator("#confirm-deletion").click();
  await expect(page.getByRole("alert")).toContainText("expiré après dix minutes");
  await expect(page.locator(".file-row")).toHaveCount(2);
  await expect(page.locator(".deletion-report")).toHaveCount(0);
});

test("storage observations are per filesystem and do not initiate deletion or interpret device names as HTML", async ({ page }) => {
  const name = "<img src=x onerror=alert(1)>";
  await nativeDeletion(page, { filesystems: [
    { directory: "/ssd", device: "8:1", filesystem: "ext4", storage: { kind: "nonRotational", blockDevice: "sda", backingDevices: [{ name, kind: "nonRotational" }], discardMaxBytes: 1048576 } },
    { directory: "/hdd", device: "8:17", filesystem: "xfs", storage: { kind: "rotational", blockDevice: "sdb", backingDevices: [{ name: "sdb", kind: "rotational" }], discardMaxBytes: 0 } },
    { directory: "/raid", device: "9:0", filesystem: "ext4", storage: { kind: "mixed", blockDevice: "md0", backingDevices: [{ name: "sda", kind: "nonRotational" }, { name: "sdb", kind: "rotational" }], discardMaxBytes: null } },
  ] });
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#prepare-deletion").click();
  const observations = page.locator(".deletion-filesystems article");
  await expect(observations).toHaveCount(3);
  await expect(observations.nth(0)).toContainText("Non rotatif (SSD/flash)");
  await expect(observations.nth(0).locator(".storage-discard")).toContainText("Discard annoncé");
  await expect(observations.nth(0)).toContainText(name);
  await expect(observations.locator("img")).toHaveCount(0);
  await expect(observations.nth(1)).toContainText("Rotatif (HDD déclaré)");
  await expect(observations.nth(1).locator(".storage-discard")).toContainText("Discard non annoncé");
  await expect(observations.nth(2)).toContainText("Stockage mixte");
  await expect(observations.nth(2).locator(".storage-discard")).toContainText("indéterminée");
  await expect(page.locator("#deletion-trim")).not.toBeChecked();
  expect(await page.evaluate(() => (window as unknown as { deletionRequests: unknown[] }).deletionRequests)).toHaveLength(0);
});

test("unknown or absent storage observations never imply SSD or disable controlled deletion", async ({ page }) => {
  await nativeDeletion(page, { filesystems: [
    { directory: "/btrfs", device: "0:32", filesystem: "btrfs", storage: { kind: "unknown", blockDevice: null, backingDevices: [], discardMaxBytes: null } },
    { directory: "/network", device: "0:33", filesystem: "unknown" },
  ] });
  await page.goto("/");
  await page.locator("#add-files").click();
  await page.locator("#prepare-deletion").click();
  await expect(page.locator(".deletion-filesystems .storage-kind")).toHaveText(["Stockage déclaré: Indéterminé", "Stockage déclaré: Indéterminé"]);
  await expect(page.locator(".deletion-filesystems .storage-discard")).toHaveText(["Capacité discard indéterminée", "Capacité discard indéterminée"]);
  await expect(page.locator("#confirm-deletion")).toBeEnabled();
  await expect(page.locator("#deletion-trim")).toBeEnabled();
});

test("storage detection labels are available in all three interface languages", async ({ page }) => {
  await nativeDeletion(page);
  await page.goto("/");
  await page.locator("#add-files").click();
  for (const [language, heading, kind, discard] of [
    ["fr", "Détection du stockage avant suppression", "NVMe non rotatif", "Discard non annoncé"],
    ["en", "Storage detection before deletion", "Non-rotational NVMe", "No discard advertised"],
    ["kab", "Asenqed n uḥraz send tukksa", "NVMe war tuzzya", "Discard ur yettwaseknen ara"],
  ]) {
    await page.locator("#language").selectOption(language);
    await page.locator("#prepare-deletion").click();
    await expect(page.locator(".deletion-filesystems h3")).toHaveText(heading);
    await expect(page.locator(".deletion-filesystems .storage-kind")).toContainText(kind);
    await expect(page.locator(".deletion-filesystems .storage-discard")).toContainText(discard);
    await page.keyboard.press("Escape");
  }
});
