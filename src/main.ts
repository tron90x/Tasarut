import "./style.css";
import "./themes.css";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  createIcons,
  KeyRound,
  ShieldCheck,
  FolderLock,
  LockKeyhole,
  UnlockKeyhole,
  Files,
  FolderPlus,
  Plus,
  X,
  ArrowRight,
  ChevronDown,
  Check,
  CircleAlert,
  WandSparkles,
  Eye,
  EyeOff,
  File,
  FileLock2,
  Languages,
  SlidersHorizontal,
  Info,
  HardDrive,
  RefreshCw,
  Layers,
  Scissors,
  Fingerprint,
  Shield,
  ArrowUpFromLine,
  Keyboard,
  Trash2,
  Palette,
} from "lucide";
import { dictionaries, type Language, type TranslationKey } from "./i18n";
import { shortcuts, matchShortcut, shortcutKeys, ariaShortcut } from "./shortcuts";
import { themes, loadTheme, saveTheme, applyTheme, isTheme, type ThemeId } from "./themes";
import {
  presetProfiles, loadCustomProfiles, saveCustomProfiles, validateSettings, profileName, nameKey,
  freeProfileName, sameSettings, parseProfileDocument, exportProfileDocument, mergeProfiles,
  MAX_PROFILE_BYTES, MAX_PROFILES,
  type ProfileSettings, type UsageProfile, type CustomProfile, type CipherAlgorithm,
} from "./profiles";

interface ProfileEditor {
  kind: "create" | "save" | "duplicate" | "delete";
  id?: string;
  name: string;
  settings: ProfileSettings;
  rememberOutput: boolean;
  folder: string;
  error: string;
}

interface InputFile {
  path: string;
  relativePath: string;
  size: number;
  volume: boolean;
  revocable?: boolean;
}
interface DeletionItem { source: string; kind: string; members: string[]; bytes: number; missingParts: number; error: string | null }
type StorageKind = "nvme" | "nonRotational" | "rotational" | "mixed" | "unknown";
interface StorageInfo {
  kind: StorageKind;
  blockDevice: string | null;
  backingDevices: { name: string; kind: StorageKind }[];
  discardMaxBytes: number | null;
}
interface DeletionReview {
  token: string;
  preview: { items: DeletionItem[]; totalFiles: number; totalBytes: number; filesystems: { directory: string; device: string; filesystem: string; storage?: StorageInfo }[] };
}
interface DeletionProgress {
  id: string; phase: string; current: string; deletedFiles: number; totalFiles: number; deletedBytes: number; totalBytes: number;
}
interface DeletionReport {
  results: { source: string; kind: string; status: string; deletedFiles: number; deletedBytes: number; remaining: string[]; planned: string[]; disappearanceConfirmed: boolean; directoryRemoved: boolean; synchronizationError: string | null; error: string | null; recoveryPath: string | null }[];
  trim: { directory: string; device: string; filesystem: string; storage?: StorageInfo; status: string; reportedBytes: number | null; error: string | null }[];
  cancelled: boolean; deletedFiles: number; deletedBytes: number; physicalErasureVerified: false;
}
interface VolumeInfo {
  algorithm?: CipherAlgorithm;
  comment: string;
  compressed: boolean;
  originalSize: number;
  paranoid: boolean;
  formatVersion: number;
  reedSolomon: boolean;
  chunkCount?: number | null;
  revocable?: boolean;
  revocableId?: string | null;
  revocableIndex?: string | null;
}
interface RepairInfo {
  reedSolomon: boolean;
  correctedBlocks: number;
  correctedBytes: number;
}
interface FileResult {
  source: string;
  output: string | null;
  error: string | null;
  repair: RepairInfo | null;
  recovery: ForceReport | null;
}
type MacStatus = "valid" | "invalid" | "missing" | "notChecked";
interface ForceReport {
  authenticated: false;
  macStatus: MacStatus;
  partial: boolean;
  declaredSize: number;
  recoveredBytes: number;
  outputLimit: number;
  limitReached: boolean;
  decompressionFailed: boolean;
  trailingData: boolean;
  damage: {
    uncorrectableBlocks: number;
    missingBytes: number;
    truncated: boolean;
    descriptorDamaged: boolean;
    noncanonicalPadding: boolean;
    ranges: { offset: number; length: number }[];
    rangesOmitted: boolean;
  };
}
interface Progress {
  id: string;
  completed: number;
  total: number;
  current: string;
  result: FileResult | null;
  byteProgress?: {
    phase: ProgressPhase;
    processedBytes: number;
    totalBytes: number | null;
  };
}
type ProgressPhase = "preparing" | "keyDerivation" | "encrypting" | "authenticating" | "decrypting" | "splitting" | "reassembling" | "wrapping" | "unwrapping" | "recovering" | "publishing" | "complete" | "failed" | "cancelled" | "keyStorage" | "revoking";

const desktop = isTauri();
const saved = (() => { try { return localStorage.getItem("tasarut-language"); } catch { return null; } })();
const storedProfiles = loadCustomProfiles();
const state = {
  language: (saved && saved in dictionaries ? saved : "fr") as Language,
  theme: loadTheme(),
  themeSaved: true,
  page: "workspace",
  mode: "encrypt",
  paths: [] as string[],
  files: [] as InputFile[],
  password: "",
  confirmation: "",
  showPassword: false,
  keyfiles: [] as string[],
  comment: "",
  compress: false,
  algorithm: "xchacha20" as CipherAlgorithm,
  paranoid: false,
  reedSolomon: false,
  forceDecrypt: false,
  recoveryLimitMiB: 4096,
  chunks: false,
  deniability: false,
  revocable: false,
  tpmOwnerAuth: "",
  tpm: { available: false, reason: "revocable_provider_required", device: null } as { available: boolean; reason: string; device: string | null },
  revocationReview: null as null | { token: string; items: { source: string; identifier: string | null; index: string | null; error: string | null }[] },
  revocationResults: [] as { source: string; identifier: string | null; index: string | null; revoked: boolean; hardwareAbsenceConfirmed: boolean; error: string | null }[],
  chunkSizeMiB: 100,
  recursive: false,
  output: "",
  busy: false,
  jobKind: "crypto" as "crypto" | "deleteReview" | "delete",
  deletionReview: null as DeletionReview | null,
  deletionProgress: null as DeletionProgress | null,
  deletionReport: null as DeletionReport | null,
  deletionTrim: false,
  deletionNotice: "",
  cancelSending: false,
  cancelRequested: false,
  cancelled: false,
  selecting: false,
  picking: false,
  excluded: new Set<string>(),
  results: [] as FileResult[],
  error: "",
  progress: null as Progress | null,
  jobId: "",
  inspection: null as { name: string; info: VolumeInfo } | null,
  generatorOpen: false,
  generatorPending: false,
  shortcutsOpen: false,
  profiles: storedProfiles.profiles,
  profileId: "preset-simple",
  profilePending: false,
  profileStorageProblem: storedProfiles.error,
  profileNotice: "",
  profileActionsOpen: false,
  profileDialog: null as ProfileEditor | null,
  generated: "",
  generatorLength: 32,
  symbols: true,
};
const app = document.querySelector<HTMLDivElement>("#app")!;
const t = (key: TranslationKey) => dictionaries[state.language][key];
const esc = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
const icon = (name: string, classes = "") =>
  `<i data-lucide="${name}" class="${classes}" aria-hidden="true"></i>`;
const filename = (path: string) => path.split(/[\\/]/).pop() || path;
function size(bytes: number) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${new Intl.NumberFormat(state.language === "kab" ? "fr" : state.language, { maximumFractionDigits: i ? 1 : 0 }).format(bytes)} ${units[i]}`;
}
function errorText(error: unknown): string {
  const message = String(error);
  if (message.startsWith("revocable_cleanup_failed:")) return `${t("revocable_cleanup_failed")} ${message.split(":")[1]}`;
  return message in dictionaries.en ? t(message as TranslationKey) : message;
}
const locked = () => state.busy || state.selecting || state.picking || state.profilePending;
const disabled = () => locked() ? "disabled" : "";

interface FocusSnapshot {
  selector: string;
  selection?: { start: number; end: number; direction: "forward" | "backward" | "none" };
}
let modalReturnFocus: FocusSnapshot | null = null;
let generatorRequest = 0;
let inspectionRequest = 0;

function captureFocus(): FocusSnapshot | null {
  const element = document.activeElement as HTMLElement | null;
  if (!element || !app.contains(element)) return null;
  const attribute = ["data-page", "data-theme", "data-mode", "data-inspect", "data-remove", "data-remove-key"].find((name) => element.hasAttribute(name));
  const selector = element.id ? `#${CSS.escape(element.id)}`
    : attribute ? `${attribute === "data-theme" ? ".theme-card" : ""}[${attribute}="${CSS.escape(element.getAttribute(attribute)!)}"]` : "#open-shortcuts";
  const snapshot: FocusSnapshot = { selector };
  if ((element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) && element.selectionStart !== null && element.selectionEnd !== null) {
    snapshot.selection = { start: element.selectionStart, end: element.selectionEnd, direction: element.selectionDirection ?? "none" };
  }
  return snapshot;
}

function restoreFocus(snapshot: FocusSnapshot | null): boolean {
  const element = snapshot ? document.querySelector<HTMLElement>(snapshot.selector) : null;
  if (!element || element.matches(":disabled") || element.closest("[inert]")) return false;
  element.focus();
  if (snapshot?.selection && (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement)) {
    element.setSelectionRange(snapshot.selection.start, snapshot.selection.end, snapshot.selection.direction);
  }
  return document.activeElement === element;
}

function render() {
  const modalOpen = state.generatorOpen || state.shortcutsOpen || Boolean(state.profileDialog) || Boolean(state.deletionReview) || Boolean(state.revocationReview);
  const modalFocus = modalOpen && document.activeElement?.closest(".modal") ? captureFocus() : null;
  document.documentElement.lang = state.language;
  const totalSize = state.files.reduce((sum, file) => sum + file.size, 0);
  const paranoid =
    state.mode === "encrypt"
      ? state.paranoid
      : state.inspection?.info.paranoid === true;
  const force = state.mode === "decrypt" && state.forceDecrypt;
  const threefish = state.mode === "encrypt" ? state.algorithm === "threefish1024" : state.inspection?.info.algorithm === "threefish1024";
  app.innerHTML = `
    <aside class="sidebar" ${modalOpen ? "inert" : ""}>
      <a class="brand" href="#" aria-label="Tasarut"><span class="brand-icon">${icon("key-round")}</span><span>Tasarut<small>${t("tagline")}</small></span></a>
      <div class="sidebar-label">TASARUT / 01</div>
      <nav aria-label="Tasarut">
        ${(["workspace", "roadmap", "themes", "about"] as const).map((page, i) => `<button class="nav-item ${state.page === page ? "active" : ""}" data-page="${page}" aria-label="${t(page)}" ${state.page === page ? 'aria-current="page"' : ""}>${icon(["folder-lock", "sliders-horizontal", "palette", "info"][i])}<span>${t(page)}</span></button>`).join("")}
      </nav>
      <div class="sidebar-bottom"><div class="local-status"><span class="status-dot"></span>${t("local")}</div><p>${t("version")}</p></div>
    </aside>
    <main ${modalOpen ? "inert" : ""}>
      <header class="topbar"><div class="breadcrumb">Tasarut <span>/</span> ${t(state.page as "workspace" | "roadmap" | "themes" | "about")}</div>
        <div class="topbar-actions">${themeSelector()}<button class="secondary shortcuts-button" id="open-shortcuts" aria-label="${t("keyboardShortcuts")}" aria-haspopup="dialog">${icon("keyboard")}<span>${t("keyboardShortcuts")}</span><kbd>F1</kbd></button><div class="language">${icon("languages")}<select id="language" aria-label="${t("language")}" ${disabled()}><option value="en" ${state.language === "en" ? "selected" : ""}>English</option><option value="fr" ${state.language === "fr" ? "selected" : ""}>Français</option><option value="kab" ${state.language === "kab" ? "selected" : ""}>Taqbaylit</option></select>${icon("chevron-down")}</div></div>
      </header>
      <div class="content">
        ${!desktop ? `<div class="preview-banner">${icon("info")} ${t("desktopOnly")}</div>` : ""}
        ${
          state.page === "workspace"
            ? `
          <section class="intro"><div class="eyebrow">${t("eyebrow")}</div><h1>${t("title")}</h1><p>${t("subtitle")}</p></section>
          <div class="workspace-grid">
            <div class="files-column">
              <div class="mode-tabs" role="group" aria-label="${t("workspace")}">${["encrypt", "decrypt"].map((mode) => `<button data-mode="${mode}" class="${state.mode === mode ? "selected" : ""}" aria-pressed="${state.mode === mode}" ${disabled()}>${icon(mode === "encrypt" ? "lock-keyhole" : "unlock-keyhole")}${t(mode as "encrypt" | "decrypt")}</button>`).join("")}</div>
              <section class="card file-card"><div class="section-heading"><h2>${t("files")} <span class="count">${state.files.length.toString().padStart(2, "0")}</span></h2><button class="text-button" id="clear-files" ${disabled()}>${t("clear")}</button></div>
                <button class="dropzone" id="dropzone" ${disabled()}><span class="drop-icon">${icon("arrow-up-from-line")}</span><strong>${t("dropTitle")}</strong><span>${t("dropHint")}</span><small>${t(state.deniability ? "deniabilityDropFooter" : "dropFooter")}</small></button>
                <div class="file-actions"><button class="secondary" id="add-files" ${disabled()}>${icon("plus")}${t("addFiles")}</button><button class="secondary" id="add-folder" ${disabled()}>${icon("folder-plus")}${t("addFolder")}</button></div>
                <div class="file-list">${state.files.length ? state.files.map((file, i) => `<div class="file-row"><span class="file-icon ${file.volume ? "encrypted" : ""}">${icon(file.volume ? "file-lock-2" : "file")}</span><button class="file-details" data-inspect="${i}" title="${esc(file.path)}" ${disabled()}><strong>${esc(file.relativePath)}</strong><small>${size(file.size)} <span>·</span> ${t(state.deniability && state.mode === "decrypt" ? "opaqueFile" : file.volume ? "volume" : "plain")}</small></button><button class="icon-button" data-remove="${i}" aria-label="${t("remove")} ${esc(filename(file.path))}" ${disabled()}>${icon("x")}</button></div>`).join("") : `<div class="empty-state">${icon("files")}<span>${t("empty")}</span></div>`}</div>
                <div class="file-summary"><span>${state.files.length} ${t("fileCount")}</span><span>${size(totalSize)}</span></div>
              </section>
              <section class="card deletion-action"><button class="secondary danger" id="prepare-deletion" ${locked() || !state.files.length ? "disabled" : ""}>${icon("trash-2")}${t("deletionTitle")}</button><p class="hint">${t("deletionActionHint")}</p></section>
              ${state.files.some((file) => file.revocable) ? `<section class="card revocable-action"><button class="secondary danger" id="prepare-revocation" ${locked() || !state.tpm.available ? "disabled" : ""}>${icon("key-round")}${t("revokeVolumes")}</button><p class="hint">${t("revocableCopiesHint")}</p></section>` : ""}
              ${state.inspection ? `<section class="card inspection"><div class="section-heading"><h2>${t("comments")}</h2><button class="icon-button" id="close-inspection" aria-label="${t("close")}">${icon("x")}</button></div><small>${esc(state.inspection.name)}</small><div class="volume-profile">${icon("shield-check")}${t(state.inspection.info.paranoid ? "paranoid" : "standardMode")} · v${state.inspection.info.formatVersion}${state.inspection.info.reedSolomon ? ` · ${t("reed")}` : ""}${state.inspection.info.chunkCount ? ` · ${state.inspection.info.chunkCount} ${t("partsCount")}` : ""}</div><p class="comment-content">${esc(state.inspection.info.comment || t("noComment"))}</p><p class="hint">${t("commentHint")}</p></section>` : `<p class="inspection-hint">${icon("info")}${t("inspectHint")}</p>`}
              <section class="crypto-card ${force ? "force-card" : ""}"><span class="crypto-shield">${icon(force ? "circle-alert" : "shield-check")}</span><div><div class="eyebrow">${t("architecture")}</div><h3>${t(threefish ? "threefishAlgorithms" : paranoid ? "paranoidAlgorithms" : "algorithms")}</h3><p>${t(state.deniability ? "deniabilityKdf" : threefish ? "threefishKdf" : paranoid ? "paranoidKdf" : "kdf")}</p><p>${t(force ? "forceWarning" : "integrity")}</p></div><span class="crypto-decoration"></span></section>
            </div>
            <div class="settings-column">
              ${profilesMarkup()}
              <section class="card credentials"><div class="section-heading"><h2>${icon("key-round")}${t("credentials")}</h2><button class="text-button mint" id="open-generator" ${disabled()}>${icon("wand-sparkles")}${t("generator")}</button></div>
                <label class="field-label" for="password">${t("password")}</label><div class="password-field"><input id="password" type="${state.showPassword ? "text" : "password"}" value="${esc(state.password)}" placeholder="${t("passwordPlaceholder")}" autocomplete="off" spellcheck="false" ${disabled()}><button id="toggle-password" class="icon-button" aria-label="${t(state.showPassword ? "hide" : "show")}" ${disabled()}>${icon(state.showPassword ? "eye-off" : "eye")}</button></div><p class="hint">${t("passwordHint")}</p>
                ${state.mode === "encrypt" ? `<label class="field-label" for="confirmation">${t("confirm")}</label><input id="confirmation" type="${state.showPassword ? "text" : "password"}" value="${esc(state.confirmation)}" placeholder="${t("confirmPlaceholder")}" autocomplete="off" spellcheck="false" ${disabled()}>` : ""}
                <div class="keyfile-section"><div class="section-heading"><label>${t("keyfiles")} <span class="optional-count">${state.keyfiles.length || ""}</span></label><button class="text-button" id="add-keyfiles" ${disabled()}>${icon("plus")}${t("addKeyfiles")}</button></div>
                  ${state.keyfiles.map((path, i) => `<div class="keyfile-chip"><span>${i + 1}. ${esc(filename(path))}</span><button class="icon-button" data-remove-key="${i}" aria-label="${t("remove")} ${esc(filename(path))}" ${disabled()}>${icon("x")}</button></div>`).join("")}<p class="hint">${t("keyfileHint")}</p></div>
              </section>
               <section class="card options"><h2>${t("options")}</h2>
                 ${cipherOptionsMarkup()}
                ${revocableOptionsMarkup()}
                <label class="option-row"><span><strong>${icon("fingerprint")}${t("deniability")}</strong><small>${t("deniabilityHint")}</small></span><input class="switch" type="checkbox" id="deniability" ${state.deniability ? "checked" : ""} ${disabled()}></label>${state.deniability ? `<p class="hint deniability-details" role="status">${t("deniabilityDetails")}</p>` : ""}
                ${state.mode === "encrypt" ? `<label class="option-row paranoid-option"><span><strong>${icon("shield")}${t("paranoid")}</strong><small>${t("paranoidHint")}</small></span><input class="switch" type="checkbox" id="paranoid" ${state.paranoid ? "checked" : ""} ${disabled()}></label>${state.paranoid ? `<p class="paranoid-cost" role="status">${t("paranoidCost")}</p>` : ""}` : `<p class="hint auto-mode">${t(state.deniability ? "deniabilityDecryptHint" : "autoModeHint")}</p>`}
                ${state.mode === "decrypt" ? `<label class="option-row"><span><strong>${t("force")}</strong><small>${t("forceHint")}</small></span><input class="switch" type="checkbox" id="force-decrypt" ${force ? "checked" : ""} ${state.deniability ? "disabled" : disabled()}></label>${force ? `<div class="force-notice" role="status"><p>${t("forceWarning")}</p><label class="field-label" for="recovery-limit">${t("recoveryLimit")}</label><input type="number" id="recovery-limit" min="1" max="1048576" step="1" value="${state.recoveryLimitMiB}" ${disabled()}><p class="hint">${t("recoveryLimitHint")}</p></div>` : ""}` : ""}
                ${state.mode === "encrypt" ? `<label class="option-row"><span><strong>${t("reed")}</strong><small>${t("reedHint")}</small></span><input class="switch" type="checkbox" id="reed-solomon" ${state.reedSolomon ? "checked" : ""} ${disabled()}></label>${state.reedSolomon ? `<p class="reed-cost hint">${t("reedCost")}</p>` : ""}` : ""}
                ${state.mode === "encrypt" ? `<label class="option-row"><span><strong>${t("compress")}</strong><small>${t("compressHint")}</small></span><input class="switch" type="checkbox" id="compress" ${state.compress ? "checked" : ""} ${disabled()}></label>` : ""}
                ${state.mode === "encrypt" ? `<label class="option-row"><span><strong>${t("chunks")}</strong><small>${t("chunksHint")}</small></span><input class="switch" type="checkbox" id="chunks" ${state.chunks ? "checked" : ""} ${state.deniability ? "disabled" : disabled()}></label>${state.chunks ? `<label class="field-label" for="chunk-size">${t("chunkSize")}</label><input id="chunk-size" type="number" min="1" max="1048576" step="1" value="${state.chunkSizeMiB}" ${disabled()}><p class="hint">${t("chunkSizeHint")}</p>` : ""}` : state.deniability ? "" : `<p class="hint">${t("chunksDecryptHint")}</p>`}
                <label class="option-row"><span><strong>${t("recursive")}</strong><small>${t("recursiveHint")}</small></span><input class="switch" type="checkbox" id="recursive" ${state.recursive ? "checked" : ""} ${disabled()}></label>
                ${state.mode === "encrypt" && !state.deniability ? `<div class="comments-field"><label class="field-label" for="comment">${t("comments")} ${icon("info")}</label><textarea id="comment" rows="3" maxlength="65536" placeholder="${t("commentPlaceholder")}" ${disabled()}>${esc(state.comment)}</textarea><p class="hint">${t("commentHint")}</p></div>` : ""}
              </section>
              <section class="card destination"><label class="field-label">${t("destination")}</label><button class="folder-picker" id="output-folder" ${disabled()}>${icon("hard-drive")}<span title="${esc(state.output)}">${esc(state.output || t("chooseFolder"))}</span>${icon("chevron-down")}</button><p class="hint">${t("destinationHint")}</p></section>
              <button class="primary start-button ${force ? "force-button" : ""}" id="start" ${disabled()}>${icon(state.busy ? "refresh-cw" : state.mode === "encrypt" ? "lock-keyhole" : "unlock-keyhole", state.busy ? "spin" : "")}<span>${t(state.busy ? "processing" : force ? "startRecovery" : state.mode === "encrypt" ? "startEncrypt" : "startDecrypt")}</span>${icon("arrow-right")}</button>
              <div class="action-caption">${icon("shield-check")}${t("preserved")}</div>
            </div>
          </div>
          ${state.busy ? progressMarkup() : ""}
          ${state.cancelled ? `<div class="card cancelled-banner" role="status">${t("cancelledNotice")}</div>` : ""}
          ${state.results.length ? `<section class="card results"><h2>${t("results")}</h2>${state.results.map(resultMarkup).join("")}</section>` : ""}
          ${state.deletionNotice ? `<div class="card cancelled-banner" role="status">${esc(state.deletionNotice)}</div>` : ""}
          ${state.deletionReport ? deletionReportMarkup(state.deletionReport) : ""}
          ${state.revocationResults.length ? revocationReportMarkup() : ""}
        `
            : state.page === "roadmap"
              ? roadmap()
              : state.page === "themes" ? themeGallery() : about()
        }
        ${state.error ? `<div class="error-banner" role="alert">${icon("circle-alert")}<div><strong>${t("errorTitle")}</strong><p>${esc(errorText(state.error))}</p></div><button class="icon-button" id="dismiss-error" aria-label="${t("close")}">${icon("x")}</button></div>` : ""}
        <footer>${icon("shield-check")} ${t("offline")}<span>TASARUT <span class="mint">0.4</span></span></footer>
      </div>
    </main>
    ${state.generatorOpen ? generatorModal() : ""}
    ${state.shortcutsOpen ? shortcutsModal() : ""}
    ${state.profileDialog ? profileDialogMarkup() : ""}
    ${state.deletionReview ? deletionReviewMarkup() : ""}
    ${state.revocationReview ? revocationReviewMarkup() : ""}
  `;
  if (state.profileDialog && state.profileDialog.kind !== "delete") {
    document.querySelector(".profile-editor-options")?.insertAdjacentHTML("beforebegin", cipherSelect("profile-algorithm", state.profileDialog.settings.algorithm ?? "xchacha20"));
    if (state.profileDialog.settings.algorithm === "threefish1024") {
      const input = document.getElementById("profile-option-paranoid") as HTMLInputElement | null;
      if (input) input.disabled = true;
    }
  }
  if (state.algorithm === "threefish1024") {
    const input = document.getElementById("paranoid") as HTMLInputElement | null;
    if (input) input.disabled = true;
  }
  const inspected = state.inspection?.info;
  if (inspected?.algorithm === "threefish1024") {
    const profile = document.querySelector(".volume-profile");
    if (profile) profile.innerHTML = `${icon("shield-check")}${t("threefishOption")} · v${inspected.formatVersion}${inspected.reedSolomon ? ` · ${t("reed")}` : ""}${inspected.chunkCount ? ` · ${inspected.chunkCount} ${t("partsCount")}` : ""}`;
  }
  if (state.page === "about") {
    document.querySelector(".about-facts")?.insertAdjacentHTML("beforeend", `<div>${icon("shield")}<span>${t("threefishAlgorithms")}<small>${t("threefishKdf")}</small></span></div>`);
  }
  createIcons({
    icons: {
      KeyRound,
      ShieldCheck,
      FolderLock,
      LockKeyhole,
      UnlockKeyhole,
      Files,
      FolderPlus,
      Plus,
      X,
      ArrowRight,
      ChevronDown,
      Check,
      CircleAlert,
      WandSparkles,
      Eye,
      EyeOff,
      File,
      FileLock2,
      Languages,
      SlidersHorizontal,
      Info,
      HardDrive,
      RefreshCw,
      Layers,
      Scissors,
      Fingerprint,
      Shield,
      ArrowUpFromLine,
      Keyboard,
      Trash2,
      Palette,
    },
  });
  bindEvents();
  if (state.deletionReview) {
    const filesystems = document.querySelector(".deletion-filesystems");
    if (filesystems) filesystems.innerHTML = `<h3>${t("storageBeforeDeletion")}</h3><p>${t("storageObservationHint")}</p>${state.deletionReview.preview.filesystems.map((filesystem) => `<article><strong>${esc(filesystem.directory)}</strong><p>${esc(filesystem.filesystem)} · ${t("deletionDevice")}: ${esc(filesystem.device)}</p>${storageMarkup(filesystem.storage)}</article>`).join("")}`;
    const total = document.querySelector(".deletion-modal .deletion-total strong");
    if (total) total.textContent = `${state.deletionReview.preview.totalFiles} ${t("deletionListedFiles")} · ${size(state.deletionReview.preview.totalBytes)}`;
    const actions = document.querySelector(".deletion-modal .modal-actions");
    if (actions) {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = t("deletionJSONReview");
      const text = document.createElement("textarea");
      text.id = "deletion-review-json"; text.readOnly = true; text.rows = 8;
      text.setAttribute("aria-label", t("deletionJSONReview"));
      text.value = JSON.stringify(state.deletionReview.preview, null, 2);
      details.append(summary, text); actions.before(details);
    }
  }
  if (state.deletionReport) {
    document.querySelectorAll(".trim-result").forEach((element, index) => {
      element.insertAdjacentHTML("beforeend", storageMarkup(state.deletionReport!.trim[index]?.storage));
    });
  }
  if (state.revocable || state.files.some((file) => file.revocable)) {
    for (const id of ["chunks", "deniability", "force-decrypt"]) {
      const input = document.getElementById(id) as HTMLInputElement | null;
      if (input) input.disabled = true;
    }
    if (state.revocable && state.mode === "encrypt") {
      const comment = document.querySelector<HTMLElement>(".comments-field");
      if (comment) comment.hidden = true;
    }
    const kdf = document.querySelector(".crypto-card p");
    if (kdf) kdf.textContent = t("revocableKdf");
  }
  decorateShortcuts();
  if (modalOpen && !restoreFocus(modalFocus)) document.querySelector<HTMLButtonElement>(".modal .section-heading button")?.focus();
}

function themeSelector() {
  return `<label class="theme-control" title="${t("themeSelect")}">${icon("palette")}<select id="theme-select" aria-label="${t("themeSelect")}" ${disabled()}>${themes.map((theme) => `<option value="${theme.id}" ${state.theme === theme.id ? "selected" : ""}>${t(theme.name)}</option>`).join("")}</select></label>`;
}

function cipherSelect(id: string, selected: CipherAlgorithm) {
  return `<div class="cipher-selection"><label class="field-label" for="${id}">${t("cipherLabel")}</label><select class="algorithm-select" id="${id}" ${disabled()}><option value="xchacha20" ${selected === "xchacha20" ? "selected" : ""}>${t("xchachaOption")}</option><option value="threefish1024" ${selected === "threefish1024" ? "selected" : ""}>${t("threefishOption")}</option></select></div>`;
}
function cipherOptionsMarkup() {
  if (state.mode !== "encrypt") return `<p class="hint cipher-auto">${t("cipherAuto")}</p>`;
  return cipherSelect("cipher-algorithm", state.algorithm) + (state.algorithm === "threefish1024" ? `<p class="hint threefish-details" role="status">${t("threefishHint")}</p>` : "");
}

function themeGallery() {
  return `<section class="intro"><div class="eyebrow">TASARUT / ${t("themes")}</div><h1>${t("themeTitle")}</h1><p>${t("themeSubtitle")}</p></section><p class="theme-preference-note" role="status">${icon(state.themeSaved ? "shield-check" : "info")}${t(state.themeSaved ? "themePreference" : "themeMemoryOnly")}</p><section class="theme-gallery" aria-label="${t("themeSelect")}">${themes.map((theme) => `<button class="theme-card" data-theme="${theme.id}" data-theme-preview="${theme.id}" aria-pressed="${state.theme === theme.id}" aria-labelledby="theme-name-${theme.id}" aria-describedby="theme-description-${theme.id}" ${disabled()}><span class="theme-landscape" aria-hidden="true"><span class="theme-miniature"><span></span><span></span><span></span></span></span><span class="theme-caption"><span class="theme-card-title"><strong id="theme-name-${theme.id}">${t(theme.name)}</strong>${state.theme === theme.id ? `<span class="theme-selected">${t("themeSelected")}</span>${icon("check")}` : ""}</span><span class="theme-description" id="theme-description-${theme.id}">${t(theme.description)}</span></span></button>`).join("")}</section>`;
}

function changeTheme(theme: ThemeId) {
  if (locked()) return;
  const focus = captureFocus();
  state.theme = theme;
  applyTheme(theme);
  state.themeSaved = saveTheme(theme);
  render();
  restoreFocus(focus);
}

function roadmap() {
  return `<section class="intro"><div class="eyebrow">TASARUT / ROADMAP</div><h1>${t("roadmapTitle")}</h1><p>${t("roadmapSubtitle")}</p></section><div class="roadmap-grid">${(
    [
      ["paranoid", "paranoidHint", "shield"],
      ["reed", "reedHint", "layers"],
      ["force", "forceHint", "unlock-keyhole"],
      ["chunks", "chunksHint", "scissors"],
      ["deniability", "deniabilityHint", "fingerprint"],
    ] as const
  )
    .map(
      ([name, hint, image]) =>
        `<article class="card roadmap-card"><div class="roadmap-card-top">${icon(image)}<span class="available">${t("available")}</span></div><h2>${t(name)}</h2><p>${t(hint)}</p><button class="secondary" id="enable-${name}" ${disabled()}>${t(name === "deniability" ? "enableDeniability" : name === "chunks" ? "enableChunks" : name === "reed" ? "enableReed" : name === "force" ? "enableForce" : "enableParanoid")}${icon("arrow-right")}</button></article>`,
    )
    .join("")}</div>`;
}

function allProfiles(): UsageProfile[] { return [...presetProfiles, ...state.profiles]; }
function selectedProfile() { return allProfiles().find((profile) => profile.id === state.profileId); }
function profileTitle(profile: UsageProfile) { return "label" in profile ? t(profile.label) : profile.name; }
function profileNames() { return allProfiles().map(profileTitle); }
function currentProfileSettings(rememberOutput = false): ProfileSettings {
  const chunkSize = !state.chunks && (!Number.isInteger(state.chunkSizeMiB) || state.chunkSizeMiB < 1 || state.chunkSizeMiB > 1048576) ? 100 : state.chunkSizeMiB;
  return {
    algorithm: state.algorithm,
    compress: state.compress, paranoid: state.paranoid, reedSolomon: state.reedSolomon,
    chunks: state.chunks, chunkSizeMiB: chunkSize, deniability: state.deniability,
    recursive: state.recursive, generatorLength: state.generatorLength, generatorSymbols: state.symbols,
    revocable: state.revocable,
    ...(rememberOutput && state.output ? { outputDirectory: state.output } : {}),
  };
}
function profileDirty() {
  const profile = selectedProfile();
  return Boolean(profile && !sameSettings(profile.settings, currentProfileSettings(profile.settings.outputDirectory !== undefined)));
}
function profileSummary(settings: ProfileSettings): string {
  const features = [t(settings.revocable ? "revocable" : settings.deniability ? "deniability" : settings.algorithm === "threefish1024" ? "threefishOption" : settings.paranoid ? "paranoid" : "standardMode")];
  if (settings.algorithm === "threefish1024" && (settings.revocable || settings.deniability)) features.push(t("threefishOption"));
  if (settings.revocable && settings.paranoid) features.push(t("paranoid"));
  if (settings.deniability && settings.paranoid) features.push(t("paranoid"));
  if (settings.compress) features.push(t("compress"));
  if (settings.reedSolomon) features.push(t("reed"));
  if (settings.chunks) features.push(`${t("chunks")} · ${Number.isInteger(settings.chunkSizeMiB) && settings.chunkSizeMiB >= 1 && settings.chunkSizeMiB <= 1048576 ? size(settings.chunkSizeMiB * 1024 * 1024) : t("invalid_chunk_size")}`);
  if (settings.recursive) features.push(t("recursive"));
  features.push(`${t("generator")} · ${settings.generatorLength}${settings.generatorSymbols ? ` · ${t("symbols")}` : ""}`);
  return features.join(" · ");
}
function profileCosts(settings: ProfileSettings) {
  return `<p class="profile-cost-label">${t("profileCosts")}</p><p>${t(settings.algorithm === "threefish1024" || settings.paranoid || settings.deniability || settings.revocable ? "profileMemory256" : "profileMemory64")}</p>${settings.reedSolomon ? `<p>${t("profileReedCost")}</p>` : ""}${settings.chunks || settings.deniability ? `<p>${t("profileTemporaryCost")}</p>` : ""}`;
}
function profileLiveMarkup() {
  const profile = selectedProfile();
  const settings = currentProfileSettings(profile?.settings.outputDirectory !== undefined);
  return `<div class="profile-state ${profileDirty() ? "modified" : ""}" role="status">${t(!profile ? "profileManual" : profileDirty() ? "profileModified" : "profileActive")}</div><p class="profile-summary">${esc(profileSummary(settings))}</p>${settings.outputDirectory ? `<p class="profile-folder">${t("destination")}: ${esc(settings.outputDirectory)}</p>` : ""}<div class="profile-costs hint">${profileCosts(settings)}</div>${state.mode === "decrypt" ? `<p class="hint">${t("profileDecryptHint")}</p>` : ""}${state.profileNotice ? `<p class="profile-notice" role="status">${esc(state.profileNotice)}</p>` : ""}`;
}
function storageLabel(kind?: StorageKind) {
  const labels: Record<StorageKind, TranslationKey> = { nvme: "storageNvme", nonRotational: "storageNonRotational", rotational: "storageRotational", mixed: "storageMixed", unknown: "storageUnknown" };
  return t(kind && labels[kind] || "storageUnknown");
}
function storageMarkup(storage?: StorageInfo) {
  const discard = storage?.discardMaxBytes;
  const discardLabel = discard === null || discard === undefined ? "storageDiscardUnknown" : discard > 0 ? "storageDiscardAvailable" : "storageDiscardUnavailable";
  return `<div class="deletion-storage"><p class="storage-kind"><strong>${t("storageKindLabel")}: ${storageLabel(storage?.kind)}</strong></p>${storage?.blockDevice ? `<p>${t("storageDevice")}: ${esc(storage.blockDevice)}</p>` : ""}${storage?.backingDevices.length ? `<p>${t("storageBacking")}: ${storage.backingDevices.map((device) => `${esc(device.name)} (${storageLabel(device.kind)})`).join(", ")}</p>` : ""}<p class="storage-discard">${t(discardLabel)}</p></div>`;
}
function deletionKind(kind: string) { return t(kind === "chunks" ? "deletionKindChunks" : kind === "opaque" ? "deletionKindOpaque" : kind === "volume" ? "volume" : "deletionKindUnknown"); }
function deletionReviewMarkup() {
  const review = state.deletionReview!;
  return `<div class="modal-backdrop"><section class="modal card deletion-modal" role="dialog" aria-modal="true" aria-labelledby="deletion-title" aria-describedby="deletion-warning"><div class="section-heading"><h2 id="deletion-title">${icon("trash-2")}${t("deletionTitle")}</h2><button class="icon-button" id="close-deletion-review" aria-label="${t("close")}" aria-keyshortcuts="Escape">${icon("x")}</button></div><p class="deletion-warning" id="deletion-warning">${t("deletionWarning")}</p><p class="hint">${t("deletionRecognitionHint")}</p><p class="deletion-total"><strong>${review.preview.totalFiles} ${t("deletionFiles")} · ${size(review.preview.totalBytes)}</strong></p><div class="deletion-preview">${review.preview.items.map((item, index) => `<article><strong>${esc(item.source)}</strong><p>${deletionKind(item.kind)} · ${size(item.bytes)}</p>${item.error ? `<p class="deletion-error">${esc(errorText(item.error))}</p>` : `<details><summary id="deletion-members-${index}">${item.members.length} ${t("deletionListedFiles")}</summary>${item.members.slice(0, 200).map((path) => `<p>${esc(path)}</p>`).join("")}${item.members.length > 200 ? `<p>${t("deletionListTruncated")}</p>` : ""}</details>`}${item.missingParts ? `<p class="hint">${item.missingParts} ${t("deletionMissingParts")}</p>` : ""}</article>`).join("")}</div><label class="option-row"><span><strong>${t("deletionRequestTrim")}</strong><small>${t("deletionTrimScope")}</small></span><input class="switch" id="deletion-trim" type="checkbox" ${state.deletionTrim ? "checked" : ""}></label>${review.preview.filesystems.length ? `<div class="deletion-filesystems hint">${review.preview.filesystems.map((filesystem) => `<p>${esc(filesystem.directory)} · ${esc(filesystem.filesystem)} · ${t("deletionDevice")}: ${esc(filesystem.device)}</p>`).join("")}</div>` : ""}<p class="hint">${t("deletionTrimPermissions")}</p><div class="modal-actions"><button class="secondary" id="cancel-deletion-review">${t("close")}</button><button class="primary danger" id="confirm-deletion" ${review.preview.totalFiles ? "" : "disabled"}>${t("deletionConfirm")}</button></div></section></div>`;
}
function deletionProgressMarkup() {
  const progress = state.deletionProgress;
  const deleting = state.jobKind === "delete" && progress?.phase === "deleting" && progress.totalBytes > 0;
  const fraction = deleting ? Math.min(1, progress!.deletedBytes / progress!.totalBytes) : null;
  const phase = state.jobKind === "deleteReview" ? "deletionPreparing" : progress?.phase === "trimming" ? "deletionTrimming" : progress?.phase === "complete" ? "deletionFinished" : progress?.phase === "cancelled" ? "cancelledStatus" : "deletionDeleting";
  return `<div><strong>${t("deletionTitle")}</strong><span class="progress-files">${progress?.deletedFiles ?? 0} / ${progress?.totalFiles ?? 0} ${t("deletionFiles")}</span></div><div class="progress-phase"><strong>${t(phase)}</strong><span>${fraction === null ? "" : `${Math.round(fraction * 100)} %`}</span></div><progress aria-label="${t("deletionProgressLabel")}" max="1" ${fraction === null ? "" : `value="${fraction}"`}></progress><div class="progress-bytes">${size(progress?.deletedBytes ?? 0)}${progress?.totalBytes ? ` / ${size(progress.totalBytes)}` : ""}</div><p>${esc(progress?.current || "")}</p><small>${t("deletionLogicalBytes")} ${t("working")}</small>`;
}
function deletionReportMarkup(report: DeletionReport) {
  const statusLabels: Record<string, TranslationKey> = { deleted: "deletionDeleted", partial: "deletionPartial", refused: "deletionRefused", cancelled: "cancelledStatus", notProcessed: "notProcessedStatus" };
  const trimLabels: Record<string, TranslationKey> = { notRequested: "trimNotRequested", noDeletion: "trimNoDeletion", cancelled: "cancelledStatus", succeeded: "trimSucceeded", permissionDenied: "trimPermissionDenied", unsupported: "trimUnsupported", failed: "trimFailed" };
  return `<section class="card deletion-report"><h2>${t("deletionReportTitle")}</h2><p class="deletion-total">${report.deletedFiles} ${t("deletionFiles")} · ${size(report.deletedBytes)}${report.cancelled ? ` · ${t("cancelledStatus")}` : ""}</p><p class="deletion-warning">${t("deletionPhysicalUnknown")}</p>${report.results.map((result) => `<article class="deletion-result"><div><strong>${esc(result.source)}</strong><span>${t(statusLabels[result.status] ?? "deletionRefused")}</span></div><p>${result.deletedFiles} ${t("deletionFiles")} · ${size(result.deletedBytes)} · ${t(result.disappearanceConfirmed ? "deletionAbsenceVerified" : "deletionAbsenceUnverified")}</p>${result.directoryRemoved ? `<p>${t("deletionDirectoryRemoved")}</p>` : ""}${result.error ? `<p class="deletion-error">${esc(errorText(result.error))}</p>` : ""}${result.synchronizationError ? `<p class="deletion-error">${t("deletionSyncFailed")} ${esc(result.synchronizationError)}</p>` : ""}${result.recoveryPath ? `<p class="deletion-error">${t("deletionRecoveryPath")} ${esc(result.recoveryPath)}</p>` : ""}${result.remaining.length ? `<details><summary>${result.remaining.length} ${t("deletionRemaining")}</summary>${result.remaining.slice(0, 200).map((path) => `<p>${esc(path)}</p>`).join("")}${result.remaining.length > 200 ? `<p>${t("deletionListTruncated")}</p>` : ""}</details>` : ""}</article>`).join("")}<h3>${t("deletionTrimReport")}</h3><p class="hint">${t("deletionTrimScope")}</p>${report.trim.map((trim) => `<article class="trim-result"><strong>${esc(trim.directory)} · ${esc(trim.filesystem)}</strong><p>${t(trimLabels[trim.status] ?? "trimFailed")}${trim.reportedBytes !== null ? ` · ${size(trim.reportedBytes)} ${t("trimReportedBytes")}` : ""}</p>${trim.error ? `<p class="hint">${esc(trim.error)}</p>` : ""}</article>`).join("")}<details><summary>${t("deletionJSONReport")}</summary><textarea id="deletion-report-json" readonly rows="10" spellcheck="false" aria-label="${t("deletionJSONReport")}">${esc(JSON.stringify(report, null, 2))}</textarea></details></section>`;
}
async function prepareDeletion() {
  if (locked() || state.profileDialog || state.deletionReview || state.generatorOpen || state.shortcutsOpen || !state.files.length || !requireDesktop()) return;
  const origin = captureFocus();
  state.jobKind = "deleteReview"; state.busy = true; state.cancelSending = false; state.cancelRequested = false;
  state.jobId = crypto.randomUUID(); state.deletionProgress = null; state.deletionNotice = ""; state.error = "";
  render();
  try {
    const review = await invoke<DeletionReview>("prepare_deletion", { request: { id: state.jobId, paths: state.files.map((file) => file.path), allowOpaque: state.mode === "decrypt" && state.deniability,
      password: state.mode === "decrypt" && state.deniability ? state.password : "", keyfiles: state.keyfiles,
    } });
    state.shortcutsOpen = false;
    state.deletionReview = review; state.deletionTrim = false;
    modalReturnFocus = origin;
  } catch (error) {
    if (String(error) === "operation_cancelled") state.deletionNotice = t("deletionPreparationCancelled");
    else state.error = String(error);
  } finally { state.busy = false; state.jobKind = "crypto"; state.cancelSending = false; state.cancelRequested = false; render(); }
}
function closeDeletionReview() {
  const token = state.deletionReview?.token;
  state.deletionReview = null; state.deletionTrim = false;
  if (token) void invoke("discard_deletion", { token }).catch(() => {});
  render();
  if (!restoreFocus(modalReturnFocus)) document.getElementById("prepare-deletion")?.focus();
  modalReturnFocus = null;
}
async function runDeletion() {
  const review = state.deletionReview;
  if (!review || !review.preview.totalFiles || locked()) return;
  const requestTrim = state.deletionTrim;
  state.deletionReview = null; modalReturnFocus = null;
  state.busy = true; state.jobKind = "delete"; state.jobId = crypto.randomUUID(); state.deletionProgress = null;
  state.cancelSending = false; state.cancelRequested = false; state.error = ""; state.deletionReport = null;
  render();
  try {
    const report = await invoke<DeletionReport>("run_deletion", { id: state.jobId, token: review.token, requestTrim });
    state.deletionReport = report;
    const gone = new Set(report.results.filter((result) => result.disappearanceConfirmed && (result.kind !== "chunks" || result.directoryRemoved)).map((result) => result.source));
    state.files = state.files.filter((file) => !gone.has(file.path));
    const selection = await invoke<{ paths: string[]; files: InputFile[] }>("refresh_deletion_selection", { paths: state.paths, recursive: state.recursive });
    state.paths = selection.paths; state.files = selection.files.filter((file) => !state.excluded.has(file.path));
    state.inspection = null; inspectionRequest++;
  } catch (error) { state.error = String(error); }
  finally {
    state.busy = false; state.jobKind = "crypto"; state.cancelSending = false; state.cancelRequested = false;
    state.password = ""; state.confirmation = ""; state.generated = ""; state.showPassword = false;
    render();
  }
}

function revocableOptionsMarkup() {
  const needed = state.revocable || state.files.some((file) => file.revocable);
  return `${state.mode === "encrypt" ? `<label class="option-row"><span><strong>${t("revocable")}</strong><small>${t("revocableHint")}</small></span><input class="switch" id="revocable" type="checkbox" ${state.revocable ? "checked" : ""} ${locked() || !state.tpm.available || state.deniability ? "disabled" : ""}></label>` : needed ? `<p class="hint">${t("revocableAuto")}</p>` : ""}<div class="tpm-status hint" role="status"><span>${t(state.tpm.available ? "revocableTpmReady" : "revocableTpmUnavailable")}${state.tpm.available ? state.tpm.device ? ` · ${esc(state.tpm.device)}` : "" : ` · ${esc(errorText(state.tpm.reason))}`}</span><button class="text-button" id="refresh-tpm" ${locked() ? "disabled" : ""}>${t("refreshTpm")}</button></div>${needed ? `<p class="hint revocable-details">${t("revocableDetails")}</p><label class="field-label" for="tpm-owner-auth">${t("tpmOwnerAuth")}</label><input id="tpm-owner-auth" type="password" value="${esc(state.tpmOwnerAuth)}" autocomplete="off" spellcheck="false" ${disabled()}><p class="hint">${t("tpmOwnerAuthHint")}</p>` : ""}`;
}
async function refreshTpm() {
  if (!desktop || locked() || state.revocationReview || state.deletionReview || state.profileDialog) return;
  try {
    const status = await invoke<typeof state.tpm>("revocable_status");
    if (status && typeof status.available === "boolean") {
      const focus = captureFocus(); state.tpm = status;
      if (!status.available) state.revocable = false;
      render(); restoreFocus(focus);
    }
  } catch { state.tpm = { available: false, reason: "revocable_provider_required", device: null }; }
}
function revocationReviewMarkup() {
  const review = state.revocationReview!;
  return `<div class="modal-backdrop"><section class="modal card" role="dialog" aria-modal="true" aria-labelledby="revocation-title"><div class="section-heading"><h2 id="revocation-title">${t("revokeVolumes")}</h2><button class="icon-button" id="close-revocation-review" aria-label="${t("close")}">${icon("x")}</button></div><p class="deletion-warning">${t("revocationWarning")}</p><p class="hint">${t("revocationProofHint")}</p><div class="revocation-preview">${review.items.map((item) => `<article><strong>${esc(item.source)}</strong><p>${esc(item.identifier || "")} · ${esc(item.index || "")}</p>${item.error ? `<p class="deletion-error">${esc(errorText(item.error))}</p>` : ""}</article>`).join("")}</div><div class="modal-actions"><button class="secondary" id="cancel-revocation-review">${t("close")}</button><button class="primary danger" id="confirm-revocation" ${review.items.some((item) => !item.error) ? "" : "disabled"}>${t("confirmRevocation")}</button></div></section></div>`;
}
function revocationReportMarkup() {
  return `<section class="card revocation-report"><h2>${t("revocationReport")}</h2><p class="hint">${t("revocableCopiesHint")}</p>${state.revocationResults.map((result) => `<article><strong>${esc(result.source)}</strong><p>${esc(result.identifier || "")} · ${esc(result.index || "")}</p><p>${t(result.revoked && result.hardwareAbsenceConfirmed ? "revocationConfirmed" : "revocationNotConfirmed")}</p>${result.error ? `<p class="deletion-error">${esc(errorText(result.error))}</p>` : ""}</article>`).join("")}</section>`;
}
async function prepareRevocation() {
  if (!desktop || locked() || state.profileDialog || state.generatorOpen || state.shortcutsOpen || state.deletionReview || state.revocationReview || !state.tpm.available) return;
  if (!state.password) { state.error = "empty_password"; render(); return; }
  const origin = captureFocus(); state.busy = true; state.jobKind = "crypto"; state.jobId = crypto.randomUUID(); state.progress = null; state.error = "";
  try {
    const preview = await invoke<NonNullable<typeof state.revocationReview>>("prepare_revocation", { id: state.jobId, paths: state.files.filter((file) => file.revocable).map((file) => file.path) });
    state.shortcutsOpen = false; state.revocationReview = preview; modalReturnFocus = origin;
  } catch (error) { state.error = String(error); }
  finally { state.busy = false; state.cancelRequested = false; state.cancelSending = false; render(); }
}
function closeRevocationReview() {
  const token = state.revocationReview?.token; state.revocationReview = null;
  if (token) void invoke("discard_revocation", { token }).catch(() => {});
  render(); if (!restoreFocus(modalReturnFocus)) document.getElementById("prepare-revocation")?.focus(); modalReturnFocus = null;
}
async function runRevocation() {
  const review = state.revocationReview;
  if (!review || locked()) return;
  state.revocationReview = null; modalReturnFocus = null;
  state.busy = true; state.jobKind = "crypto"; state.jobId = crypto.randomUUID(); state.progress = null; state.error = "";
  state.cancelRequested = false; state.cancelSending = false; render();
  try {
    state.revocationResults = await invoke<typeof state.revocationResults>("run_revocation", { request: { id: state.jobId, token: review.token,
      password: state.password, keyfiles: state.keyfiles, tpmOwnerAuth: state.tpmOwnerAuth,
    } });
  } catch (error) { state.error = String(error); }
  finally { state.busy = false; state.cancelRequested = false; state.cancelSending = false; state.password = ""; state.confirmation = ""; state.generated = ""; state.tpmOwnerAuth = ""; render(); }
}

function profilesMarkup() {
  const custom = selectedProfile();
  const editable = Boolean(custom && "name" in custom);
  const storageBlocked = Boolean(state.profileStorageProblem);
  const changeDisabled = locked() || storageBlocked ? "disabled" : "";
  return `<section class="card profiles-card"><div class="section-heading"><h2>${t("usageProfiles")}</h2></div><label class="field-label" for="profile-select">${t("profileChoose")}</label><div class="profile-selection"><select id="profile-select" ${disabled()}><option value="" ${!state.profileId ? "selected" : ""}>${t("profileManual")}</option><optgroup label="${t("profileBuiltins")}">${presetProfiles.map((profile) => `<option value="${profile.id}" ${profile.id === state.profileId ? "selected" : ""}>${t(profile.label)}</option>`).join("")}</optgroup>${state.profiles.length ? `<optgroup label="${t("profilePersonal")}">${state.profiles.map((profile) => `<option value="${esc(profile.id)}" ${profile.id === state.profileId ? "selected" : ""}>${esc(profile.name)}</option>`).join("")}</optgroup>` : ""}</select><button id="profile-revert" class="secondary" ${locked() || !profileDirty() ? "disabled" : ""}>${t("profileRestore")}</button></div><div id="profile-live">${profileLiveMarkup()}</div>${custom && "description" in custom ? `<p class="hint">${t(custom.description)}</p>` : ""}<details id="profile-actions" ${state.profileActionsOpen ? "open" : ""}><summary>${t("profileManage")}</summary><div class="profile-buttons"><button class="secondary" id="profile-create" ${changeDisabled}>${t("profileCreate")}</button><button class="secondary" id="profile-save" ${locked() || storageBlocked || !editable ? "disabled" : ""}>${t("profileSave")}</button><button class="secondary" id="profile-duplicate" ${locked() || storageBlocked || !custom ? "disabled" : ""}>${t("profileDuplicate")}</button><button class="secondary" id="profile-delete" ${locked() || storageBlocked || !editable ? "disabled" : ""}>${t("profileDelete")}</button></div><div class="profile-buttons"><button class="text-button" id="profile-export" ${locked() || !custom ? "disabled" : ""}>${t("profileExport")}</button><button class="text-button" id="profile-export-all" ${locked() || !state.profiles.length ? "disabled" : ""}>${t("profileExportAll")}</button><button class="text-button" id="profile-import" ${changeDisabled}>${t("profileImport")}</button></div><input type="file" id="profile-import-file" accept=".json,application/json" hidden ${disabled()}><p class="hint">${t("profileHint")}</p></details>${state.profileStorageProblem ? `<div class="profile-storage-error" role="alert"><p>${t(state.profileStorageProblem)}</p><button class="secondary" id="profile-reload" ${disabled()}>${t("profileReload")}</button>${state.profileStorageProblem === "profile_storage_invalid" ? `<button class="secondary" id="profile-reset" ${disabled()}>${t("profileReset")}</button>` : ""}</div>` : ""}${state.profilePending ? `<p class="hint" role="status">${t("profileWorking")}</p>` : ""}</section>`;
}
function updateProfileSummary() {
  const panel = document.getElementById("profile-live");
  if (panel) panel.innerHTML = profileLiveMarkup();
  const revert = document.getElementById("profile-revert") as HTMLButtonElement | null;
  if (revert) revert.disabled = locked() || !profileDirty();
}
function profileDialogMarkup() {
  const draft = state.profileDialog!;
  const title = t(draft.kind === "create" ? "profileCreate" : draft.kind === "duplicate" ? "profileDuplicate" : draft.kind === "delete" ? "profileDelete" : "profileSave");
  if (draft.kind === "delete") return `<div class="modal-backdrop"><section class="modal card" role="dialog" aria-modal="true" aria-labelledby="profile-dialog-title"><div class="section-heading"><h2 id="profile-dialog-title">${title}</h2><button class="icon-button" id="close-profile-dialog" aria-label="${t("close")}">${icon("x")}</button></div><p>${esc(draft.name)}</p><p class="hint">${t("profileDeleteHint")}</p>${draft.error ? `<p class="profile-dialog-error" role="alert">${esc(errorText(draft.error))}</p>` : ""}<div class="modal-actions"><button class="secondary" id="cancel-profile-dialog">${t("close")}</button><button class="primary" id="confirm-profile-delete">${t("profileDelete")}</button></div></section></div>`;
  const options = [["revocable", "revocable"], ["deniability", "deniability"], ["paranoid", "paranoid"], ["reedSolomon", "reed"], ["compress", "compress"], ["chunks", "chunks"], ["recursive", "recursive"]] as const;
  return `<div class="modal-backdrop"><section class="modal card profile-editor" role="dialog" aria-modal="true" aria-labelledby="profile-dialog-title"><div class="section-heading"><h2 id="profile-dialog-title">${title}</h2><button class="icon-button" id="close-profile-dialog" aria-label="${t("close")}">${icon("x")}</button></div><form id="profile-editor-form" novalidate><label class="field-label" for="profile-name">${t("profileName")}</label><input id="profile-name" value="${esc(draft.name)}" maxlength="240" autocomplete="off"><div class="profile-editor-options">${options.map(([key, label]) => `<label class="option-row"><span><strong>${t(label)}</strong></span><input class="switch" type="checkbox" id="profile-option-${key}" data-profile-option="${key}" ${draft.settings[key] ? "checked" : ""} ${key === "chunks" && draft.settings.deniability ? "disabled" : ""}></label>`).join("")}</div>${draft.settings.chunks ? `<label class="field-label" for="profile-chunk-size">${t("chunkSize")}</label><input id="profile-chunk-size" type="number" min="1" max="1048576" step="1" value="${draft.settings.chunkSizeMiB}">` : ""}<label class="field-label" for="profile-generator-length">${t("profileGeneratorLength")}</label><input id="profile-generator-length" type="number" min="16" max="128" step="1" value="${draft.settings.generatorLength}"><label class="option-row"><strong>${t("symbols")}</strong><input class="switch" type="checkbox" id="profile-generator-symbols" ${draft.settings.generatorSymbols ? "checked" : ""}></label><label class="option-row"><strong>${t("profileRememberOutput")}</strong><input class="switch" type="checkbox" id="profile-remember-output" ${draft.rememberOutput ? "checked" : ""}></label>${draft.rememberOutput ? `<label class="field-label" for="profile-folder">${t("destination")}</label><input id="profile-folder" value="${esc(draft.folder)}" placeholder="${t("profileFolderPlaceholder")}" autocomplete="off">${desktop ? `<button class="secondary" type="button" id="profile-pick-folder">${t("chooseFolder")}</button>` : ""}` : ""}<p class="hint">${t("profileHint")}</p><div id="profile-editor-live" class="profile-costs hint">${profileCosts(draft.settings)}</div>${draft.error ? `<p class="profile-dialog-error" role="alert">${esc(errorText(draft.error))}</p>` : ""}<div class="modal-actions"><button class="secondary" type="button" id="cancel-profile-dialog">${t("close")}</button><button class="primary" type="submit" id="save-profile-dialog">${t("profileSave")}</button></div></form></section></div>`;
}

function profileFailure(error: unknown) { return error instanceof Error ? error.message : String(error); }
function openProfileDialog(kind: ProfileEditor["kind"]) {
  if (locked() || state.generatorOpen || state.shortcutsOpen || state.profileDialog || state.profileStorageProblem) return;
  const profile = selectedProfile();
  if ((kind === "save" || kind === "delete") && (!profile || !("name" in profile))) return;
  if (kind === "duplicate" && !profile) return;
  if (kind !== "save" && kind !== "delete" && state.profiles.length >= MAX_PROFILES) { state.error = "profile_limit_reached"; render(); return; }
  modalReturnFocus = captureFocus();
  const name = kind === "create" ? freeProfileName(t("profileNewName"), profileNames())
    : kind === "duplicate" ? freeProfileName(`${profileTitle(profile!)} ${t("profileCopySuffix")}`, profileNames()) : profileTitle(profile!);
  const settings = kind === "delete" ? { ...profile!.settings } : currentProfileSettings(profile?.settings.outputDirectory !== undefined);
  state.profileDialog = { kind, id: kind === "save" || kind === "delete" ? profile?.id : undefined,
    name, settings, rememberOutput: profile?.settings.outputDirectory !== undefined,
    folder: state.output || profile?.settings.outputDirectory || "", error: "",
  };
  render();
  if (kind !== "delete") { document.getElementById("profile-name")?.focus(); (document.getElementById("profile-name") as HTMLInputElement)?.select(); }
}
function closeProfileDialog() {
  state.profileDialog = null;
  render();
  if (!restoreFocus(modalReturnFocus)) document.getElementById("profile-select")?.focus();
  modalReturnFocus = null;
}
async function saveProfileDialog() {
  const draft = state.profileDialog;
  if (!draft || draft.kind === "delete" || locked() || state.profileStorageProblem) return;
  try {
    const name = profileName(draft.name);
    if (allProfiles().some((profile) => profile.id !== draft.id && nameKey(profileTitle(profile)) === nameKey(name))) throw new Error("profile_name_exists");
    const { outputDirectory: _folder, ...base } = draft.settings;
    if (!base.chunks && (!Number.isInteger(base.chunkSizeMiB) || base.chunkSizeMiB < 1 || base.chunkSizeMiB > 1048576)) base.chunkSizeMiB = 100;
    const settings = validateSettings({ ...base, ...(draft.rememberOutput ? { outputDirectory: draft.folder } : {}) });
    const profile: CustomProfile = { id: draft.id ?? crypto.randomUUID(), name, settings };
    const next = draft.id ? state.profiles.map((existing) => existing.id === draft.id ? profile : existing) : [...state.profiles, profile];
    state.profiles = saveCustomProfiles(next);
    state.profileId = profile.id;
    closeProfileDialog();
    await applyProfile(profile.id);
    state.profileNotice = `${t("profileSaved")}: ${name}`;
    updateProfileSummary();
  } catch (error) {
    if (state.profileDialog === draft) draft.error = profileFailure(error);
    else state.error = profileFailure(error);
    render();
  }
}
function deleteProfile() {
  const draft = state.profileDialog;
  if (!draft || draft.kind !== "delete" || locked() || state.profileStorageProblem) return;
  try {
    state.profiles = saveCustomProfiles(state.profiles.filter((profile) => profile.id !== draft.id));
    state.profileId = "";
    state.profileNotice = t("profileDeleted");
    closeProfileDialog();
  } catch (error) { draft.error = profileFailure(error); render(); }
}
async function applyProfile(id: string) {
  if (locked() || state.generatorOpen || state.shortcutsOpen || state.profileDialog) return;
  const profile = allProfiles().find((item) => item.id === id);
  if (!profile) { state.profileId = ""; state.profileNotice = ""; render(); return; }
  const settings = validateSettings(profile.settings);
  if (settings.revocable && !state.tpm.available) { state.error = state.tpm.reason; render(); return; }
  const recursiveChanged = state.recursive !== settings.recursive;
  const previousMode = state.mode;
  state.profilePending = true;
  state.error = "";
  render();
  try {
    let files: InputFile[] | null = null;
    if (recursiveChanged && state.paths.length) files = (await invoke<InputFile[]>("collect_files", { paths: state.paths, recursive: settings.recursive })).filter((file) => !state.excluded.has(file.path));
    state.compress = settings.compress; state.paranoid = settings.paranoid; state.reedSolomon = settings.reedSolomon;
    state.algorithm = settings.algorithm ?? "xchacha20";
    setDeniability(settings.deniability); state.chunks = settings.chunks; state.chunkSizeMiB = settings.chunkSizeMiB;
    state.revocable = settings.revocable === true;
    state.recursive = settings.recursive; state.generatorLength = settings.generatorLength; state.symbols = settings.generatorSymbols;
    if (settings.outputDirectory !== undefined) state.output = settings.outputDirectory;
    state.forceDecrypt = false;
    state.generated = "";
    if (files) state.files = files;
    state.mode = previousMode;
    inspectionRequest++;
    state.inspection = null;
    state.profileId = id;
    state.profileNotice = t("profileApplied");
    const volume = state.files.find((file) => file.volume);
    if (volume && !state.deniability) await inspect(volume, false);
  } catch (error) { state.error = profileFailure(error); }
  finally { state.profilePending = false; render(); if (state.page === "workspace" && !state.shortcutsOpen) document.getElementById("profile-select")?.focus(); }
}
function profileDocument(all: boolean) {
  const profiles = all ? state.profiles : selectedProfile() ? [selectedProfile()!] : [];
  return exportProfileDocument(profiles.map((profile) => ({ name: profileTitle(profile), settings: profile.settings })));
}
async function exportProfiles(all: boolean) {
  if (locked() || state.profileDialog) return;
  state.profilePending = true; state.error = ""; render();
  try {
    const document = profileDocument(all);
    if (desktop) {
      state.picking = true;
      let path = await save({ title: t("profileExport"), defaultPath: all ? "tasarut-profils.json" : "tasarut-profil.json", filters: [{ name: "JSON", extensions: ["json"] }] });
      if (!path) return;
      if (!path.toLowerCase().endsWith(".json")) path += ".json";
      await invoke("write_profile_document", { path, document });
    } else {
      const url = URL.createObjectURL(new Blob([document], { type: "application/json" }));
      const link = window.document.createElement("a");
      link.href = url; link.download = all ? "tasarut-profils.json" : "tasarut-profil.json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    state.profileNotice = t("profileExported");
  } catch (error) { state.error = profileFailure(error); }
  finally { state.picking = false; state.profilePending = false; render(); }
}
function commitProfileImport(document: string) {
  const profiles = parseProfileDocument(document);
  const next = mergeProfiles(state.profiles, profiles, profileNames());
  state.profiles = saveCustomProfiles(next);
  state.profileNotice = `${t("profileImported")}: ${profiles.length}`;
}
async function importProfiles() {
  if (locked() || state.profileDialog || state.profileStorageProblem) return;
  if (!desktop) { (document.getElementById("profile-import-file") as HTMLInputElement)?.click(); return; }
  state.profilePending = true; state.picking = true; state.error = ""; render();
  try {
    const path = await open({ title: t("profileImport"), directory: false, multiple: false, filters: [{ name: "JSON", extensions: ["json"] }] });
    if (typeof path !== "string") return;
    commitProfileImport(await invoke<string>("read_profile_document", { path }));
  } catch (error) { state.error = profileFailure(error); }
  finally { state.picking = false; state.profilePending = false; render(); }
}
async function importBrowserProfile(file: globalThis.File) {
  if (locked() || state.profileDialog || state.profileStorageProblem) return;
  state.profilePending = true; state.error = ""; render();
  try {
    if (file.size > MAX_PROFILE_BYTES) throw new Error("profile_document_too_large");
    commitProfileImport(await file.text());
  } catch (error) { state.error = profileFailure(error); }
  finally { state.profilePending = false; render(); }
}

function progressMarkup() {
  const cancelling = state.cancelSending || state.cancelRequested;
  return `<section class="card progress-panel"><div class="progress-live" role="status">${progressDetailsMarkup()}</div><div class="progress-actions"><button class="secondary" id="cancel-job" ${cancelling ? "disabled" : ""}>${t(cancelling ? "cancelling" : "cancelJob")}</button><p id="cancel-notice" ${cancelling ? "" : "hidden"} role="status">${t("cancellingHint")}</p></div></section>`;
}

function progressDetailsMarkup() {
  if (state.jobKind !== "crypto") return deletionProgressMarkup();
  const bytes = state.progress?.byteProgress;
  const phases: Record<ProgressPhase, TranslationKey> = {
    preparing: "progressPreparing",
    keyDerivation: "progressKeyDerivation",
    encrypting: "progressEncrypting",
    authenticating: "progressAuthenticating",
    decrypting: "progressDecrypting",
    splitting: "progressSplitting",
    reassembling: "progressReassembling",
    wrapping: "progressWrapping",
    unwrapping: "progressUnwrapping",
    recovering: "progressRecovering",
    publishing: "progressPublishing",
    complete: "progressComplete",
    failed: "progressFailed",
    cancelled: "cancelledStatus",
    keyStorage: "progressKeyStorage",
    revoking: "progressRevoking",
  };
  const total = bytes?.totalBytes;
  const processed = bytes?.processedBytes ?? 0;
  const measurable = typeof total === "number" && total > 0;
  const fraction = measurable ? Math.min(1, Math.max(0, processed / total)) : null;
  const percentage = fraction === null ? "" : `${new Intl.NumberFormat(state.language === "kab" ? "fr" : state.language, { maximumFractionDigits: 1 }).format(fraction * 100)} %`;
  const byteText = bytes && (measurable || processed > 0 || total === 0)
    ? `${size(processed)}${typeof total === "number" ? ` / ${size(total)}` : ""}`
    : t("progressIndeterminate");
  return `<div><strong>${t("processing")}</strong><span class="progress-files">${state.progress?.completed ?? 0} / ${state.progress?.total ?? state.files.length} ${t("progressFiles")}</span></div><div class="progress-phase"><strong>${t(bytes ? phases[bytes.phase] : "progressPreparing")}</strong><span class="progress-percent">${percentage}</span></div><progress aria-label="${t("progressLabel")}" max="1" ${fraction === null ? "" : `value="${fraction}"`}></progress><div class="progress-bytes">${byteText}</div><p>${esc(state.progress ? filename(state.progress.current) : t("working"))}</p><small>${t("progressHint")} ${t("working")}</small>`;
}

function updateProgressPanel() {
  const live = document.querySelector(".progress-live");
  if (live) live.innerHTML = progressDetailsMarkup();
  const cancelling = state.cancelSending || state.cancelRequested;
  const button = document.getElementById("cancel-job") as HTMLButtonElement | null;
  if (button) {
    button.disabled = cancelling;
    button.textContent = t(cancelling ? "cancelling" : "cancelJob");
  }
  const notice = document.getElementById("cancel-notice");
  if (notice) notice.hidden = !cancelling;
  decorateShortcuts();
}

function resultMarkup(result: FileResult) {
  const cancelled = result.error === "operation_cancelled";
  const skipped = result.error === "not_processed";
  const recovered = !result.error ? result.recovery : null;
  const macLabels: Record<MacStatus, TranslationKey> = {
    valid: "macValid",
    invalid: "macInvalid",
    missing: "macMissing",
    notChecked: "macNotChecked",
  };
  return `<div class="result-row ${cancelled || skipped ? "result-cancelled" : result.error ? "result-error" : recovered ? "result-recovery" : ""}">${icon(cancelled || skipped ? "x" : result.error || recovered ? "circle-alert" : "check")}<div><strong>${esc(filename(result.source))}</strong><p>${esc(result.error ? errorText(result.error) : result.output || t("success"))}</p>
    ${!result.error && result.repair && result.repair.correctedBytes > 0 ? `<p class="repair-summary">${t("reedRecovered")} ${result.repair.correctedBlocks} ${t("correctedBlocks")} · ${result.repair.correctedBytes} ${t("correctedBytes")}</p>` : ""}
    ${recovered ? `<div class="recovery-report"><strong>${t("untrustedOutput")}</strong><p>${size(recovered.recoveredBytes)} ${t("recoveredBytes")} · ${t(recovered.partial ? "partialRecovery" : "declaredLengthRecovered")}</p><p>${t(macLabels[recovered.macStatus])}</p>${recovered.limitReached ? `<p>${t("recoveryLimitReached")}</p>` : ""}${recovered.decompressionFailed ? `<p>${t("decompressionStopped")}</p>` : ""}${recovered.damage.truncated ? `<p>${t("truncatedVolume")} ${size(recovered.damage.missingBytes)}</p>` : ""}${recovered.damage.uncorrectableBlocks > 0 ? `<p>${recovered.damage.uncorrectableBlocks} ${t("uncorrectableBlocks")}</p>` : ""}${recovered.damage.descriptorDamaged || recovered.damage.noncanonicalPadding || recovered.trailingData ? `<p>${t("damagedStructure")}</p>` : ""}${recovered.damage.ranges.length ? `<details><summary>${t("damagedRanges")}</summary>${recovered.damage.ranges.map((range) => `<p>${range.offset} + ${range.length} B</p>`).join("")}${recovered.damage.rangesOmitted ? `<p>${t("rangesOmitted")}</p>` : ""}</details>` : ""}</div>` : ""}
  </div><span>${t(cancelled ? "cancelledStatus" : skipped ? "notProcessedStatus" : result.error ? "failed" : recovered ? "recoveredStatus" : "success")}</span></div>`;
}

function about() {
  return `<section class="about-page"><div class="about-key">${icon("key-round")}</div><div class="eyebrow">TASARUT / 0.4</div><h1>${t("aboutTitle")}</h1><p>${t("aboutText")}</p><section class="card about-facts"><div>${icon("shield-check")}<span>${t("algorithms")}<small>${t("kdf")}</small></span></div><div>${icon("shield")}<span>${t("paranoidAlgorithms")}<small>${t("paranoidKdf")}</small></span></div><div>${icon("layers")}<span>${t("reed")}<small>${t("reedHint")}</small></span></div><div>${icon("hard-drive")}<span>${t("memory")}<small>${t("destinationHint")}</small></span></div><div>${icon("languages")}<span>${t("languages")}<small>${t("translationNote")}</small></span></div></section><p class="hint">${t("formatNote")}</p></section>`;
}

function generatorModal() {
  return `<div class="modal-backdrop"><section class="modal card" role="dialog" aria-modal="true" aria-labelledby="generator-title"><div class="section-heading"><h2 id="generator-title">${icon("wand-sparkles")}${t("generator")}</h2><button class="icon-button" id="close-generator" aria-label="${t("close")}">${icon("x")}</button></div><p class="hint">${t("generated")}</p><label class="field-label" for="generated-password">${t("password")}</label><textarea readonly id="generated-password" class="generated-password" rows="3" spellcheck="false">${esc(state.generated)}</textarea><div class="range-label"><label for="generator-length">${t("length")}</label><strong id="length-value">${state.generatorLength}</strong></div><input id="generator-length" type="range" min="16" max="128" value="${state.generatorLength}" ${state.generatorPending ? "disabled" : ""}><label class="option-row"><strong>${t("symbols")}</strong><input class="switch" id="generator-symbols" type="checkbox" ${state.symbols ? "checked" : ""} ${state.generatorPending ? "disabled" : ""}></label><div class="modal-actions"><button class="secondary" id="generate-password" ${state.generatorPending ? "disabled" : ""}>${icon("refresh-cw")}${t("generate")}</button><button class="primary" id="use-password" ${state.generated && !state.generatorPending ? "" : "disabled"}>${t("usePassword")}${icon("arrow-right")}</button></div></section></div>`;
}

function shortcutsModal() {
  const scopeLabels = { global: "shortcutGlobal", workspace: "shortcutWorkspace", processing: "shortcutProcessing" } as const;
  return `<div class="modal-backdrop"><section class="modal card shortcuts-modal" role="dialog" aria-modal="true" aria-labelledby="shortcuts-title" aria-describedby="shortcuts-hint"><div class="section-heading"><h2 id="shortcuts-title">${icon("keyboard")}${t("keyboardShortcuts")}</h2><button class="icon-button" id="close-shortcuts" aria-label="${t("close")}" aria-keyshortcuts="Escape">${icon("x")}</button></div><p class="hint" id="shortcuts-hint">${t("shortcutsHint")}</p><table class="shortcuts-table"><thead><tr><th scope="col">${t("shortcutAction")}</th><th scope="col">${t("shortcutKeys")}</th></tr></thead><tbody>${shortcuts.map((shortcut) => `<tr><td>${t(shortcut.label)}<small>${t(scopeLabels[shortcut.scope])}</small></td><td><span class="shortcut-combination">${shortcutKeys(shortcut, t("shortcutShift"), t("shortcutEnter")).map((key) => `<kbd>${esc(key)}</kbd>`).join('<span aria-hidden="true">+</span>')}</span></td></tr>`).join("")}<tr><td>${t("shortcutCloseDialog")}<small>${t("shortcutDialog")}</small></td><td><kbd>${t("shortcutEscape")}</kbd></td></tr></tbody></table></section></div>`;
}

function decorateShortcuts() {
  document.getElementById("close-generator")?.setAttribute("aria-keyshortcuts", "Escape");
  for (const shortcut of shortcuts) {
    const element = document.querySelector<HTMLElement>(shortcut.selector);
    if (!element) continue;
    element.setAttribute("aria-keyshortcuts", ariaShortcut(shortcut));
    element.title = `${t(shortcut.label)} (${shortcutKeys(shortcut, t("shortcutShift"), t("shortcutEnter")).join(" + ")})`;
  }
}

function openShortcuts() {
  if (state.generatorOpen || state.shortcutsOpen || state.profileDialog || state.deletionReview || state.revocationReview || state.picking) return;
  modalReturnFocus = captureFocus();
  state.shortcutsOpen = true;
  render();
}

function closeShortcuts() {
  state.shortcutsOpen = false;
  render();
  if (!restoreFocus(modalReturnFocus)) document.getElementById("open-shortcuts")?.focus();
  modalReturnFocus = null;
}

function handleKeyboardShortcuts(event: KeyboardEvent) {
  if (event.defaultPrevented || event.isComposing || event.key === "Dead" || event.key === "Process" || event.altKey || event.getModifierState("AltGraph")) return;
  if (event.key === "Escape" && !event.ctrlKey && !event.metaKey && !event.shiftKey) {
    if (state.picking || event.repeat) return;
    if (state.generatorOpen || state.shortcutsOpen || state.profileDialog || state.deletionReview || state.revocationReview) {
      event.preventDefault();
      if (state.generatorOpen) closeGenerator(); else if (state.profileDialog) closeProfileDialog(); else if (state.deletionReview) closeDeletionReview(); else if (state.revocationReview) closeRevocationReview(); else closeShortcuts();
    } else if (state.error && !(event.target instanceof HTMLSelectElement)) {
      event.preventDefault();
      dismissError();
    }
    return;
  }
  const shortcut = matchShortcut(event);
  if (!shortcut) return;
  const editing = event.target instanceof HTMLElement && Boolean(event.target.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"])'));
  if (editing && !shortcut.whileTyping) return;
  event.preventDefault();
  if (event.repeat || state.picking || state.generatorOpen || state.shortcutsOpen || state.profileDialog || state.deletionReview || state.revocationReview) return;
  if (shortcut.scope === "workspace" && (state.page !== "workspace" || locked())) return;
  if (shortcut.scope === "processing") {
    if (!state.busy || state.cancelSending || state.cancelRequested) return;
    if (state.page !== "workspace") { state.page = "workspace"; render(); }
  }
  const element = document.querySelector<HTMLElement>(shortcut.selector);
  if (!element || element.matches(":disabled") || element.closest("[inert]")) return;
  if (shortcut.focus) element.focus();
  else {
    const origin = captureFocus();
    element.click();
    if (["workspace", "roadmap", "about", "encrypt", "decrypt"].includes(shortcut.id)) document.querySelector<HTMLElement>(shortcut.selector)?.focus();
    else if (shortcut.id === "start" && !state.busy && !state.picking && !state.selecting) restoreFocus(origin);
  }
}

function dismissError() {
  state.error = "";
  document.querySelector(".error-banner")?.remove();
}

function on(id: string, handler: () => void | Promise<void>) {
  document.getElementById(id)?.addEventListener("click", () => {
    void handler();
  });
}

function bindEvents() {
  document.getElementById("cipher-algorithm")?.addEventListener("change", (event) => {
    if (locked()) return;
    state.algorithm = (event.target as HTMLSelectElement).value as CipherAlgorithm;
    if (state.algorithm === "threefish1024") state.paranoid = false;
    render(); document.getElementById("cipher-algorithm")?.focus();
  });
  document.getElementById("profile-algorithm")?.addEventListener("change", (event) => {
    const draft = state.profileDialog;
    if (!draft || locked()) return;
    draft.settings.algorithm = (event.target as HTMLSelectElement).value as CipherAlgorithm;
    if (draft.settings.algorithm === "threefish1024") draft.settings.paranoid = false;
    draft.error = ""; render(); document.getElementById("profile-algorithm")?.focus();
  });
  document.getElementById("theme-select")?.addEventListener("change", (event) => {
    const value = (event.target as HTMLSelectElement).value;
    if (isTheme(value)) changeTheme(value);
  });
  document.querySelectorAll<HTMLButtonElement>(".theme-card[data-theme]").forEach((button) => button.addEventListener("click", () => {
    if (isTheme(button.dataset.theme)) changeTheme(button.dataset.theme);
  }));
  on("refresh-tpm", refreshTpm);
  on("prepare-revocation", prepareRevocation);
  on("close-revocation-review", closeRevocationReview);
  on("cancel-revocation-review", closeRevocationReview);
  on("confirm-revocation", runRevocation);
  document.getElementById("tpm-owner-auth")?.addEventListener("input", (event) => { state.tpmOwnerAuth = (event.target as HTMLInputElement).value; });
  document.getElementById("revocable")?.addEventListener("change", (event) => {
    state.revocable = state.tpm.available && (event.target as HTMLInputElement).checked;
    if (state.revocable) { setDeniability(false); state.chunks = false; state.forceDecrypt = false; }
    render(); document.getElementById("revocable")?.focus();
  });
  on("prepare-deletion", prepareDeletion);
  on("close-deletion-review", closeDeletionReview);
  on("cancel-deletion-review", closeDeletionReview);
  on("confirm-deletion", runDeletion);
  document.getElementById("deletion-trim")?.addEventListener("change", (event) => { state.deletionTrim = (event.target as HTMLInputElement).checked; });
  document.getElementById("profile-select")?.addEventListener("change", (event) => { void applyProfile((event.target as HTMLSelectElement).value); });
  on("profile-revert", () => applyProfile(state.profileId));
  on("profile-create", () => openProfileDialog("create"));
  on("profile-save", () => openProfileDialog("save"));
  on("profile-duplicate", () => openProfileDialog("duplicate"));
  on("profile-delete", () => openProfileDialog("delete"));
  on("confirm-profile-delete", deleteProfile);
  on("close-profile-dialog", closeProfileDialog);
  on("cancel-profile-dialog", closeProfileDialog);
  on("profile-export", () => exportProfiles(false));
  on("profile-export-all", () => exportProfiles(true));
  on("profile-import", importProfiles);
  document.getElementById("profile-actions")?.addEventListener("toggle", (event) => { state.profileActionsOpen = (event.target as HTMLDetailsElement).open; });
  document.getElementById("profile-import-file")?.addEventListener("change", (event) => {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (file) void importBrowserProfile(file);
  });
  on("profile-reload", () => {
    if (locked()) return;
    const loaded = loadCustomProfiles(); state.profiles = loaded.profiles; state.profileStorageProblem = loaded.error;
    if (!selectedProfile()) state.profileId = "";
    render();
  });
  on("profile-reset", () => {
    if (locked()) return;
    try { state.profiles = saveCustomProfiles([]); state.profileStorageProblem = ""; state.profileId = ""; state.profileNotice = t("profileResetDone"); }
    catch (error) { state.error = profileFailure(error); }
    render();
  });
  document.getElementById("profile-editor-form")?.addEventListener("submit", (event) => { event.preventDefault(); saveProfileDialog(); });
  document.getElementById("profile-name")?.addEventListener("input", (event) => { if (state.profileDialog) state.profileDialog.name = (event.target as HTMLInputElement).value; });
  document.querySelectorAll<HTMLInputElement>("[data-profile-option]").forEach((input) => input.addEventListener("change", () => {
    const draft = state.profileDialog;
    if (!draft) return;
    const key = input.dataset.profileOption as "compress" | "paranoid" | "reedSolomon" | "chunks" | "deniability" | "recursive" | "revocable";
    draft.settings[key] = input.checked;
    if (key === "deniability" && input.checked) draft.settings.chunks = false;
    if (key === "revocable" && input.checked) { draft.settings.chunks = false; draft.settings.deniability = false; }
    if ((key === "deniability" || key === "chunks") && input.checked) draft.settings.revocable = false;
    draft.error = "";
    render();
  }));
  document.getElementById("profile-chunk-size")?.addEventListener("input", (event) => { if (state.profileDialog) state.profileDialog.settings.chunkSizeMiB = Number((event.target as HTMLInputElement).value); });
  document.getElementById("profile-generator-length")?.addEventListener("input", (event) => { if (state.profileDialog) state.profileDialog.settings.generatorLength = Number((event.target as HTMLInputElement).value); });
  document.getElementById("profile-generator-symbols")?.addEventListener("change", (event) => { if (state.profileDialog) state.profileDialog.settings.generatorSymbols = (event.target as HTMLInputElement).checked; });
  document.getElementById("profile-remember-output")?.addEventListener("change", (event) => { if (state.profileDialog) { state.profileDialog.rememberOutput = (event.target as HTMLInputElement).checked; render(); } });
  document.getElementById("profile-folder")?.addEventListener("input", (event) => { if (state.profileDialog) state.profileDialog.folder = (event.target as HTMLInputElement).value; });
  on("profile-pick-folder", async () => {
    const draft = state.profileDialog;
    if (!draft || locked()) return;
    try {
      const folder = await pickPaths({ directory: true, multiple: false, title: t("chooseFolder") });
      if (typeof folder === "string" && state.profileDialog === draft) draft.folder = folder;
    } catch (error) { if (state.profileDialog === draft) draft.error = profileFailure(error); }
    render();
  });
  on("open-shortcuts", openShortcuts);
  on("close-shortcuts", closeShortcuts);
  on("cancel-job", cancelBatch);
  on("enable-deniability", () => {
    setDeniability(true);
    state.page = "workspace";
    render();
  });
  document.getElementById("deniability")?.addEventListener("change", async (event) => {
    setDeniability((event.target as HTMLInputElement).checked);
    const volume = state.files.find((file) => file.volume);
    if (volume && !state.deniability) await inspect(volume, false);
    render();
    document.getElementById("deniability")?.focus();
  });
  on("enable-chunks", () => {
    state.revocable = false;
    setDeniability(false);
    state.chunks = true;
    state.mode = "encrypt";
    state.forceDecrypt = false;
    state.page = "workspace";
    render();
  });
  document.getElementById("chunks")?.addEventListener("change", (event) => {
    state.chunks = (event.target as HTMLInputElement).checked;
    render();
    document.getElementById("chunks")?.focus();
  });
  document.getElementById("chunk-size")?.addEventListener("input", (event) => {
      state.chunkSizeMiB = Number((event.target as HTMLInputElement).value);
      updateProfileSummary();
  });
  on("enable-force", async () => {
    setDeniability(false);
    state.forceDecrypt = true;
    state.mode = "decrypt";
    state.page = "workspace";
    state.error = "";
    const volume = state.files.find((file) => file.volume);
    if (volume) await inspect(volume, false);
    render();
  });
  document
    .getElementById("force-decrypt")
    ?.addEventListener("change", async (event) => {
      state.forceDecrypt = (event.target as HTMLInputElement).checked;
      state.error = "";
      const volume = state.files.find((file) => file.volume);
      if (volume) await inspect(volume, false);
      render();
      document.getElementById("force-decrypt")?.focus();
    });
  document
    .getElementById("recovery-limit")
    ?.addEventListener("input", (event) => {
      state.recoveryLimitMiB = Number((event.target as HTMLInputElement).value);
    });
  on("enable-reed", () => {
    state.reedSolomon = true;
    state.mode = "encrypt";
    state.forceDecrypt = false;
    state.page = "workspace";
    render();
  });
  document
    .getElementById("reed-solomon")
    ?.addEventListener("change", (event) => {
      state.reedSolomon = (event.target as HTMLInputElement).checked;
      render();
      document.getElementById("reed-solomon")?.focus();
    });
  on("enable-paranoid", () => {
    state.algorithm = "xchacha20";
    state.paranoid = true;
    state.mode = "encrypt";
    state.forceDecrypt = false;
    state.page = "workspace";
    render();
  });
  document.getElementById("paranoid")?.addEventListener("change", (event) => {
    state.paranoid = (event.target as HTMLInputElement).checked;
    render();
    document.getElementById("paranoid")?.focus();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-page]").forEach(
    (button) =>
      (button.onclick = () => {
        state.page = button.dataset.page!;
        render();
      }),
  );
  document.querySelectorAll<HTMLButtonElement>("[data-mode]").forEach(
    (button) =>
      (button.onclick = () => {
        state.mode = button.dataset.mode!;
        if (state.mode === "encrypt") state.forceDecrypt = false;
        state.error = "";
        render();
      }),
  );
  document.getElementById("language")?.addEventListener("change", (event) => {
    state.language = (event.target as HTMLSelectElement).value as Language;
    try { localStorage.setItem("tasarut-language", state.language); } catch { state.error = "profile_storage_unavailable"; }
    render();
  });
  on("add-files", () => selectPaths(false));
  on("dropzone", () => selectPaths(false));
  on("add-folder", () => selectPaths(true));
  on("clear-files", () => {
    state.paths = [];
    state.files = [];
    state.excluded.clear();
    state.inspection = null;
    state.forceDecrypt = false;
    state.results = [];
    state.cancelled = false;
    render();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-remove]").forEach(
    (button) =>
      (button.onclick = () => {
        const [removed] = state.files.splice(Number(button.dataset.remove), 1);
        state.excluded.add(removed.path);
        state.inspection = null;
        render();
      }),
  );
  document.querySelectorAll<HTMLButtonElement>("[data-inspect]").forEach(
    (button) =>
      (button.onclick = () => {
        void inspect(state.files[Number(button.dataset.inspect)]);
      }),
  );
  on("close-inspection", () => {
    state.inspection = null;
    render();
  });
  document.getElementById("password")?.addEventListener("input", (event) => {
    state.password = (event.target as HTMLInputElement).value;
  });
  document
    .getElementById("confirmation")
    ?.addEventListener("input", (event) => {
      state.confirmation = (event.target as HTMLInputElement).value;
    });
  document.getElementById("comment")?.addEventListener("input", (event) => {
    state.comment = (event.target as HTMLTextAreaElement).value;
  });
  on("toggle-password", () => {
    state.showPassword = !state.showPassword;
    render();
    document.getElementById("password")?.focus();
  });
  on("add-keyfiles", async () => {
    if (!requireDesktop()) return;
    try {
      const paths = await pickPaths({
        multiple: true,
        directory: false,
        title: t("addKeyfiles"),
      });
      if (paths)
        state.keyfiles = [
          ...new Set([
            ...state.keyfiles,
            ...(Array.isArray(paths) ? paths : [paths]),
          ]),
        ];
    } catch (error) {
      state.error = String(error);
    }
    render();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-remove-key]").forEach(
    (button) =>
      (button.onclick = () => {
        state.keyfiles.splice(Number(button.dataset.removeKey), 1);
        render();
      }),
  );
  document.getElementById("compress")?.addEventListener("change", (event) => {
    state.compress = (event.target as HTMLInputElement).checked;
    updateProfileSummary();
  });
  document
    .getElementById("recursive")
    ?.addEventListener("change", async (event) => {
      state.recursive = (event.target as HTMLInputElement).checked;
      if (state.paths.length) await updateFiles(); else updateProfileSummary();
    });
  on("output-folder", async () => {
    if (!requireDesktop()) return;
    try {
      const folder = await pickPaths({
        directory: true,
        multiple: false,
        title: t("chooseFolder"),
      });
      if (typeof folder === "string") state.output = folder;
    } catch (error) {
      state.error = String(error);
    }
    render();
  });
  on("start", start);
  on("dismiss-error", dismissError);
  on("open-generator", async () => {
    if (locked() || state.generatorOpen || state.shortcutsOpen || state.profileDialog || state.deletionReview || state.revocationReview) return;
    modalReturnFocus = captureFocus();
    state.generatorOpen = true;
    await generate();
  });
  on("close-generator", closeGenerator);
  on("generate-password", generate);
  document
    .getElementById("generator-length")
    ?.addEventListener("input", (event) => {
      state.generatorLength = Number((event.target as HTMLInputElement).value);
      document.getElementById("length-value")!.textContent = String(
        state.generatorLength,
      );
      updateProfileSummary();
    });
  document
    .getElementById("generator-symbols")
    ?.addEventListener("change", (event) => {
      state.symbols = (event.target as HTMLInputElement).checked;
      updateProfileSummary();
    });
  on("use-password", () => {
    state.password = state.generated;
    state.confirmation = state.generated;
    state.showPassword = true;
    closeGenerator();
  });
  // Both dialogs isolate their controls and keep keyboard focus inside.
  document
    .querySelector<HTMLElement>(".modal")
    ?.addEventListener("keydown", (event) => {
      if (event.key !== "Tab") return;
      const focusable = [
        ...document.querySelectorAll<HTMLElement>(
          ".modal button:not(:disabled), .modal input:not(:disabled), .modal textarea:not(:disabled), .modal select:not(:disabled)",
        ),
      ];
      const first = focusable[0],
        last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    });
}

function setDeniability(enabled: boolean) {
  state.deniability = enabled;
  state.inspection = null;
  inspectionRequest++;
  state.error = "";
  if (enabled) {
    state.revocable = false;
    state.chunks = false;
    state.forceDecrypt = false;
  }
}

function closeGenerator() {
  generatorRequest++;
    state.generatorOpen = false;
    state.generatorPending = false;
  state.generated = "";
  render();
  if (!restoreFocus(modalReturnFocus)) document.getElementById("open-generator")?.focus();
  modalReturnFocus = null;
}
function requireDesktop() {
  if (desktop) return true;
  state.error = "desktopOnly";
  render();
  return false;
}

async function selectPaths(directory: boolean) {
  if (!requireDesktop() || locked()) return;
  try {
    const paths = await pickPaths({
      multiple: true,
      directory,
      title: t(directory ? "addFolder" : "addFiles"),
    });
    if (!paths) { render(); return; }
    if (directory) state.recursive = true;
    const oldPaths = [...state.paths];
    state.paths = [
      ...new Set([...state.paths, ...(Array.isArray(paths) ? paths : [paths])]),
    ];
    if (!(await updateFiles())) state.paths = oldPaths;
  } catch (error) {
    state.error = String(error);
    render();
  }
}

async function pickPaths(options: { directory: boolean; multiple: boolean; title: string }) {
  if (locked()) return null;
  state.picking = true;
  try { return await open(options); }
  finally { state.picking = false; }
}

async function updateFiles(): Promise<boolean> {
  state.selecting = true;
  state.error = "";
  render();
  try {
    const collected = await invoke<InputFile[]>("collect_files", {
      paths: state.paths,
      recursive: state.recursive,
    });
    const files = collected.filter((file) => !state.excluded.has(file.path));
    state.files = files;
    state.results = [];
    state.cancelled = false;
    state.inspection = null;
    if (!state.deniability && files.length && files.every((file) => file.volume))
      state.mode = "decrypt";
    const volume = files.find((file) => file.volume);
    if (volume) await inspect(volume, false);
    return true;
  } catch (error) {
    state.error = String(error);
    return false;
  } finally {
    state.selecting = false;
    render();
  }
}

async function inspect(file: InputFile, repaint = true) {
  if (state.deniability || !file.volume) return;
  const request = ++inspectionRequest;
  const force = state.mode === "decrypt" && state.forceDecrypt;
  try {
    const info = await invoke<VolumeInfo>("inspect_volume", {
        path: file.path,
        force,
      });
    if (request === inspectionRequest && !state.deniability && force === (state.mode === "decrypt" && state.forceDecrypt) && state.files.some((input) => input.path === file.path)) state.inspection = { name: filename(file.path), info };
  } catch (error) {
    if (request === inspectionRequest && !state.deniability) state.error = String(error);
  }
  if (repaint) render();
}

async function generate() {
  if (!state.generatorOpen || state.generatorPending) return;
  const request = ++generatorRequest;
  const length = state.generatorLength;
  const symbols = state.symbols;
  state.generatorPending = true;
  render();
  try {
    let generated: string;
    if (desktop)
      generated = await invoke<string>("generate_password", {
        length,
        symbols,
      });
    else {
      // Secure browser-only preview of the generator; file crypto remains native-only.
      const alphabet =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
        (symbols ? "!#$%&()*+,-./:;<=>?@[]^_{|}~" : "");
      const limit = 256 - (256 % alphabet.length);
      let password = "";
      while (password.length < length) {
        const bytes = crypto.getRandomValues(new Uint8Array(128));
        for (const byte of bytes) {
          if (byte < limit && password.length < length)
            password += alphabet[byte % alphabet.length];
        }
        bytes.fill(0);
      }
      generated = password;
    }
    if (state.generatorOpen && request === generatorRequest) state.generated = generated;
  } catch (error) {
    if (state.generatorOpen && request === generatorRequest) state.error = String(error);
  } finally {
    if (state.generatorOpen && request === generatorRequest) {
      state.generatorPending = false;
      render();
    }
  }
}

async function start() {
  if (!requireDesktop() || locked()) return;
  const invalidLimit =
    state.mode === "decrypt" &&
    state.forceDecrypt &&
    (!Number.isInteger(state.recoveryLimitMiB) ||
      state.recoveryLimitMiB < 1 ||
      state.recoveryLimitMiB > 1048576);
  const invalidChunkSize = state.mode === "encrypt" && state.chunks &&
    (!Number.isInteger(state.chunkSizeMiB) || state.chunkSizeMiB < 1 || state.chunkSizeMiB > 1048576);
  const error = invalidChunkSize
    ? "invalid_chunk_size"
    : invalidLimit
    ? "invalid_recovery_limit"
    : !state.files.length
      ? "no_files"
      : !state.password
        ? "empty_password"
        : state.mode === "encrypt" && state.password !== state.confirmation
          ? "mismatch"
          : !state.output
            ? "outputRequired"
            : "";
  if (error) {
    state.error = error;
    render();
    return;
  }
  state.busy = true;
  state.jobKind = "crypto";
  state.cancelSending = false;
  state.cancelRequested = false;
  state.cancelled = false;
  state.results = [];
  state.error = "";
  state.progress = null;
  state.jobId = crypto.randomUUID();
  render();
  try {
    state.results = await invoke<FileResult[]>("run_batch", {
      request: {
        algorithm: state.mode === "encrypt" ? state.algorithm : "xchacha20",
        id: state.jobId,
        mode: state.mode,
        paths: state.paths,
        selectedPaths: state.files.map((file) => file.path),
        outputDirectory: state.output,
        password: state.password,
        keyfiles: state.keyfiles,
        comment: state.deniability || state.revocable ? "" : state.comment,
        revocable: state.mode === "encrypt" && state.revocable,
        tpmOwnerAuth: state.tpmOwnerAuth,
        compress: state.compress,
        paranoid: state.mode === "encrypt" && state.paranoid,
        reedSolomon: state.mode === "encrypt" && state.reedSolomon,
        deniability: state.deniability,
        chunkSizeMiB: state.mode === "encrypt" && state.chunks ? state.chunkSizeMiB : null,
        forceDecrypt: state.mode === "decrypt" && state.forceDecrypt,
        recoveryLimitMiB:
          state.mode === "decrypt" && state.forceDecrypt
            ? state.recoveryLimitMiB
            : 4096,
        recursive: state.recursive,
      },
    });
    state.cancelled = state.results.some((result) => result.error === "operation_cancelled" || result.error === "not_processed");
  } catch (error) {
    if (String(error) === "operation_cancelled") state.cancelled = true;
    else state.error = String(error);
  } finally {
    state.busy = false;
    state.cancelSending = false;
    state.cancelRequested = false;
    state.password = "";
    state.confirmation = "";
    state.generated = "";
    state.showPassword = false;
    state.tpmOwnerAuth = "";
    render();
  }
}

async function cancelBatch() {
  if (!desktop || !state.busy || state.cancelSending || state.cancelRequested) return;
  const id = state.jobId;
  state.error = "";
  document.querySelector(".error-banner")?.remove();
  state.cancelSending = true;
  updateProgressPanel();
  try {
    const accepted = await invoke<boolean>("cancel_batch", { id });
    if (state.busy && state.jobId === id && accepted) state.cancelRequested = true;
  } catch (error) {
    if (state.busy && state.jobId === id) {
      state.error = String(error);
      render();
    }
  } finally {
    if (state.jobId === id) {
      state.cancelSending = false;
      updateProgressPanel();
    }
  }
}

async function initialize() {
  applyTheme(state.theme);
  render();
  document.addEventListener("keydown", handleKeyboardShortcuts);
  if (!desktop) return;
  void refreshTpm();
  try {
    await listen<Progress>("tasarut-progress", (event) => {
      if (!state.busy || event.payload.id !== state.jobId) return;
      state.progress = event.payload;
      if (event.payload.byteProgress?.phase === "cancelled") state.cancelRequested = true;
      // Update only the progress panel: streaming events must not rebuild the
      // credential fields or disturb navigation, scroll position and focus.
      updateProgressPanel();
    });
    await listen<DeletionProgress>("tasarut-deletion-progress", (event) => {
      if (!state.busy || state.jobKind === "crypto" || event.payload.id !== state.jobId) return;
      state.deletionProgress = event.payload;
      updateProgressPanel();
    });
    await getCurrentWebview().onDragDropEvent((event) => {
      if (locked() || state.generatorOpen || state.shortcutsOpen || state.profileDialog || state.deletionReview || state.revocationReview) return;
      if (event.payload.type === "enter" || event.payload.type === "over")
        document.getElementById("dropzone")?.classList.add("dragover");
      else document.getElementById("dropzone")?.classList.remove("dragover");
      if (event.payload.type === "drop") {
        const oldPaths = [...state.paths];
        state.paths = [...new Set([...state.paths, ...event.payload.paths])];
        void updateFiles().then((success) => {
          if (!success) state.paths = oldPaths;
        });
      }
    });
  } catch (error) {
    state.error = String(error);
    render();
  }
}
void initialize();
