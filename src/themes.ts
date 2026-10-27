import type { TranslationKey } from "./i18n";

export const themes = [
  { id: "default", name: "themeDefault", description: "themeDefaultDescription" },
  { id: "desert", name: "themeDesert", description: "themeDesertDescription" },
  { id: "kabylie", name: "themeKabylie", description: "themeKabylieDescription" },
  { id: "ocean", name: "themeOcean", description: "themeOceanDescription" },
  { id: "space", name: "themeSpace", description: "themeSpaceDescription" },
  { id: "arctic", name: "themeArctic", description: "themeArcticDescription" },
] as const satisfies readonly { id: string; name: TranslationKey; description: TranslationKey }[];

export type ThemeId = typeof themes[number]["id"];
const storageKey = "tasarut-theme-v1";

export function isTheme(value: unknown): value is ThemeId {
  return typeof value === "string" && themes.some((theme) => theme.id === value);
}

export function loadTheme(): ThemeId {
  try {
    const value = localStorage.getItem(storageKey);
    return isTheme(value) ? value : "default";
  } catch { return "default"; }
}

export function saveTheme(theme: ThemeId): boolean {
  try { localStorage.setItem(storageKey, theme); return true; }
  catch { return false; }
}

export function applyTheme(theme: ThemeId) {
  document.documentElement.dataset.theme = theme;
  const color = getComputedStyle(document.documentElement).getPropertyValue("--base").trim();
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", color);
}
