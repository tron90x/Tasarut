import type { TranslationKey } from "./i18n";

export const PROFILE_STORAGE_KEY = "tasarut-profiles-v1";
export const MAX_PROFILES = 100;
export const MAX_PROFILE_BYTES = 1024 * 1024;
export type CipherAlgorithm = "xchacha20" | "threefish1024";

export interface ProfileSettings {
  algorithm?: CipherAlgorithm;
  compress: boolean;
  paranoid: boolean;
  reedSolomon: boolean;
  chunks: boolean;
  chunkSizeMiB: number;
  deniability: boolean;
  revocable?: boolean;
  recursive: boolean;
  generatorLength: number;
  generatorSymbols: boolean;
  outputDirectory?: string;
}
export interface CustomProfile {
  id: string;
  name: string;
  settings: ProfileSettings;
}
export interface PresetProfile {
  id: string;
  label: TranslationKey;
  description: TranslationKey;
  settings: ProfileSettings;
}
export type UsageProfile = CustomProfile | PresetProfile;
export interface PortableProfile { name: string; settings: ProfileSettings }

const defaults: ProfileSettings = {
  algorithm: "xchacha20",
  compress: false, paranoid: false, reedSolomon: false, chunks: false,
  chunkSizeMiB: 100, deniability: false, recursive: false,
  revocable: false,
  generatorLength: 32, generatorSymbols: true,
};
export const presetProfiles: readonly PresetProfile[] = [
  { id: "preset-simple", label: "profileSimple", description: "profileSimpleHint", settings: { ...defaults } },
  { id: "preset-backup", label: "profileBackup", description: "profileBackupHint", settings: { ...defaults, compress: true, reedSolomon: true, recursive: true } },
  { id: "preset-transfer", label: "profileTransfer", description: "profileTransferHint", settings: { ...defaults, chunks: true } },
  { id: "preset-strong", label: "profileStrong", description: "profileStrongHint", settings: { ...defaults, paranoid: true, generatorLength: 64 } },
  { id: "preset-opaque", label: "profileOpaque", description: "profileOpaqueHint", settings: { ...defaults, deniability: true, generatorLength: 64 } },
];

function fail(key: TranslationKey): never { throw new Error(key); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fail("invalid_profile_document");
  return value as Record<string, unknown>;
}
function onlyKeys(value: Record<string, unknown>, keys: readonly string[]) {
  if (Object.keys(value).some((key) => !keys.includes(key))) fail("invalid_profile_document");
}
function boolean(value: unknown): boolean {
  if (typeof value !== "boolean") return fail("invalid_profile_document");
  return value;
}
function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) return fail("invalid_profile_document");
  return value;
}
const controlCharacters = /[\u0000-\u001f\u007f]/;
function wellFormed(value: string): boolean {
  return [...value].every((character) => {
    const code = character.codePointAt(0)!;
    return code < 0xd800 || code > 0xdfff;
  });
}
export function profileName(value: unknown): string {
  if (typeof value !== "string") return fail("profile_invalid_name");
  const name = value.trim().normalize("NFC");
  if (!name || [...name].length > 120 || controlCharacters.test(name) || !wellFormed(name)) return fail("profile_invalid_name");
  return name;
}
export function nameKey(value: string): string { return value.normalize("NFC").trim().toLowerCase(); }

export function validateSettings(value: unknown): ProfileSettings {
  const settings = record(value);
  onlyKeys(settings, [...Object.keys(defaults), "outputDirectory"]);
  const parsed: ProfileSettings = {
    algorithm: settings.algorithm === undefined && !Object.hasOwn(settings, "algorithm") ? "xchacha20"
      : settings.algorithm === "xchacha20" || settings.algorithm === "threefish1024" ? settings.algorithm : fail("invalid_profile_document"),
    compress: boolean(settings.compress), paranoid: boolean(settings.paranoid),
    reedSolomon: boolean(settings.reedSolomon), chunks: boolean(settings.chunks),
    chunkSizeMiB: integer(settings.chunkSizeMiB, 1, 1048576),
    deniability: boolean(settings.deniability), recursive: boolean(settings.recursive),
    revocable: Object.hasOwn(settings, "revocable") ? boolean(settings.revocable) : false,
    generatorLength: integer(settings.generatorLength, 16, 128),
    generatorSymbols: boolean(settings.generatorSymbols),
  };
  if (parsed.deniability && parsed.chunks) fail("profile_incompatible_options");
  if (parsed.algorithm === "threefish1024" && parsed.paranoid) fail("cipher_incompatible_options");
  if (parsed.revocable && (parsed.deniability || parsed.chunks)) fail("revocable_incompatible_options");
  if (Object.hasOwn(settings, "outputDirectory")) {
    const path = settings.outputDirectory;
    if (typeof path !== "string" || !path.trim() || new TextEncoder().encode(path).length > 4096 || controlCharacters.test(path) || !wellFormed(path)
      || !(path.startsWith("/") || /^[a-z]:[\\/]/i.test(path) || path.startsWith("\\\\"))) fail("profile_invalid_folder");
    parsed.outputDirectory = path as string;
  }
  return parsed;
}

function parseDocument(text: string, format: string): Record<string, unknown> {
  if (new TextEncoder().encode(text).length > MAX_PROFILE_BYTES) return fail("profile_document_too_large");
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { return fail("invalid_profile_document"); }
  const document = record(raw);
  if (document.format !== format) fail("invalid_profile_document");
  if (document.version !== 1) fail("profile_version_unsupported");
  onlyKeys(document, ["format", "version", "profiles"]);
  if (!Array.isArray(document.profiles)) fail("invalid_profile_document");
  if ((document.profiles as unknown[]).length > MAX_PROFILES) fail("profile_limit_reached");
  return document;
}

export function parseProfileDocument(text: string): PortableProfile[] {
  const document = parseDocument(text, "tasarut-profiles");
  const profiles = document.profiles as unknown[];
  if (!profiles.length) return fail("invalid_profile_document");
  return profiles.map((value) => {
    const profile = record(value);
    onlyKeys(profile, ["name", "settings"]);
    return { name: profileName(profile.name), settings: validateSettings(profile.settings) };
  });
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function validateCustomProfiles(profiles: readonly CustomProfile[]): CustomProfile[] {
  if (profiles.length > MAX_PROFILES) fail("profile_limit_reached");
  const ids = new Set<string>();
  const names = new Set<string>();
  return profiles.map((value) => {
    const profile = record(value);
    onlyKeys(profile, ["id", "name", "settings"]);
    if (typeof profile.id !== "string" || !uuid.test(profile.id)) fail("invalid_profile_document");
    const id = (profile.id as string).toLowerCase();
    const name = profileName(profile.name);
    if (ids.has(id) || names.has(nameKey(name))) fail("invalid_profile_document");
    ids.add(id); names.add(nameKey(name));
    return { id, name, settings: validateSettings(profile.settings) };
  });
}

export function loadCustomProfiles(): { profiles: CustomProfile[]; error: TranslationKey | "" } {
  let text: string | null;
  try { text = localStorage.getItem(PROFILE_STORAGE_KEY); }
  catch { return { profiles: [], error: "profile_storage_unavailable" }; }
  if (text === null) return { profiles: [], error: "" };
  try {
    const document = parseDocument(text, "tasarut-profile-store");
    return { profiles: validateCustomProfiles(document.profiles as CustomProfile[]), error: "" };
  } catch { return { profiles: [], error: "profile_storage_invalid" }; }
}

export function saveCustomProfiles(profiles: readonly CustomProfile[]): CustomProfile[] {
  const validated = validateCustomProfiles(profiles);
  const document = JSON.stringify({ format: "tasarut-profile-store", version: 1, profiles: validated });
  if (new TextEncoder().encode(document).length > MAX_PROFILE_BYTES) fail("profile_document_too_large");
  try { localStorage.setItem(PROFILE_STORAGE_KEY, document); }
  catch { fail("profile_storage_unavailable"); }
  return validated;
}

export function exportProfileDocument(profiles: readonly PortableProfile[]): string {
  const document = JSON.stringify({ format: "tasarut-profiles", version: 1,
    profiles: profiles.map((profile) => ({ name: profileName(profile.name), settings: validateSettings(profile.settings) })),
  }, null, 2);
  // The exporter uses the same strict schema as the importer, including limits.
  parseProfileDocument(document);
  return document;
}

export function freeProfileName(base: string, occupied: readonly string[]): string {
  const names = new Set(occupied.map(nameKey));
  const name = profileName(base);
  if (!names.has(nameKey(name))) return name;
  for (let number = 2; ; number++) {
    const suffix = ` (${number})`;
    const candidate = [...name].slice(0, 120 - suffix.length).join("") + suffix;
    if (!names.has(nameKey(candidate))) return candidate;
  }
}

export function mergeProfiles(existing: readonly CustomProfile[], imported: readonly PortableProfile[], occupied: readonly string[]): CustomProfile[] {
  if (existing.length + imported.length > MAX_PROFILES) fail("profile_limit_reached");
  const names = [...occupied, ...existing.map((profile) => profile.name)];
  const added = imported.map((profile) => {
    const name = freeProfileName(profile.name, names);
    names.push(name);
    return { id: crypto.randomUUID(), name, settings: validateSettings(profile.settings) };
  });
  return [...existing, ...added];
}

export function sameSettings(left: ProfileSettings, right: ProfileSettings): boolean {
  return Object.keys(defaults).every((key) => left[key as keyof ProfileSettings] === right[key as keyof ProfileSettings])
    && left.outputDirectory === right.outputDirectory;
}
