import type { TranslationKey } from "./i18n";

export interface Shortcut {
  id: string;
  key: string;
  code?: string;
  primary?: boolean;
  shift?: boolean;
  selector: string;
  label: TranslationKey;
  scope: "global" | "workspace" | "processing";
  whileTyping?: boolean;
  focus?: boolean;
}

// One registry drives dispatch, the help dialog and accessible button hints.
// Digit codes also support the unshifted number row on French AZERTY keyboards.
export const shortcuts: readonly Shortcut[] = [
  { id: "help", key: "F1", selector: "#open-shortcuts", label: "keyboardShortcuts", scope: "global", whileTyping: true },
  { id: "workspace", key: "1", code: "Digit1", primary: true, selector: '[data-page="workspace"]', label: "workspace", scope: "global" },
  { id: "roadmap", key: "2", code: "Digit2", primary: true, selector: '[data-page="roadmap"]', label: "roadmap", scope: "global" },
  { id: "about", key: "3", code: "Digit3", primary: true, selector: '[data-page="about"]', label: "about", scope: "global" },
  { id: "files", key: "O", primary: true, selector: "#add-files", label: "addFiles", scope: "workspace", whileTyping: true },
  { id: "folder", key: "O", primary: true, shift: true, selector: "#add-folder", label: "addFolder", scope: "workspace", whileTyping: true },
  { id: "keyfiles", key: "K", primary: true, shift: true, selector: "#add-keyfiles", label: "addKeyfiles", scope: "workspace", whileTyping: true },
  { id: "output", key: "S", primary: true, shift: true, selector: "#output-folder", label: "destination", scope: "workspace", whileTyping: true },
  { id: "generator", key: "G", primary: true, shift: true, selector: "#open-generator", label: "generator", scope: "workspace", whileTyping: true },
  { id: "password", key: "K", primary: true, selector: "#password", label: "shortcutFocusPassword", scope: "workspace", whileTyping: true, focus: true },
  { id: "encrypt", key: "E", primary: true, selector: '[data-mode="encrypt"]', label: "encrypt", scope: "workspace" },
  { id: "decrypt", key: "D", primary: true, selector: '[data-mode="decrypt"]', label: "decrypt", scope: "workspace" },
  { id: "start", key: "Enter", primary: true, selector: "#start", label: "shortcutStart", scope: "workspace", whileTyping: true },
  { id: "cancel", key: ".", primary: true, selector: "#cancel-job", label: "cancelJob", scope: "processing", whileTyping: true },
];

export const macKeyboard = /Mac|iPhone|iPad/.test(navigator.platform);

export function matchShortcut(event: KeyboardEvent): Shortcut | undefined {
  if (event.altKey || event.getModifierState("AltGraph") || (event.ctrlKey && event.metaKey)) return;
  return shortcuts.find((shortcut) =>
    Boolean(shortcut.primary) === (event.ctrlKey || event.metaKey) &&
    (Boolean(shortcut.shift) === event.shiftKey || (event.key === shortcut.key && (shortcut.key === "." || Boolean(shortcut.code)))) &&
    (event.key.toLowerCase() === shortcut.key.toLowerCase() || Boolean(shortcut.code && event.code === shortcut.code)),
  );
}

export function shortcutKeys(shortcut: Shortcut, shift: string, enter: string): string[] {
  return [
    ...(shortcut.primary ? [macKeyboard ? "Cmd" : "Ctrl"] : []),
    ...(shortcut.shift ? [shift] : []),
    shortcut.key === "Enter" ? enter : shortcut.key,
  ];
}

export function ariaShortcut(shortcut: Shortcut): string {
  return [...(shortcut.primary ? [macKeyboard ? "Meta" : "Control"] : []), ...(shortcut.shift ? ["Shift"] : []), shortcut.key].join("+");
}
