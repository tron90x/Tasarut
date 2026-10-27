import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";

const localChrome = process.env.CHROME_PATH || "/usr/bin/google-chrome";
export default defineConfig({
  testDir: "./tests",
  workers: 1,
  timeout: 60000,
  use: {
    baseURL: "http://127.0.0.1:1437",
    viewport: { width: 1200, height: 1000 },
    launchOptions: existsSync(localChrome)
      ? { executablePath: localChrome }
      : {},
  },
  webServer: {
    command: "npm run dev -- --port 1437",
    url: "http://127.0.0.1:1437",
    reuseExistingServer: false,
  },
});
