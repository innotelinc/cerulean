import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    server: {
      deps: {
        external: ["node:sqlite"],
      },
    },
    env: {
      CERULEAN_ADMIN_PASSWORD: "test-password",
      CERULEAN_SERVER_ID: "srv-test1234",
      CERULEAN_LAB_DOMAIN: "lab.innotel.us",
      TECHNITIUM_URL: "http://technitium.test:5380",
      TECHNITIUM_TOKEN: "test-token",
      NPM_API_URL: "http://npm.test:81",
      NPM_EMAIL: "admin@innotel.us",
      NPM_PASSWORD: "npm-test-pw",
      CERULEAN_DATA_DIR: "/tmp/cerulean-test-data",
    },
  },
});
