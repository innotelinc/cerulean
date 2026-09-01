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
      BIND_SSH_HOST: "192.0.2.1",
      BIND_SSH_USER: "root",
      BIND_SSH_PASSWORD: "test-pw",
      BIND_TSIG_NAME: "cerulean.",
      BIND_TSIG_SECRET: "dGVzdC1zZWNyZXQ=",
      ACMEDNS_API_URL: "http://localhost:4443",
      NPM_API_URL: "http://npm.test:81",
      NPM_EMAIL: "admin@innotel.us",
      NPM_PASSWORD: "npm-test-pw",
      CERULEAN_DATA_DIR: "/tmp/cerulean-test-data",
    },
  },
});
