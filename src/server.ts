import "dotenv/config";

import { createServer } from "node:http";

import { HttpAuthsignalClient } from "./auth/authsignal-client.js";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { buildLogger } from "./logger.js";
import { createFlowStore } from "./store/index.js";

const config = loadConfig();
const logger = buildLogger(config);
const flowStore = createFlowStore(config, logger);
const authsignalClient = new HttpAuthsignalClient(config.authsignal, logger);
const app = createApp({
  config,
  logger,
  store: flowStore,
  authsignal: authsignalClient
});

const server = createServer(app);

server.listen(config.port, () => {
  logger.info({ port: config.port }, "Asgardeo/Authsignal adapter listening");
});

async function shutdown(signal: string): Promise<void> {
  logger.info({ signal }, "Shutting down");

  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  await flowStore.close();
  logger.info("Shutdown complete");
  process.exit(0);
}

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    shutdown(signal).catch((error) => {
      logger.error({ err: error }, "Shutdown failed");
      process.exit(1);
    });
  });
}
