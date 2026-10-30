import { worker } from "./mocks/browser";

async function start(): Promise<void> {
    await worker.start({ onUnhandledRequest: "error", serviceWorker: { url: "/mockServiceWorker.js" } });
    await import("../src/main");
}

void start();
