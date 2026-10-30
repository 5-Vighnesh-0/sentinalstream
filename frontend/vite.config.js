import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const headers = { "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" }; // no CSP in dev: hot reload needs inline scripts

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The backend only accepts the dashboard from these origins (CORS, WebSocket Origin check).
  server: { port: 3000, strictPort: true, host: "localhost", headers },
  preview: { port: 3000, strictPort: true, host: "localhost", headers },
  test: { environment: "jsdom", globals: true }, // globals: Testing Library cleans up between tests
});
