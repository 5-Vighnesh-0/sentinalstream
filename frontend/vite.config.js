import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The backend only accepts the dashboard from these origins (CORS, WebSocket Origin check).
  server: { port: 3000, strictPort: true, host: "localhost" },
  preview: { port: 3000, strictPort: true, host: "localhost" },
  test: { environment: "jsdom", globals: true }, // globals: Testing Library cleans up between tests
});
