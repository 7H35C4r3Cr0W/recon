import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies the API + WebSocket to the FastAPI container so the SPA is same-origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
});
