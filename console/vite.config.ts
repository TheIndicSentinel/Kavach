import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Never inline a font as a data: URL: kavach-api's Content-Security-Policy
    // (crates/kavach-api/src/console.rs) has no font-src, so default-src
    // 'self' applies and the browser refuses data: fonts. Other small assets
    // keep Vite's default.
    assetsInlineLimit: (file) => (/\.(woff2?|ttf|otf|eot)$/.test(file) ? false : undefined),
  },
  server: {
    proxy: {
      "/health": "http://localhost:8080",
      "/metrics": "http://localhost:8080",
      "/v1": "http://localhost:8080",
    },
  },
});
