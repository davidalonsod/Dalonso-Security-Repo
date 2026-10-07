import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  base: "./",
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      includeAssets: ["icon.svg"],
      manifest: {
        name: "Agentic Security Provenance Graph",
        short_name: "Agent Provenance",
        description:
          "Local-first provenance, identity, telemetry, and evidence explorer for AI agents.",
        theme_color: "#07111f",
        background_color: "#07111f",
        display: "standalone",
        start_url: "./",
        scope: "./",
        icons: [
          {
            src: "icon.svg",
            sizes: "any",
            type: "image/svg+xml",
            purpose: "any maskable"
          }
        ]
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,svg,json}"],
        cleanupOutdatedCaches: true
      }
    })
  ]
});
