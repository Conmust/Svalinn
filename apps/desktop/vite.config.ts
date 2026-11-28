import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: ["es2021", "chrome100", "safari13"],
    minify: "esbuild",
    sourcemap: false,
  },
  // Under vitest, Node's package-export resolution picks svelte's "default"
  // (SSR) build instead of its "browser" build unless we ask for the
  // browser condition explicitly -- without this, a component's own
  // `import { onMount } from 'svelte'` silently resolves to the SSR no-op
  // stub, even though the component itself still mounts and renders real
  // DOM via @sveltejs/vite-plugin-svelte's client-mode codegen. Scoped to
  // `process.env.VITEST` so the actual Tauri app build is untouched.
  resolve: process.env.VITEST ? { conditions: ["browser"] } : undefined,
});