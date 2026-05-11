import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'Paranoia',
      fileName: 'paranoia',
      formats: ['es', 'umd'],
    },
    rollupOptions: {
      // hash-wasm ships its own WASM; keep it external so consumers can configure loading
      external: [],
    },
    target: 'es2022',
    sourcemap: true,
    minify: 'esbuild',
  },
  worker: {
    format: 'es',
  },
  plugins: [
    dts({
      include: ['src'],
      rollupTypes: true,
    }),
  ],
  optimizeDeps: {
    exclude: ['hash-wasm'],
  },
});
