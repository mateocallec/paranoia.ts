import { defineConfig } from 'tsup';
import { resolve } from 'path';

export default defineConfig({
  entry: ['src/index.ts'],
  outDir: 'dist',
  format: ['cjs'],
  platform: 'node',
  target: 'node18',
  bundle: true,
  sourcemap: true,
  clean: true,
  banner: { js: '#!/usr/bin/env node' },
  noExternal: [/^(?!node:).*/],
  esbuildOptions(opts) {
    opts.alias = {
      'paranoia-ts': resolve(__dirname, '../core/src/index.ts'),
    };
  },
});
