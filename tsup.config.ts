import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'index.ts',
    'config/index.ts',
    'client/init.ts',
    'server/CsrfService.ts',
  ],
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  external: ['elysia', '@fluxstack/plugin-sdk'],
})
