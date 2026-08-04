import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    // Signal, not coverage-chasing. These tests exist to pin the behaviours the
    // dashboard used to get wrong: swallowed errors, a hardcoded LIVE badge,
    // and empty states that could not tell "no data" from "no backend".
    include: ['src/**/*.test.{js,jsx}'],
  },
})
