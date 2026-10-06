import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The built assets are served by FastAPI from FRW_STATIC_DIR. During
// development the API is reached through a proxy so cookies stay first-party
// and CSRF behaves exactly as it does in production.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },
})