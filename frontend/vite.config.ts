import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/auth': 'http://localhost:8000',
      '/envelopes': 'http://localhost:8000',
      '/search': 'http://localhost:8000',
      '/access-request': 'http://localhost:8000',
      '/ml-jobs': 'http://localhost:8000',
      '/audit': 'http://localhost:8000',
      '/anomalies': 'http://localhost:8000',
      '/policies': 'http://localhost:8000',
      '/keys': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/metrics': 'http://localhost:8000',
    },
  },
})
