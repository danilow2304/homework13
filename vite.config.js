import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Proxy keeps browser and API on the same origin so the httpOnly cookie works
export default defineConfig({ plugins: [react()], server: { proxy: { '/api': 'http://localhost:5000' } } });
