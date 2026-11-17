/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0e17',
          panel: '#111827',
          border: '#1f293d',
          accent: '#06b6d4',
          alert: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          text: '#e2e8f0',
          muted: '#94a3b8'
        }
      }
    },
  },
  plugins: [],
}
