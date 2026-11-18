/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Toned-down professional dark blue (desaturated, less "neon")
        navy: {
          950: '#0b0d14',
          900: '#0f1320',
          800: '#161b2b',
          700: '#1f2637',
          600: '#2c3547',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
