/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0B0F14',
        surface: '#121922',
        surface2: '#182230',
        border: '#243244',
        ink: '#E6EDF3',
        muted: '#8A97A6',
        brand: '#4C9EEB',
        safe: '#3DDC97',
        warn: '#FFB454',
        danger: '#FF5D5D',
      },
      fontFamily: {
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
