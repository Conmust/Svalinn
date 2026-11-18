/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        'obsidian': '#0B0C10',
        'frost-blue': '#66FCF1',
        'tungsten': '#C5C6C7',
      },
    },
  },
  plugins: [],
};