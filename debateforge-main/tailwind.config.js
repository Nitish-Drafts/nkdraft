/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./public/index.html"],
  theme: {
    extend: {
      colors: {
        'soft-blue': '#A7C7E7',
        'mint-green': '#B2D8B2',
        'warm-gray': '#E8E8E8',
        'pastel-purple': '#D7BDE2',
        'soft-yellow': '#FAD7A0',
        'calm-red': '#F4A8A8',
      },
      boxShadow: {
        'soft': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
      },
      transitionProperty: {
        'smooth': 'all 0.3s ease-in-out',
      },
    },
  },
  plugins: [],
}