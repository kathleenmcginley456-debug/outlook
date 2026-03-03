module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      fontFamily: {
        'google-sans': ['Google Sans', 'sans-serif'],
      },
      colors: {
        'google-blue': '#1a73e8',
      },
    },
  },
  plugins: [],
}