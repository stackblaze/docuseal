module.exports = {
  plugins: [
    require('daisyui')
  ],
  daisyui: {
    themes: [
      {
        docuseal: {
          'color-scheme': 'light',
          /* OpenBooks-aligned palette */
          primary: '#2ca01c',
          'primary-content': '#ffffff',
          secondary: '#f1f8ee',
          'secondary-content': '#17540f',
          accent: '#248716',
          'accent-content': '#ffffff',
          neutral: '#14532d',
          'neutral-content': '#ffffff',
          'base-100': '#ffffff',
          'base-200': '#f8faf8',
          'base-300': '#ebebeb',
          'base-content': '#252525',
          info: '#175cd3',
          success: '#2ca01c',
          warning: '#b54708',
          error: '#d92d20',
          '--rounded-btn': '0.625rem',
          '--rounded-box': '0.875rem',
          '--tab-border': '2px',
          '--tab-radius': '.5rem'
        }
      }
    ]
  }
}
