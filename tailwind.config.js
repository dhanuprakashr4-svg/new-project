/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Cyber blue primary ramp
        cyber: {
          50: '#e6f6ff',
          100: '#bae7ff',
          200: '#91d5ff',
          300: '#69c0ff',
          400: '#40a9ff',
          500: '#1890ff',
          600: '#096dd9',
          700: '#0050b3',
          800: '#003a8c',
          900: '#002766',
          950: '#001940',
        },
        // Threat red ramp
        threat: {
          50: '#fff1f0',
          100: '#ffccc7',
          200: '#ffa39e',
          300: '#ff7875',
          400: '#ff4d4f',
          500: '#f5222d',
          600: '#cf1322',
          700: '#a8071a',
          800: '#820014',
          900: '#5c0011',
        },
        // Success green
        secure: {
          50: '#f6ffed',
          100: '#b7eb8f',
          200: '#95de64',
          300: '#73d13d',
          400: '#52c41a',
          500: '#389e0d',
          600: '#237804',
          700: '#135200',
          800: '#092b00',
          900: '#000000',
        },
        // Warning amber
        alert: {
          50: '#fffbe6',
          100: '#fff1b8',
          200: '#ffe58f',
          300: '#ffd666',
          400: '#ffc53d',
          500: '#faad14',
          600: '#d48806',
          700: '#ad6800',
        },
        // Neutral slate for SOC dark theme
        soc: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          850: '#172033',
          900: '#0f172a',
          950: '#080d1a',
          980: '#050a15',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
      backgroundImage: {
        'cyber-grid':
          "linear-gradient(rgba(24,144,255,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(24,144,255,0.06) 1px, transparent 1px)",
        'radial-cyber':
          'radial-gradient(ellipse at top, rgba(24,144,255,0.12), transparent 60%)',
      },
      boxShadow: {
        glow: '0 0 20px rgba(24,144,255,0.35)',
        'glow-threat': '0 0 20px rgba(245,34,45,0.35)',
        'glow-secure': '0 0 20px rgba(82,196,26,0.3)',
        glass: '0 8px 32px rgba(0,0,0,0.45)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'scan-line': 'scanLine 2.5s ease-in-out infinite',
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
        'data-flow': 'dataFlow 1.5s linear infinite',
      },
      keyframes: {
        scanLine: {
          '0%, 100%': { transform: 'translateY(-100%)', opacity: '0' },
          '50%': { transform: 'translateY(100%)', opacity: '0.8' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        slideUp: {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(24,144,255,0.3)' },
          '50%': { boxShadow: '0 0 24px rgba(24,144,255,0.6)' },
        },
        dataFlow: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
    },
  },
  plugins: [],
};
