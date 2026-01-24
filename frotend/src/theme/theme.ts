import { createTheme, alpha } from '@mui/material/styles'

// Modern Cisco-inspired color palette
const palette = {
  // Brand colors
  ciscoBlue: '#049fd9',
  ciscoGreen: '#6cc04a',

  // Extended blues
  blue: {
    50: '#e3f2fd',
    100: '#b3e5fc',
    200: '#81d4fa',
    300: '#5cc7f0',
    400: '#29b6f6',
    500: '#049fd9',
    600: '#0288d1',
    700: '#0273a8',
    800: '#01579b',
    900: '#014377',
  },

  // Neutrals
  gray: {
    50: '#f8f9fa',
    100: '#f1f3f4',
    200: '#e9ecef',
    300: '#dee2e6',
    400: '#ced4da',
    500: '#adb5bd',
    600: '#6c757d',
    700: '#495057',
    800: '#343a40',
    900: '#1a1a1a',
  },
}

export const lightTheme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: palette.ciscoBlue,
      light: palette.blue[300],
      dark: palette.blue[700],
      contrastText: '#ffffff',
    },
    secondary: {
      main: palette.ciscoGreen,
      light: '#9cd97b',
      dark: '#4a9031',
      contrastText: '#ffffff',
    },
    error: {
      main: '#dc3545',
      light: '#f8d7da',
      dark: '#c62828',
    },
    warning: {
      main: '#ff9800',
      light: '#fff3e0',
      dark: '#e65100',
    },
    info: {
      main: '#0288d1',
      light: '#e1f5fe',
      dark: '#01579b',
    },
    success: {
      main: '#28a745',
      light: '#d4edda',
      dark: '#1e7e34',
    },
    background: {
      default: palette.gray[50],
      paper: '#ffffff',
    },
    text: {
      primary: palette.gray[900],
      secondary: palette.gray[600],
      disabled: palette.gray[500],
    },
    divider: palette.gray[200],
  },

  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: { fontSize: '2.5rem', fontWeight: 600, letterSpacing: '-0.5px' },
    h2: { fontSize: '2rem', fontWeight: 600, letterSpacing: '-0.25px' },
    h3: { fontSize: '1.75rem', fontWeight: 600 },
    h4: { fontSize: '1.5rem', fontWeight: 600 },
    h5: { fontSize: '1.25rem', fontWeight: 600 },
    h6: { fontSize: '1rem', fontWeight: 600 },
    body1: { fontSize: '0.95rem', lineHeight: 1.6 },
    body2: { fontSize: '0.875rem', lineHeight: 1.5 },
    caption: { fontSize: '0.75rem', fontWeight: 500, letterSpacing: '0.4px' },
    button: { fontWeight: 600 },
  },

  shape: {
    borderRadius: 8,
  },

  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          background: `linear-gradient(135deg, ${palette.gray[50]} 0%, #f0f4f8 100%)`,
          minHeight: '100vh',
        },
      },
    },

    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 8,
          fontWeight: 600,
          padding: '8px 16px',
          transition: 'all 0.2s ease',
        },
        contained: {
          boxShadow: `0 2px 8px ${alpha(palette.ciscoBlue, 0.25)}`,
          '&:hover': {
            boxShadow: `0 4px 12px ${alpha(palette.ciscoBlue, 0.35)}`,
          },
        },
        outlined: {
          borderWidth: '1.5px',
          '&:hover': {
            borderWidth: '1.5px',
            backgroundColor: alpha(palette.ciscoBlue, 0.04),
          },
        },
      },
    },

    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 16,
          backgroundColor: '#ffffff',
          border: `1px solid ${palette.gray[200]}`,
          boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
          transition: 'all 0.2s ease',
          '&:hover': {
            boxShadow: `0 8px 24px ${alpha(palette.ciscoBlue, 0.1)}`,
            borderColor: alpha(palette.ciscoBlue, 0.2),
          },
        },
      },
    },

    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          backgroundImage: 'none',
        },
        elevation1: {
          boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
          border: `1px solid ${palette.gray[200]}`,
        },
      },
    },

    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: palette.ciscoBlue,
          backgroundImage: `linear-gradient(135deg, ${palette.ciscoBlue} 0%, ${palette.blue[600]} 100%)`,
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        },
      },
    },

    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          fontWeight: 500,
        },
      },
    },

    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            backgroundColor: '#ffffff',
            borderRadius: 8,
            '& fieldset': {
              borderColor: palette.gray[300],
            },
            '&:hover fieldset': {
              borderColor: palette.gray[400],
            },
          },
        },
      },
    },

    MuiSelect: {
      styleOverrides: {
        root: {
          backgroundColor: '#ffffff',
          borderRadius: 8,
        },
      },
    },

    MuiDialog: {
      styleOverrides: {
        paper: {
          borderRadius: 16,
          boxShadow: '0 24px 48px rgba(0,0,0,0.15)',
        },
      },
    },

    MuiMenu: {
      styleOverrides: {
        paper: {
          borderRadius: 12,
          boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
          border: `1px solid ${palette.gray[200]}`,
        },
      },
    },

    MuiDivider: {
      styleOverrides: {
        root: {
          borderColor: palette.gray[200],
        },
      },
    },

    MuiLinearProgress: {
      styleOverrides: {
        root: {
          borderRadius: 4,
          backgroundColor: palette.gray[200],
        },
        bar: {
          borderRadius: 4,
        },
      },
    },
  },
})

export const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: palette.blue[300],
      light: palette.blue[200],
      dark: palette.blue[500],
      contrastText: '#ffffff',
    },
    secondary: {
      main: '#9cd97b',
      light: '#c5e8a8',
      dark: palette.ciscoGreen,
      contrastText: '#000000',
    },
    error: {
      main: '#f87171',
      light: '#fca5a5',
      dark: '#dc2626',
    },
    warning: {
      main: '#fbbf24',
      light: '#fcd34d',
      dark: '#d97706',
    },
    info: {
      main: '#38bdf8',
      light: '#7dd3fc',
      dark: '#0284c7',
    },
    success: {
      main: '#4ade80',
      light: '#86efac',
      dark: '#16a34a',
    },
    background: {
      default: '#0f0f0f',
      paper: '#1a1a1a',
    },
    text: {
      primary: '#f5f5f5',
      secondary: '#a1a1aa',
      disabled: '#71717a',
    },
    divider: 'rgba(255,255,255,0.1)',
  },

  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: { fontSize: '2.5rem', fontWeight: 600, letterSpacing: '-0.5px' },
    h2: { fontSize: '2rem', fontWeight: 600, letterSpacing: '-0.25px' },
    h3: { fontSize: '1.75rem', fontWeight: 600 },
    h4: { fontSize: '1.5rem', fontWeight: 600 },
    h5: { fontSize: '1.25rem', fontWeight: 600 },
    h6: { fontSize: '1rem', fontWeight: 600 },
    body1: { fontSize: '0.95rem', lineHeight: 1.6 },
    body2: { fontSize: '0.875rem', lineHeight: 1.5 },
    caption: { fontSize: '0.75rem', fontWeight: 500, letterSpacing: '0.4px' },
    button: { fontWeight: 600 },
  },

  shape: {
    borderRadius: 8,
  },

  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          background: 'linear-gradient(135deg, #0f0f0f 0%, #1a1a2e 100%)',
          minHeight: '100vh',
        },
      },
    },

    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 8,
          fontWeight: 600,
          padding: '8px 16px',
        },
        contained: {
          boxShadow: `0 2px 8px ${alpha(palette.blue[300], 0.3)}`,
        },
        outlined: {
          borderWidth: '1.5px',
          '&:hover': {
            borderWidth: '1.5px',
          },
        },
      },
    },

    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 16,
          backgroundColor: '#1a1a1a',
          border: '1px solid rgba(255,255,255,0.1)',
          boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
          '&:hover': {
            boxShadow: `0 8px 24px rgba(0,0,0,0.4)`,
            borderColor: alpha(palette.blue[300], 0.3),
          },
        },
      },
    },

    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          backgroundImage: 'none',
          backgroundColor: '#1a1a1a',
        },
      },
    },

    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#1a1a1a',
          backgroundImage: 'linear-gradient(135deg, #1a1a1a 0%, #252536 100%)',
          boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
        },
      },
    },

    MuiDialog: {
      styleOverrides: {
        paper: {
          borderRadius: 16,
          backgroundColor: '#1a1a1a',
          border: '1px solid rgba(255,255,255,0.1)',
        },
      },
    },

    MuiMenu: {
      styleOverrides: {
        paper: {
          borderRadius: 12,
          backgroundColor: '#1a1a1a',
          border: '1px solid rgba(255,255,255,0.1)',
        },
      },
    },

    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            backgroundColor: '#252525',
            '& fieldset': {
              borderColor: 'rgba(255,255,255,0.1)',
            },
          },
        },
      },
    },
  },
})

// Default export for backward compatibility
export const theme = lightTheme
