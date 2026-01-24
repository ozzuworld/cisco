import { useState } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  Box,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  CssBaseline,
  Tooltip,
} from '@mui/material'
import {
  Menu as MenuIcon,
  Home as HomeIcon,
  Dashboard as DashboardIcon,
  Work as WorkIcon,
  HealthAndSafety as HealthIcon,
  NetworkCheck as CaptureIcon,
  Folder as FolderIcon,
  Settings as SettingsIcon,
  DarkMode as DarkModeIcon,
  LightMode as LightModeIcon,
} from '@mui/icons-material'
import { useJobNotifications } from '@/hooks'
import { useTheme } from '@/context'

interface NavItem {
  text: string
  icon: JSX.Element
  path: string
}

const navItems: NavItem[] = [
  { text: 'Home', icon: <HomeIcon />, path: '/' },
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard' },
  { text: 'Jobs', icon: <WorkIcon />, path: '/jobs' },
  { text: 'Health', icon: <HealthIcon />, path: '/health' },
  { text: 'Captures', icon: <CaptureIcon />, path: '/captures' },
  { text: 'Profiles', icon: <FolderIcon />, path: '/profiles' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
]

export default function MainLayout() {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null)
  const navigate = useNavigate()
  const location = useLocation()
  const menuOpen = Boolean(anchorEl)
  const { isDark, toggleTheme } = useTheme()

  // Global job status notifications
  useJobNotifications()

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget)
  }

  const handleMenuClose = () => {
    setAnchorEl(null)
  }

  const handleNavigation = (path: string) => {
    navigate(path)
    handleMenuClose()
  }

  return (
    <Box sx={{ display: 'flex' }}>
      <CssBaseline />
      <AppBar position="fixed">
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open menu"
            edge="start"
            onClick={handleMenuOpen}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={menuOpen}
            onClose={handleMenuClose}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'left',
            }}
            transformOrigin={{
              vertical: 'top',
              horizontal: 'left',
            }}
            slotProps={{
              paper: {
                sx: {
                  bgcolor: '#1a1a2e',
                  color: 'white',
                  borderRadius: 3,
                  minWidth: 200,
                  mt: 1,
                  '& .MuiMenuItem-root': {
                    py: 1.5,
                    px: 2.5,
                    '&:hover': {
                      bgcolor: 'rgba(255, 255, 255, 0.1)',
                    },
                    '&.Mui-selected': {
                      bgcolor: 'rgba(255, 255, 255, 0.15)',
                      '&:hover': {
                        bgcolor: 'rgba(255, 255, 255, 0.2)',
                      },
                    },
                  },
                  '& .MuiListItemIcon-root': {
                    color: 'white',
                    minWidth: 40,
                  },
                  '& .MuiListItemText-primary': {
                    fontSize: '1rem',
                    fontWeight: 500,
                  },
                },
              },
            }}
          >
            {navItems.map(item => (
              <MenuItem
                key={item.text}
                selected={location.pathname === item.path}
                onClick={() => handleNavigation(item.path)}
              >
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.text} />
              </MenuItem>
            ))}
          </Menu>
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            CUCM Log Collector
          </Typography>
          <Tooltip title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}>
            <IconButton color="inherit" onClick={toggleTheme}>
              {isDark ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: '100%',
        }}
      >
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  )
}
