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
  Divider,
  ListSubheader,
} from '@mui/material'
import {
  Menu as MenuIcon,
  Home as HomeIcon,
  Work as WorkIcon,
  HealthAndSafety as HealthIcon,
  NetworkCheck as CaptureIcon,
  Folder as FolderIcon,
  Settings as SettingsIcon,
  DarkMode as DarkModeIcon,
  LightMode as LightModeIcon,
  Troubleshoot as InvestigationIcon,
  Dns as EnvironmentIcon,
  BugReport as TraceIcon,
  Description as LogsIcon,
} from '@mui/icons-material'
import { useJobNotifications } from '@/hooks'
import { useTheme } from '@/context'

interface NavItem {
  text: string
  icon: JSX.Element
  path: string
  group?: string
}

const navItems: NavItem[] = [
  // Primary
  { text: 'Home', icon: <HomeIcon />, path: '/', group: 'primary' },
  { text: 'Investigations', icon: <InvestigationIcon />, path: '/investigations', group: 'primary' },
  { text: 'Environments', icon: <EnvironmentIcon />, path: '/environments', group: 'primary' },
  // Tools
  { text: 'Captures', icon: <CaptureIcon />, path: '/captures', group: 'tools' },
  { text: 'Log Collection', icon: <LogsIcon />, path: '/logs/new', group: 'tools' },
  { text: 'Health', icon: <HealthIcon />, path: '/health', group: 'tools' },
  { text: 'Trace Levels', icon: <TraceIcon />, path: '/trace-levels', group: 'tools' },
  { text: 'Jobs', icon: <WorkIcon />, path: '/jobs', group: 'tools' },
  // Settings
  { text: 'Profiles', icon: <FolderIcon />, path: '/profiles', group: 'settings' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings', group: 'settings' },
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

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/'
    return location.pathname.startsWith(path)
  }

  const renderGroup = (group: string, label?: string) => {
    const items = navItems.filter(i => i.group === group)
    return (
      <>
        {label && (
          <ListSubheader
            sx={{
              bgcolor: 'transparent',
              color: 'rgba(255, 255, 255, 0.5)',
              fontSize: '0.7rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: 1,
              lineHeight: '32px',
              px: 2.5,
            }}
          >
            {label}
          </ListSubheader>
        )}
        {items.map(item => (
          <MenuItem
            key={item.text}
            selected={isActive(item.path)}
            onClick={() => handleNavigation(item.path)}
          >
            <ListItemIcon>{item.icon}</ListItemIcon>
            <ListItemText primary={item.text} />
          </MenuItem>
        ))}
      </>
    )
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
                  minWidth: 220,
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
                  '& .MuiDivider-root': {
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    my: 0.5,
                  },
                },
              },
            }}
          >
            {renderGroup('primary')}
            <Divider />
            {renderGroup('tools', 'Tools')}
            <Divider />
            {renderGroup('settings')}
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
