import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Paper,
  Button,
  Grid,
  Card,
  CardContent,
  CardActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  InputAdornment,
  CircularProgress,
  Alert,
  Divider,
  LinearProgress,
  Chip,
  Slider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Collapse,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  alpha,
} from '@mui/material'
import {
  Phone as CucmIcon,
  Router as CubeIcon,
  Link as ExpresswayIcon,
  Visibility,
  VisibilityOff,
  ArrowBack,
  CheckCircle,
  Error as ErrorIcon,
  Pending as PendingIcon,
  Download,
  Add,
  Delete,
  Stop,
  PlayArrow,
  Timer,
  ExpandMore,
  ExpandLess,
  Refresh,
  History,
  NetworkCheck,
  Close,
  DevicesOther,
  Settings,
  FolderOpen,
  Lan,
  Cable,
  FilterAlt,
  FiberManualRecord,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { captureService } from '@/services'
import type {
  CaptureDeviceType,
  CaptureSessionStatus,
  CaptureTargetStatus,
  CaptureTargetInfo,
  CaptureSessionInfo,
  CaptureSessionStatusResponse,
} from '@/types'
import {
  shouldPollCaptureSession,
  getSessionPollingInterval,
  canDownloadSession,
  defaultCaptureInterfaces,
  defaultCapturePorts,
} from '@/types'

interface TargetEntry {
  id: string
  device_type: CaptureDeviceType
  host: string
  port?: number
  interface?: string
  username: string
  password: string
}

// Teal accent theme for Packet Capture (distinct from blue LogCollection)
const ACCENT_COLOR = '#0d9488' // teal-600

const deviceTypeConfig: Record<CaptureDeviceType, { label: string; icon: React.ReactElement; color: string }> = {
  cucm: { label: 'CUCM', icon: <CucmIcon />, color: '#0891b2' },      // cyan-600
  cube: { label: 'CUBE', icon: <CubeIcon />, color: '#d97706' },       // amber-600
  csr1000v: { label: 'CSR1000v', icon: <CubeIcon />, color: '#0d9488' }, // teal-600
  expressway: { label: 'Expressway', icon: <ExpresswayIcon />, color: '#7c3aed' }, // violet-600
}

const targetStatusConfig: Record<CaptureTargetStatus, { color: string; label: string }> = {
  pending: { color: '#6b7280', label: 'Pending' },
  configuring: { color: '#3b82f6', label: 'Configuring' },
  ready: { color: '#3b82f6', label: 'Ready' },
  capturing: { color: '#3b82f6', label: 'Capturing' },
  stopping: { color: '#eab308', label: 'Stopping' },
  collecting: { color: '#3b82f6', label: 'Collecting' },
  completed: { color: '#22c55e', label: 'Completed' },
  failed: { color: '#ef4444', label: 'Failed' },
  cancelled: { color: '#eab308', label: 'Cancelled' },
}

export default function CaptureSession() {
  const navigate = useNavigate()
  const { enqueueSnackbar } = useSnackbar()

  // Targets list
  const [targets, setTargets] = useState<TargetEntry[]>([])

  // Add device dialog
  const [showAddDevice, setShowAddDevice] = useState(false)
  const [newDeviceType, setNewDeviceType] = useState<CaptureDeviceType>('cucm')
  const [newHost, setNewHost] = useState('')
  const [newPort, setNewPort] = useState<number>(22)
  const [newInterface, setNewInterface] = useState('')
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [showNewPassword, setShowNewPassword] = useState(false)

  // Configuration
  const [sessionName, setSessionName] = useState('')
  const [duration, setDuration] = useState(60)
  const [filterHost, setFilterHost] = useState('')
  const [filterPort, setFilterPort] = useState<number | ''>('')
  const [showFilters, setShowFilters] = useState(false)

  // Device detail modal
  const [selectedTarget, setSelectedTarget] = useState<TargetEntry | null>(null)
  const [showTargetPassword, setShowTargetPassword] = useState(false)
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({})

  // Session state
  const [activeSession, setActiveSession] = useState<CaptureSessionStatusResponse | null>(null)
  const [isStarting, setIsStarting] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [isCapturing, setIsCapturing] = useState(false)

  // History
  const [sessions, setSessions] = useState<CaptureSessionInfo[]>([])
  const [isLoadingSessions, setIsLoadingSessions] = useState(false)
  const [showHistory, setShowHistory] = useState(false)

  // Settings section collapsed state
  const [settingsExpanded, setSettingsExpanded] = useState(true)

  // Countdown timer
  const [countdown, setCountdown] = useState<{ elapsed: number; remaining: number } | null>(null)

  // Load session history
  const loadSessions = useCallback(async () => {
    setIsLoadingSessions(true)
    try {
      const response = await captureService.getSessions(20)
      setSessions(response.sessions || [])
    } catch (error) {
      console.error('Failed to load sessions:', error)
    } finally {
      setIsLoadingSessions(false)
    }
  }, [])

  useEffect(() => {
    loadSessions()
  }, [loadSessions])

  // Poll active session
  useEffect(() => {
    if (!activeSession?.session) return

    const status = activeSession.session.status
    if (!shouldPollCaptureSession(status)) return

    const interval = getSessionPollingInterval(status)
    const timer = setTimeout(async () => {
      try {
        const response = await captureService.getSessionStatus(activeSession.session.session_id)
        setActiveSession(response)

        // Update countdown during capturing
        if (response.elapsed_sec !== undefined && response.remaining_sec !== undefined) {
          setCountdown({ elapsed: response.elapsed_sec, remaining: response.remaining_sec })
        }

        // Check if completed
        if (canDownloadSession(response.session.status)) {
          enqueueSnackbar('Capture session completed! Downloads ready.', { variant: 'success' })
          setIsCapturing(false)
          loadSessions()
        } else if (response.session.status === 'failed') {
          enqueueSnackbar('Capture session failed', { variant: 'error' })
          setIsCapturing(false)
          loadSessions()
        }
      } catch (error) {
        console.error('Failed to poll session:', error)
      }
    }, interval)

    return () => clearTimeout(timer)
  }, [activeSession, enqueueSnackbar, loadSessions])

  const handleDeviceTypeChange = (type: CaptureDeviceType) => {
    setNewDeviceType(type)
    setNewPort(defaultCapturePorts[type])
    setNewInterface('')
  }

  const handleAddTarget = () => {
    if (!newHost) {
      enqueueSnackbar('Please enter a host address', { variant: 'warning' })
      return
    }
    if (!newUsername || !newPassword) {
      enqueueSnackbar('Please enter credentials', { variant: 'warning' })
      return
    }
    if (targets.length >= 10) {
      enqueueSnackbar('Maximum 10 devices allowed', { variant: 'warning' })
      return
    }

    const newTarget: TargetEntry = {
      id: `${newDeviceType}-${Date.now()}`,
      device_type: newDeviceType,
      host: newHost,
      port: newPort || defaultCapturePorts[newDeviceType],
      interface: newInterface || defaultCaptureInterfaces[newDeviceType],
      username: newUsername,
      password: newPassword,
    }

    setTargets([...targets, newTarget])
    setNewHost('')
    setNewInterface('')
    setNewUsername('')
    setNewPassword('')
    setShowAddDevice(false)

    enqueueSnackbar(`Added ${deviceTypeConfig[newDeviceType].label}: ${newHost}`, { variant: 'success' })
  }

  const handleRemoveTarget = (id: string) => {
    setTargets(targets.filter(t => t.id !== id))
  }

  const handleStartSession = async () => {
    if (targets.length === 0) {
      enqueueSnackbar('Please add at least one device', { variant: 'warning' })
      return
    }

    setIsStarting(true)
    setIsCapturing(true)

    try {
      const response = await captureService.startSession({
        name: sessionName || undefined,
        duration_sec: duration,
        filter: filterHost || filterPort ? {
          host: filterHost || undefined,
          port: filterPort || undefined,
        } : undefined,
        targets: targets.map(t => ({
          device_type: t.device_type,
          host: t.host,
          port: t.port,
          interface: t.interface,
          username: t.username,
          password: t.password,
        })),
      })

      // Start polling
      const statusResponse = await captureService.getSessionStatus(response.session_id)
      setActiveSession(statusResponse)
      setCountdown(null)

      enqueueSnackbar('Capture session started!', { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(
        error instanceof Error ? error.message : 'Failed to start session',
        { variant: 'error' }
      )
      setIsCapturing(false)
    } finally {
      setIsStarting(false)
    }
  }

  const handleStopSession = async () => {
    if (!activeSession?.session) return

    setIsStopping(true)
    try {
      await captureService.stopSession(activeSession.session.session_id)
      enqueueSnackbar('Stop signal sent', { variant: 'info' })
    } catch (error) {
      enqueueSnackbar(
        error instanceof Error ? error.message : 'Failed to stop session',
        { variant: 'error' }
      )
    } finally {
      setIsStopping(false)
    }
  }

  const handleDownload = (sessionId: string, filename?: string) => {
    captureService.downloadSessionBundle(sessionId, filename)
    enqueueSnackbar('Download started', { variant: 'success' })
  }

  const handleDeleteSession = async (sessionId: string) => {
    try {
      await captureService.deleteSession(sessionId)
      enqueueSnackbar('Session deleted', { variant: 'success' })
      loadSessions()
    } catch {
      enqueueSnackbar('Failed to delete session', { variant: 'error' })
    }
  }

  const handleNewSession = () => {
    setTargets([])
    setSessionName('')
    setDuration(60)
    setFilterHost('')
    setFilterPort('')
    setActiveSession(null)
    setCountdown(null)
    setIsCapturing(false)
  }

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const formatDate = (dateStr?: string): string => {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleString()
  }

  const getStatusMessage = (status: CaptureSessionStatus): string => {
    switch (status) {
      case 'pending': return 'Preparing...'
      case 'configuring': return 'Configuring devices...'
      case 'ready': return 'All devices ready'
      case 'starting': return 'Starting captures...'
      case 'capturing': return 'Capturing packets...'
      case 'stopping': return 'Stopping captures...'
      case 'collecting': return 'Retrieving capture files...'
      case 'completed': return 'Session complete'
      case 'partial': return 'Some devices completed'
      case 'failed': return 'Session failed'
      case 'cancelled': return 'Session cancelled'
      default: return status
    }
  }

  const getStatusColor = (status: CaptureTargetStatus) => {
    return targetStatusConfig[status]?.color || '#6b7280'
  }

  const getStatusIcon = (status: CaptureTargetStatus, size: number = 24) => {
    switch (status) {
      case 'completed':
        return <CheckCircle sx={{ fontSize: size }} color="success" />
      case 'failed':
      case 'cancelled':
        return <ErrorIcon sx={{ fontSize: size }} color="error" />
      case 'capturing':
      case 'configuring':
      case 'collecting':
      case 'stopping':
        return <CircularProgress size={size} />
      default:
        return <PendingIcon sx={{ fontSize: size }} color="disabled" />
    }
  }

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }))
  }

  // Get target status from active session
  const getTargetStatus = (host: string): CaptureTargetInfo | undefined => {
    return activeSession?.session?.targets?.find(t => t.host === host)
  }

  const session = activeSession?.session
  const isFinished = session && canDownloadSession(session.status)
  const isFailed = session && (session.status === 'failed' || session.status === 'cancelled')

  // Workflow steps with icons
  const workflowSteps = [
    { label: 'Devices', icon: <DevicesOther sx={{ fontSize: 16 }} /> },
    { label: 'Configure', icon: <Settings sx={{ fontSize: 16 }} /> },
    { label: 'Capture', icon: <FiberManualRecord sx={{ fontSize: 16 }} /> },
    { label: 'Download', icon: <Download sx={{ fontSize: 16 }} /> },
  ]

  const getActiveStep = () => {
    if (isFinished) return 3
    if (isCapturing) return 2
    if (targets.length > 0) return 1
    return 0
  }

  // Device counts by type
  const deviceCounts = {
    cucm: targets.filter(t => t.device_type === 'cucm').length,
    cube: targets.filter(t => t.device_type === 'cube').length,
    csr1000v: targets.filter(t => t.device_type === 'csr1000v').length,
    expressway: targets.filter(t => t.device_type === 'expressway').length,
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <IconButton onClick={() => navigate('/')}>
            <ArrowBack />
          </IconButton>
          <Typography variant="h5" fontWeight={600}>Packet Capture</Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {!isCapturing && (
            <Button
              variant="outlined"
              startIcon={<Add />}
              onClick={() => setShowAddDevice(true)}
              disabled={targets.length >= 10}
              sx={{ borderColor: ACCENT_COLOR, color: ACCENT_COLOR, '&:hover': { borderColor: ACCENT_COLOR, bgcolor: alpha(ACCENT_COLOR, 0.08) } }}
            >
              Add Device
            </Button>
          )}
          {targets.length > 0 && !isCapturing && (
            <Button
              variant="contained"
              startIcon={isStarting ? <CircularProgress size={20} color="inherit" /> : <PlayArrow />}
              onClick={handleStartSession}
              disabled={isStarting}
              sx={{ bgcolor: ACCENT_COLOR, '&:hover': { bgcolor: '#0f766e' } }}
            >
              {isStarting ? 'Starting...' : 'Start Capture'}
            </Button>
          )}
          {isCapturing && !isFinished && !isFailed && (
            <Button
              variant="contained"
              color="error"
              startIcon={isStopping ? <CircularProgress size={20} color="inherit" /> : <Stop />}
              onClick={handleStopSession}
              disabled={isStopping || session?.status === 'stopping' || session?.status === 'collecting'}
            >
              {isStopping ? 'Stopping...' : 'Stop Capture'}
            </Button>
          )}
          {(isFinished || isFailed) && (
            <>
              {isFinished && activeSession?.download_available && (
                <Button
                  variant="contained"
                  startIcon={<Download />}
                  onClick={() => handleDownload(session!.session_id, session!.bundle_filename)}
                  sx={{ bgcolor: ACCENT_COLOR, '&:hover': { bgcolor: '#0f766e' } }}
                >
                  Download Bundle
                </Button>
              )}
              <Button
                variant="outlined"
                startIcon={<PlayArrow />}
                onClick={handleNewSession}
              >
                New Session
              </Button>
            </>
          )}
        </Box>
      </Box>

      {/* Compact Workflow & Stats Bar */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 2,
          mb: 2,
          p: 1.5,
          bgcolor: alpha(ACCENT_COLOR, 0.06),
          borderRadius: 2,
          border: `1px solid ${alpha(ACCENT_COLOR, 0.15)}`,
        }}
      >
        {/* Mini Stepper with Icons */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          {workflowSteps.map((step, index) => {
            const isActive = index === getActiveStep()
            const isCompleted = index < getActiveStep()
            return (
              <Box key={step.label} sx={{ display: 'flex', alignItems: 'center' }}>
                <Chip
                  size="small"
                  label={step.label}
                  icon={isCompleted ? <CheckCircle sx={{ fontSize: 16 }} /> : step.icon}
                  sx={{
                    height: 30,
                    fontSize: '0.75rem',
                    fontWeight: isActive ? 600 : 400,
                    bgcolor: isCompleted ? '#10b981' : isActive ? ACCENT_COLOR : 'transparent',
                    color: isCompleted || isActive ? 'white' : 'text.secondary',
                    border: !isCompleted && !isActive ? '1px solid' : 'none',
                    borderColor: 'divider',
                    '& .MuiChip-icon': {
                      color: isCompleted || isActive ? 'white' : 'text.disabled',
                    },
                  }}
                />
                {index < workflowSteps.length - 1 && (
                  <Box
                    sx={{
                      width: 24,
                      height: 2,
                      bgcolor: isCompleted ? '#10b981' : 'divider',
                      mx: 0.5,
                    }}
                  />
                )}
              </Box>
            )
          })}
        </Box>

        {/* Compact Stats */}
        {targets.length > 0 && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip
              size="small"
              icon={<DevicesOther sx={{ fontSize: 16 }} />}
              label={`${targets.length} devices`}
              sx={{ bgcolor: alpha(ACCENT_COLOR, 0.15) }}
            />
            {deviceCounts.cucm > 0 && (
              <Chip
                size="small"
                icon={<CucmIcon sx={{ fontSize: 16, color: deviceTypeConfig.cucm.color }} />}
                label={deviceCounts.cucm}
                sx={{ bgcolor: alpha(deviceTypeConfig.cucm.color, 0.1), minWidth: 50 }}
              />
            )}
            {deviceCounts.csr1000v > 0 && (
              <Chip
                size="small"
                icon={<CubeIcon sx={{ fontSize: 16, color: deviceTypeConfig.csr1000v.color }} />}
                label={deviceCounts.csr1000v}
                sx={{ bgcolor: alpha(deviceTypeConfig.csr1000v.color, 0.1), minWidth: 50 }}
              />
            )}
            {deviceCounts.expressway > 0 && (
              <Chip
                size="small"
                icon={<ExpresswayIcon sx={{ fontSize: 16, color: deviceTypeConfig.expressway.color }} />}
                label={deviceCounts.expressway}
                sx={{ bgcolor: alpha(deviceTypeConfig.expressway.color, 0.1), minWidth: 50 }}
              />
            )}
            {isFinished && activeSession?.download_available && (
              <Chip
                size="small"
                icon={<Download sx={{ fontSize: 16 }} />}
                label="Ready"
                color="success"
              />
            )}
          </Box>
        )}
      </Box>

      {/* Active Capture Status */}
      {isCapturing && session && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              {isFinished ? (
                <CheckCircle sx={{ fontSize: 48 }} color="success" />
              ) : isFailed ? (
                <ErrorIcon sx={{ fontSize: 48 }} color="error" />
              ) : (
                <CircularProgress size={48} />
              )}
              <Box>
                <Typography variant="h5">
                  {session.name || 'Capture Session'}
                </Typography>
                <Typography color="text.secondary">
                  {getStatusMessage(session.status)}
                </Typography>
              </Box>
            </Box>

            {/* Animated Countdown Timer */}
            {session.status === 'capturing' && countdown && (
              <Box
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 2,
                }}
              >
                {/* Circular Progress Ring */}
                <Box sx={{ position: 'relative', display: 'inline-flex' }}>
                  {/* Background ring */}
                  <CircularProgress
                    variant="determinate"
                    value={100}
                    size={80}
                    thickness={3}
                    sx={{ color: alpha(ACCENT_COLOR, 0.15) }}
                  />
                  {/* Progress ring */}
                  <CircularProgress
                    variant="determinate"
                    value={(countdown.elapsed / duration) * 100}
                    size={80}
                    thickness={3}
                    sx={{
                      position: 'absolute',
                      left: 0,
                      color: ACCENT_COLOR,
                      '& .MuiCircularProgress-circle': {
                        strokeLinecap: 'round',
                        transition: 'stroke-dashoffset 0.5s ease',
                      },
                    }}
                  />
                  {/* Center content */}
                  <Box
                    sx={{
                      top: 0,
                      left: 0,
                      bottom: 0,
                      right: 0,
                      position: 'absolute',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexDirection: 'column',
                    }}
                  >
                    <Timer sx={{ fontSize: 18, color: ACCENT_COLOR, mb: 0.25 }} />
                    <Typography
                      variant="caption"
                      fontWeight={700}
                      sx={{ color: ACCENT_COLOR, fontSize: '0.65rem' }}
                    >
                      {Math.round((countdown.elapsed / duration) * 100)}%
                    </Typography>
                  </Box>
                </Box>

                {/* Time display */}
                <Box sx={{ textAlign: 'left' }}>
                  <Typography
                    variant="h3"
                    sx={{
                      fontFamily: 'monospace',
                      fontWeight: 700,
                      color: 'text.primary',
                      lineHeight: 1,
                    }}
                  >
                    {formatTime(countdown.remaining)}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <Box
                      sx={{
                        width: 6,
                        height: 6,
                        borderRadius: '50%',
                        bgcolor: ACCENT_COLOR,
                        animation: 'pulse 1.5s ease-in-out infinite',
                        '@keyframes pulse': {
                          '0%, 100%': { opacity: 1, transform: 'scale(1)' },
                          '50%': { opacity: 0.5, transform: 'scale(1.3)' },
                        },
                      }}
                    />
                    {formatTime(countdown.elapsed)} elapsed of {formatTime(duration)}
                  </Typography>
                </Box>
              </Box>
            )}
          </Box>

          {session.status === 'capturing' && countdown && (
            <LinearProgress
              variant="determinate"
              value={(countdown.elapsed / duration) * 100}
              sx={{ height: 8, borderRadius: 4 }}
            />
          )}

          {session.status === 'configuring' && targets.some(t => t.device_type === 'csr1000v') && (
            <Alert severity="info" sx={{ mt: 2 }}>
              CSR/IOS-XE devices require EPC configuration which takes ~2-3 minutes per device.
            </Alert>
          )}
        </Paper>
      )}

      {/* No devices state */}
      {targets.length === 0 && !isCapturing && (
        <Paper
          sx={{
            p: 6,
            textAlign: 'center',
            borderRadius: 3,
            border: `1px dashed ${alpha(ACCENT_COLOR, 0.3)}`,
            bgcolor: alpha(ACCENT_COLOR, 0.02),
          }}
        >
          <Box
            sx={{
              width: 80,
              height: 80,
              borderRadius: '50%',
              bgcolor: alpha(ACCENT_COLOR, 0.1),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              mx: 'auto',
              mb: 3,
            }}
          >
            <NetworkCheck sx={{ fontSize: 40, color: ACCENT_COLOR }} />
          </Box>
          <Typography variant="h6" color="text.primary" fontWeight={600} gutterBottom>
            No Devices Added
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Add devices to capture packets from simultaneously (max 10 devices)
          </Typography>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setShowAddDevice(true)}
            sx={{ bgcolor: ACCENT_COLOR, '&:hover': { bgcolor: '#0f766e' } }}
          >
            Add Your First Device
          </Button>
        </Paper>
      )}

      {/* Device Cards - Enhanced Grid */}
      {targets.length > 0 && (
        <Grid container spacing={2}>
          {targets.map(target => {
            const config = deviceTypeConfig[target.device_type]
            const targetStatus = getTargetStatus(target.host)
            const status = targetStatus?.status || 'pending'
            const hasStatus = !!targetStatus

            return (
              <Grid item xs={12} sm={6} md={4} lg={3} key={target.id}>
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    borderRadius: 3,
                    overflow: 'hidden',
                    border: 'none',
                    boxShadow: `0 2px 8px ${alpha(config.color, 0.15)}`,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: `0 8px 24px ${alpha(config.color, 0.25)}`,
                    },
                  }}
                >
                  {/* Gradient header with large icon */}
                  <Box
                    sx={{
                      px: 2,
                      py: 1.5,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      background: `linear-gradient(135deg, ${alpha(config.color, 0.15)} 0%, ${alpha(config.color, 0.05)} 100%)`,
                      borderBottom: `2px solid ${config.color}`,
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                      <Box
                        sx={{
                          width: 36,
                          height: 36,
                          borderRadius: 2,
                          bgcolor: 'background.paper',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          boxShadow: `0 2px 8px ${alpha(config.color, 0.3)}`,
                        }}
                      >
                        {React.cloneElement(config.icon, { sx: { fontSize: 20, color: config.color } })}
                      </Box>
                      <Box>
                        <Typography variant="caption" fontWeight={700} color={config.color} sx={{ textTransform: 'uppercase', letterSpacing: 0.5 }}>
                          {config.label}
                        </Typography>
                        {/* Status indicator */}
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.25 }}>
                          <Box
                            sx={{
                              width: 6,
                              height: 6,
                              borderRadius: '50%',
                              bgcolor: hasStatus ? getStatusColor(status) : '#9ca3af',
                              ...(status === 'capturing' || status === 'configuring' || status === 'collecting' ? {
                                animation: 'pulse 1.5s ease-in-out infinite',
                                '@keyframes pulse': {
                                  '0%, 100%': { opacity: 1, transform: 'scale(1)' },
                                  '50%': { opacity: 0.5, transform: 'scale(1.3)' },
                                },
                              } : {}),
                            }}
                          />
                          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                            {hasStatus ? targetStatusConfig[status]?.label : 'Ready'}
                          </Typography>
                        </Box>
                      </Box>
                    </Box>
                    {!isCapturing && (
                      <IconButton
                        size="small"
                        onClick={() => handleRemoveTarget(target.id)}
                        sx={{ p: 0.5, color: 'text.secondary', '&:hover': { color: 'error.main' } }}
                      >
                        <Delete sx={{ fontSize: 18 }} />
                      </IconButton>
                    )}
                  </Box>

                  <CardContent sx={{ flexGrow: 1, p: 2 }}>
                    {/* Host */}
                    <Typography variant="body1" sx={{ fontWeight: 600, mb: 1.5, color: 'text.primary' }}>
                      {target.host}
                    </Typography>

                    {/* Connection details with icons */}
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Lan sx={{ fontSize: 14, color: 'text.disabled' }} />
                        <Typography variant="caption" color="text.secondary">
                          Port {target.port}
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Cable sx={{ fontSize: 14, color: 'text.disabled' }} />
                        <Typography variant="caption" color="text.secondary">
                          {target.interface}
                        </Typography>
                      </Box>
                    </Box>

                    {/* Status during capture */}
                    {hasStatus && targetStatus.packets_captured != null && (
                      <Box sx={{ mt: 1.5 }}>
                        <Chip
                          icon={<NetworkCheck sx={{ fontSize: 14 }} />}
                          label={`${targetStatus.packets_captured.toLocaleString()} packets`}
                          size="small"
                          sx={{
                            height: 24,
                            fontSize: '0.7rem',
                            fontWeight: 600,
                            bgcolor: alpha(ACCENT_COLOR, 0.1),
                            color: ACCENT_COLOR,
                            '& .MuiChip-icon': { color: ACCENT_COLOR },
                          }}
                        />
                      </Box>
                    )}

                    {/* Status chips for completed/failed */}
                    {status === 'completed' && (
                      <Box sx={{ mt: 1.5 }}>
                        <Chip size="small" label="Capture Complete" color="success" sx={{ height: 24, fontSize: '0.7rem' }} />
                      </Box>
                    )}

                    {status === 'failed' && (
                      <Box sx={{ mt: 1.5 }}>
                        <Chip size="small" label="Failed" color="error" sx={{ height: 24, fontSize: '0.7rem' }} />
                      </Box>
                    )}
                  </CardContent>

                  <CardActions sx={{ px: 2, pb: 1.5, pt: 0, borderTop: '1px solid', borderColor: 'divider' }}>
                    <Button
                      size="small"
                      onClick={() => setSelectedTarget(target)}
                      sx={{
                        ml: 'auto',
                        fontSize: '0.75rem',
                        color: config.color,
                        '&:hover': { bgcolor: alpha(config.color, 0.08) },
                      }}
                    >
                      View Details
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            )
          })}
        </Grid>
      )}

      {/* Capture Settings - show when devices added but not capturing */}
      {targets.length > 0 && !isCapturing && (
        <Paper
          sx={{
            p: 2,
            mt: 3,
            background: theme => theme.palette.mode === 'dark'
              ? 'linear-gradient(135deg, rgba(13,148,136,0.08) 0%, rgba(20,40,50,0.9) 100%)'
              : 'linear-gradient(135deg, rgba(13,148,136,0.03) 0%, rgba(248,250,252,0.95) 100%)',
            border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
            borderRadius: 3,
          }}
        >
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              cursor: 'pointer',
              '&:hover': { opacity: 0.8 },
            }}
            onClick={() => setSettingsExpanded(!settingsExpanded)}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Box
                sx={{
                  width: 8,
                  height: 28,
                  borderRadius: 1,
                  bgcolor: ACCENT_COLOR,
                }}
              />
              <Typography variant="h6" fontWeight={600}>Capture Settings</Typography>
            </Box>
            <IconButton size="small">
              {settingsExpanded ? <ExpandLess /> : <ExpandMore />}
            </IconButton>
          </Box>
          <Collapse in={settingsExpanded}>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5, mb: 2, ml: 3 }}>
              Configure your packet capture session
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Box
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    bgcolor: alpha(ACCENT_COLOR, 0.05),
                    border: `1px solid ${alpha(ACCENT_COLOR, 0.15)}`,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
                    <Settings sx={{ color: ACCENT_COLOR, fontSize: 20 }} />
                    <Typography variant="subtitle2" fontWeight={600}>Session Name</Typography>
                  </Box>
                  <TextField
                    value={sessionName}
                    onChange={e => setSessionName(e.target.value)}
                    placeholder="e.g., Debug Call Flow #12345"
                    fullWidth
                    size="small"
                    sx={{ bgcolor: 'background.paper' }}
                  />
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    bgcolor: alpha('#10b981', 0.05),
                    border: `1px solid ${alpha('#10b981', 0.15)}`,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
                    <Timer sx={{ color: '#10b981', fontSize: 20 }} />
                    <Typography variant="subtitle2" fontWeight={600}>Duration: {formatTime(duration)}</Typography>
                  </Box>
                  <Slider
                    value={duration}
                    onChange={(_, value) => setDuration(value as number)}
                    min={10}
                    max={600}
                    step={10}
                    marks={[
                      { value: 60, label: '1m' },
                      { value: 300, label: '5m' },
                      { value: 600, label: '10m' },
                    ]}
                    sx={{
                      color: '#10b981',
                      '& .MuiSlider-markLabel': { fontSize: '0.7rem' },
                    }}
                  />
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box
                  sx={{
                    p: 2,
                    borderRadius: 2,
                    bgcolor: alpha('#7c3aed', 0.05),
                    border: `1px solid ${alpha('#7c3aed', 0.15)}`,
                    minHeight: showFilters ? 'auto' : 88,
                    display: 'flex',
                    flexDirection: 'column',
                  }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      cursor: 'pointer',
                    }}
                    onClick={() => setShowFilters(!showFilters)}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <FilterAlt sx={{ color: '#7c3aed', fontSize: 20 }} />
                      <Typography variant="subtitle2" fontWeight={600}>Packet Filters</Typography>
                      {(filterHost || filterPort) && (
                        <Chip
                          size="small"
                          label="Active"
                          sx={{ height: 18, fontSize: '0.65rem', bgcolor: '#7c3aed', color: 'white' }}
                        />
                      )}
                    </Box>
                    {showFilters ? <ExpandLess sx={{ color: '#7c3aed' }} /> : <ExpandMore sx={{ color: '#7c3aed' }} />}
                  </Box>
                  {!showFilters && (
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
                      Click to add host/port filters
                    </Typography>
                  )}
                  <Collapse in={showFilters}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
                      <TextField
                        label="Filter by Host IP"
                        value={filterHost}
                        onChange={e => setFilterHost(e.target.value)}
                        placeholder="e.g., 10.0.0.50"
                        size="small"
                        fullWidth
                        sx={{ bgcolor: 'background.paper' }}
                        onClick={e => e.stopPropagation()}
                      />
                      <TextField
                        label="Filter by Port"
                        type="number"
                        value={filterPort}
                        onChange={e => setFilterPort(e.target.value ? Number(e.target.value) : '')}
                        placeholder="e.g., 5060"
                        size="small"
                        fullWidth
                        sx={{ bgcolor: 'background.paper' }}
                        onClick={e => e.stopPropagation()}
                      />
                    </Box>
                  </Collapse>
                </Box>
              </Grid>
            </Grid>

            {targets.some(t => t.device_type === 'csr1000v') && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                <strong>CSR1000v Note:</strong> IOS-XE devices require EPC configuration which takes ~2-3 minutes per device.
              </Alert>
            )}
          </Collapse>
        </Paper>
      )}

      {/* Add Device Dialog */}
      <Dialog open={showAddDevice} onClose={() => setShowAddDevice(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add Device</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
            <FormControl fullWidth>
              <InputLabel>Device Type</InputLabel>
              <Select
                value={newDeviceType}
                label="Device Type"
                onChange={e => handleDeviceTypeChange(e.target.value as CaptureDeviceType)}
              >
                <MenuItem value="cucm">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CucmIcon /> CUCM / UC Servers
                  </Box>
                </MenuItem>
                <MenuItem value="csr1000v">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CubeIcon /> CSR1000v / IOS-XE Routers
                  </Box>
                </MenuItem>
                <MenuItem value="expressway">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <ExpresswayIcon /> Expressway / VCS
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>

            <Grid container spacing={2}>
              <Grid item xs={8}>
                <TextField
                  label="Host IP/Hostname"
                  value={newHost}
                  onChange={e => setNewHost(e.target.value)}
                  placeholder="172.168.0.101"
                  fullWidth
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Port"
                  type="number"
                  value={newPort}
                  onChange={e => setNewPort(Number(e.target.value))}
                  fullWidth
                />
              </Grid>
            </Grid>

            <TextField
              label="Interface"
              value={newInterface}
              onChange={e => setNewInterface(e.target.value)}
              placeholder={defaultCaptureInterfaces[newDeviceType]}
              helperText={`Default: ${defaultCaptureInterfaces[newDeviceType]}`}
              fullWidth
            />

            <Divider />

            <TextField
              label="Username"
              value={newUsername}
              onChange={e => setNewUsername(e.target.value)}
              fullWidth
            />

            <TextField
              label="Password"
              type={showNewPassword ? 'text' : 'password'}
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              fullWidth
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowNewPassword(!showNewPassword)} edge="end">
                      {showNewPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAddDevice(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAddTarget}
            disabled={!newHost || !newUsername || !newPassword}
          >
            Add Device
          </Button>
        </DialogActions>
      </Dialog>

      {/* Device Detail Dialog */}
      <Dialog
        open={!!selectedTarget}
        onClose={() => setSelectedTarget(null)}
        maxWidth="sm"
        fullWidth
      >
        {selectedTarget && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Chip
                    icon={deviceTypeConfig[selectedTarget.device_type].icon}
                    label={deviceTypeConfig[selectedTarget.device_type].label}
                    sx={{
                      bgcolor: deviceTypeConfig[selectedTarget.device_type].color,
                      color: 'white',
                    }}
                  />
                  <Typography variant="h6">{selectedTarget.host}</Typography>
                </Box>
                <IconButton onClick={() => setSelectedTarget(null)}>
                  <Close />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent>
              <Paper variant="outlined" sx={{ mb: 2 }}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    p: 2,
                    cursor: 'pointer',
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                  onClick={() => toggleSection('info')}
                >
                  <Typography variant="subtitle1" fontWeight="medium">Device Information</Typography>
                  {expandedSections.info !== false ? <ExpandLess /> : <ExpandMore />}
                </Box>
                <Collapse in={expandedSections.info !== false}>
                  <Divider />
                  <Box sx={{ p: 2 }}>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Host</Typography>
                        <Typography variant="body1">{selectedTarget.host}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Port</Typography>
                        <Typography variant="body1">{selectedTarget.port}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Interface</Typography>
                        <Typography variant="body1">{selectedTarget.interface}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Username</Typography>
                        <Typography variant="body1">{selectedTarget.username}</Typography>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">Password</Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="body1">
                            {showTargetPassword ? selectedTarget.password : '••••••••'}
                          </Typography>
                          <IconButton size="small" onClick={() => setShowTargetPassword(!showTargetPassword)}>
                            {showTargetPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                          </IconButton>
                        </Box>
                      </Grid>
                    </Grid>
                  </Box>
                </Collapse>
              </Paper>

              {/* Capture status if active */}
              {(() => {
                const targetStatus = getTargetStatus(selectedTarget.host)
                if (!targetStatus) return null

                return (
                  <Paper variant="outlined">
                    <Box
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        p: 2,
                        cursor: 'pointer',
                        '&:hover': { bgcolor: 'action.hover' },
                      }}
                      onClick={() => toggleSection('status')}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getStatusIcon(targetStatus.status, 24)}
                        <Typography variant="subtitle1" fontWeight="medium">Capture Status</Typography>
                      </Box>
                      {expandedSections.status !== false ? <ExpandLess /> : <ExpandMore />}
                    </Box>
                    <Collapse in={expandedSections.status !== false}>
                      <Divider />
                      <Box sx={{ p: 2 }}>
                        <Typography variant="body2">
                          Status: {targetStatusConfig[targetStatus.status]?.label || targetStatus.status}
                        </Typography>
                        {targetStatus.message && (
                          <Typography variant="body2">Message: {targetStatus.message}</Typography>
                        )}
                        {targetStatus.packets_captured != null && (
                          <Typography variant="body2">
                            Packets: {targetStatus.packets_captured.toLocaleString()}
                          </Typography>
                        )}
                      </Box>
                    </Collapse>
                  </Paper>
                )
              })()}
            </DialogContent>
            <DialogActions>
              <Button variant="contained" onClick={() => setSelectedTarget(null)}>
                Close
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Session History */}
      <Paper
        sx={{
          mt: 3,
          borderRadius: 2,
          overflow: 'hidden',
          border: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            px: 2,
            py: 1.5,
            bgcolor: alpha(ACCENT_COLOR, 0.04),
            borderBottom: showHistory ? '1px solid' : 'none',
            borderColor: 'divider',
            cursor: 'pointer',
            '&:hover': { bgcolor: alpha(ACCENT_COLOR, 0.06) },
          }}
          onClick={() => setShowHistory(!showHistory)}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <History sx={{ color: ACCENT_COLOR }} />
            <Typography variant="subtitle1" fontWeight={600}>Session History</Typography>
            <Chip
              label={sessions.length}
              size="small"
              sx={{ height: 22, fontSize: '0.75rem', bgcolor: alpha(ACCENT_COLOR, 0.1) }}
            />
          </Box>
          <IconButton size="small">
            {showHistory ? <ExpandLess /> : <ExpandMore />}
          </IconButton>
        </Box>
        <Collapse in={showHistory}>
          <Box sx={{ p: 2 }}>
            {isLoadingSessions ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <CircularProgress size={32} sx={{ color: ACCENT_COLOR }} />
              </Box>
            ) : sessions.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <FolderOpen sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
                <Typography color="text.secondary">No previous sessions</Typography>
              </Box>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 600, color: 'text.secondary', fontSize: '0.75rem' }}>Name</TableCell>
                      <TableCell sx={{ fontWeight: 600, color: 'text.secondary', fontSize: '0.75rem' }}>Status</TableCell>
                      <TableCell sx={{ fontWeight: 600, color: 'text.secondary', fontSize: '0.75rem' }}>Devices</TableCell>
                      <TableCell sx={{ fontWeight: 600, color: 'text.secondary', fontSize: '0.75rem' }}>Duration</TableCell>
                      <TableCell sx={{ fontWeight: 600, color: 'text.secondary', fontSize: '0.75rem' }}>Created</TableCell>
                      <TableCell align="right" sx={{ fontWeight: 600, color: 'text.secondary', fontSize: '0.75rem' }}>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {sessions.map(sessionItem => {
                      const canDL = canDownloadSession(sessionItem.status)
                      return (
                        <TableRow
                          key={sessionItem.session_id}
                          sx={{ '&:hover': { bgcolor: alpha(ACCENT_COLOR, 0.03) } }}
                        >
                          <TableCell sx={{ fontSize: '0.85rem' }}>
                            {sessionItem.name || sessionItem.session_id.slice(0, 8)}
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={sessionItem.status}
                              size="small"
                              sx={{
                                height: 22,
                                fontSize: '0.7rem',
                                bgcolor: canDL ? '#10b981' : sessionItem.status === 'failed' ? '#ef4444' : '#6b7280',
                                color: 'white',
                              }}
                            />
                          </TableCell>
                          <TableCell sx={{ fontSize: '0.85rem' }}>{sessionItem.targets.length}</TableCell>
                          <TableCell sx={{ fontSize: '0.85rem' }}>{formatTime(sessionItem.duration_sec)}</TableCell>
                          <TableCell sx={{ fontSize: '0.85rem' }}>{formatDate(sessionItem.created_at)}</TableCell>
                          <TableCell align="right">
                            {canDL && (
                              <Tooltip title="Download">
                                <IconButton
                                  size="small"
                                  onClick={() => handleDownload(sessionItem.session_id, sessionItem.bundle_filename)}
                                  sx={{ color: ACCENT_COLOR }}
                                >
                                  <Download fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            )}
                            <Tooltip title="Delete">
                              <IconButton
                                size="small"
                                onClick={() => handleDeleteSession(sessionItem.session_id)}
                                sx={{ color: 'text.secondary', '&:hover': { color: 'error.main' } }}
                              >
                                <Delete fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            )}

            <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
              <Button
                size="small"
                startIcon={<Refresh />}
                onClick={loadSessions}
                disabled={isLoadingSessions}
                sx={{ color: ACCENT_COLOR }}
              >
                Refresh
              </Button>
            </Box>
          </Box>
        </Collapse>
      </Paper>
    </Box>
  )
}
