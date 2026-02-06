import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Paper,
  Button,
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  InputAdornment,
  CircularProgress,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  alpha,
  Checkbox,
  Tooltip,
  LinearProgress,
  Tabs,
  Tab,
  Divider,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material'
import {
  Visibility,
  VisibilityOff,
  ArrowBack,
  CheckCircle,
  Error as ErrorIcon,
  BugReport as DebugIcon,
  Save as SaveIcon,
  Dns as CucmIcon,
  Router as CubeIcon,
  Star,
  Computer,
  Search,
  Download,
  Preview,
  FolderOpen,
  LinkOff,
  Link as LinkIcon,
  Refresh,
  PlayArrow,
  Stop,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { logService } from '@/services'
import { useGetTraceLevels, useSetTraceLevels, useProfiles, useCreateSession, useDeleteSession, useGetCubeDebugStatus, useEnableCubeDebug, useClearCubeDebug } from '@/hooks'
import type { TraceLevelSetNodeResult, TraceLevelNodeResult } from '@/services/traceService'
import type { CubeDebugCategory } from '@/services/logService'
import type { ClusterNode, DebugLevel, LogProfile } from '@/types'

type DeviceMode = 'cucm' | 'cube'

interface TraceSnapshot {
  label: string
  timestamp: string
  nodes: TraceLevelNodeResult[]
}

interface SetSnapshot {
  label: string
  timestamp: string
  level: DebugLevel
  services: string[]
  nodes: TraceLevelSetNodeResult[]
}

export default function TraceLevel() {
  const navigate = useNavigate()
  const { enqueueSnackbar } = useSnackbar()

  // Device mode selector
  const [deviceMode, setDeviceMode] = useState<DeviceMode>('cucm')

  // Connection form
  const [host, setHost] = useState('')
  const [port, setPort] = useState(22)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  // Discovery state
  const [isDiscovering, setIsDiscovering] = useState(false)
  const [discoveredNodes, setDiscoveredNodes] = useState<ClusterNode[]>([])
  const [selectedNodes, setSelectedNodes] = useState<string[]>([])

  // Profile and trace state
  const [selectedProfile, setSelectedProfile] = useState<string>('')
  const [targetDebugLevel, setTargetDebugLevel] = useState<DebugLevel>('detailed')

  // Snapshots for before/after
  const [snapshots, setSnapshots] = useState<(TraceSnapshot | SetSnapshot)[]>([])
  const [activeTab, setActiveTab] = useState(0)

  // SSH Session state
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [sessionStatus, setSessionStatus] = useState<'disconnected' | 'connecting' | 'connected' | 'error'>('disconnected')
  const [sessionConnectedNodes, setSessionConnectedNodes] = useState<string[]>([])

  // CUBE debug state
  const [cubeDebugStatus, setCubeDebugStatus] = useState<CubeDebugCategory[]>([])
  const [cubeConnected, setCubeConnected] = useState(false)
  const [cubeRawOutput, setCubeRawOutput] = useState<string | null>(null)

  // Hooks
  const { data: profiles } = useProfiles()
  const getTraceLevelsMutation = useGetTraceLevels()
  const setTraceLevelsMutation = useSetTraceLevels()
  const createSessionMutation = useCreateSession()
  const deleteSessionMutation = useDeleteSession()

  // CUBE debug hooks
  const getCubeDebugStatusMutation = useGetCubeDebugStatus()
  const enableCubeDebugMutation = useEnableCubeDebug()
  const clearCubeDebugMutation = useClearCubeDebug()

  // Filter to only profiles with trace_services
  const traceProfiles = (profiles ?? []).filter(
    (p: LogProfile) => p.trace_services && p.trace_services.length > 0
  )

  // Get services for the selected profile
  const activeProfile = traceProfiles.find((p: LogProfile) => p.name === selectedProfile)
  const activeServices = activeProfile?.trace_services ?? []

  // Cleanup session on page leave
  useEffect(() => {
    const cleanup = () => {
      if (sessionId) {
        // Fire-and-forget: use navigator.sendBeacon or just call delete
        // The backend TTL will clean up even if this fails
        traceService_deleteSession(sessionId)
      }
    }

    window.addEventListener('beforeunload', cleanup)
    return () => {
      window.removeEventListener('beforeunload', cleanup)
      cleanup()
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // Helper: best-effort session cleanup (non-hook)
  const traceService_deleteSession = (sid: string) => {
    try {
      // Use fetch directly for beforeunload (can't use hooks there)
      const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
      fetch(`${baseUrl}/ssh-sessions/${sid}`, { method: 'DELETE', keepalive: true })
    } catch {
      // Ignore errors in cleanup
    }
  }

  const handleToggleNode = (ip: string) => {
    setSelectedNodes(prev =>
      prev.includes(ip) ? prev.filter(n => n !== ip) : [...prev, ip]
    )
  }

  const handleCreateSession = () => {
    if (selectedNodes.length === 0) {
      enqueueSnackbar('No nodes selected', { variant: 'warning' })
      return
    }

    setSessionStatus('connecting')
    createSessionMutation.mutate(
      {
        hosts: selectedNodes,
        username,
        password,
        port,
      },
      {
        onSuccess: (response) => {
          setSessionId(response.session_id)
          setSessionConnectedNodes(response.connected_nodes)
          if (response.connected_nodes.length > 0) {
            setSessionStatus('connected')
            enqueueSnackbar(
              `SSH session ready: ${response.connected_nodes.length} of ${selectedNodes.length} nodes connected`,
              { variant: 'success' }
            )
          } else {
            setSessionStatus('error')
            enqueueSnackbar('Failed to connect to any nodes', { variant: 'error' })
          }
          if (response.failed_nodes.length > 0) {
            for (const fn of response.failed_nodes) {
              enqueueSnackbar(`${fn.host}: ${fn.error || 'Connection failed'}`, { variant: 'warning' })
            }
          }
        },
        onError: (error) => {
          setSessionStatus('error')
          enqueueSnackbar(
            error instanceof Error ? error.message : 'Failed to create SSH session',
            { variant: 'error' }
          )
        },
      }
    )
  }

  const handleDestroySession = () => {
    if (!sessionId) return

    deleteSessionMutation.mutate(sessionId, {
      onSuccess: () => {
        enqueueSnackbar('SSH session disconnected', { variant: 'info' })
        setSessionId(null)
        setSessionStatus('disconnected')
        setSessionConnectedNodes([])
      },
      onError: (error) => {
        enqueueSnackbar(
          error instanceof Error ? error.message : 'Failed to disconnect session',
          { variant: 'error' }
        )
      },
    })
  }

  const handleCheckLevels = () => {
    if (selectedNodes.length === 0) {
      enqueueSnackbar('No nodes selected', { variant: 'warning' })
      return
    }

    getTraceLevelsMutation.mutate(
      {
        hosts: selectedNodes,
        username,
        password,
        port,
        session_id: sessionId ?? undefined,
      },
      {
        onSuccess: (response) => {
          const hasSet = snapshots.some(s => 'level' in s)
          const checkCount = snapshots.filter(s => !('level' in s)).length + 1
          const label = hasSet ? `After Check #${checkCount}` : `Before Check #${checkCount}`

          const snapshot: TraceSnapshot = {
            label,
            timestamp: new Date().toLocaleString(),
            nodes: response.results,
          }
          setSnapshots(prev => [...prev, snapshot])
          setActiveTab(snapshots.length)
          enqueueSnackbar(
            `Trace levels checked on ${response.successful_nodes} of ${response.total_nodes} nodes`,
            { variant: response.successful_nodes > 0 ? 'success' : 'error' }
          )
        },
        onError: (error) => {
          enqueueSnackbar(
            error instanceof Error ? error.message : 'Failed to check trace levels',
            { variant: 'error' }
          )
        },
      }
    )
  }

  const handleSetTraceLevels = () => {
    if (selectedNodes.length === 0) {
      enqueueSnackbar('No nodes selected', { variant: 'warning' })
      return
    }
    if (!selectedProfile || activeServices.length === 0) {
      enqueueSnackbar('Select a collection profile first', { variant: 'warning' })
      return
    }

    setTraceLevelsMutation.mutate(
      {
        hosts: selectedNodes,
        username,
        password,
        port,
        level: targetDebugLevel,
        services: activeServices,
        session_id: sessionId ?? undefined,
      },
      {
        onSuccess: (response) => {
          const snapshot: SetSnapshot = {
            label: `Set ${activeProfile?.name ?? ''} → ${levelLabels[targetDebugLevel]}`,
            timestamp: new Date().toLocaleString(),
            level: targetDebugLevel,
            services: activeServices,
            nodes: response.results,
          }
          setSnapshots(prev => [...prev, snapshot])
          setActiveTab(snapshots.length)
          if (response.successful_nodes > 0) {
            enqueueSnackbar(
              `Trace level set to "${targetDebugLevel}" on ${response.successful_nodes} of ${response.total_nodes} nodes`,
              { variant: 'success' }
            )
          } else {
            enqueueSnackbar(response.message || 'Failed to set trace levels on any nodes', { variant: 'error' })
          }
        },
        onError: (error) => {
          enqueueSnackbar(
            error instanceof Error ? error.message : 'Failed to set trace levels',
            { variant: 'error' }
          )
        },
      }
    )
  }

  const handleDiscover = async () => {
    if (!host || !username || !password) {
      enqueueSnackbar('Please fill in host, username, and password', { variant: 'warning' })
      return
    }

    setIsDiscovering(true)
    setSnapshots([])
    setActiveTab(0)
    // Destroy any existing session when re-discovering
    if (sessionId) {
      try {
        await deleteSessionMutation.mutateAsync(sessionId)
      } catch { /* ignore */ }
      setSessionId(null)
      setSessionStatus('disconnected')
      setSessionConnectedNodes([])
    }
    try {
      const response = await logService.discoverNodes({
        publisher_host: host,
        username,
        password,
        port,
      })
      setDiscoveredNodes(response.nodes)
      setSelectedNodes(response.nodes.map(n => n.ip))
      enqueueSnackbar(`Discovered ${response.nodes.length} cluster nodes`, { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(error instanceof Error ? error.message : 'Discovery failed', { variant: 'error' })
    } finally {
      setIsDiscovering(false)
    }
  }

  // CUBE debug handlers
  const handleCubeCheckStatus = () => {
    if (!host || !username || !password) {
      enqueueSnackbar('Please fill in host, username, and password', { variant: 'warning' })
      return
    }

    getCubeDebugStatusMutation.mutate(
      { host, port, username, password },
      {
        onSuccess: (response) => {
          setCubeDebugStatus(response.categories)
          setCubeConnected(true)
          setCubeRawOutput(response.raw_output ?? null)
          if (response.success) {
            const activeCount = response.categories.filter(c => c.enabled).length
            enqueueSnackbar(
              activeCount > 0
                ? `Found ${activeCount} active debug(s) on ${response.host}`
                : `No active debugs on ${response.host}`,
              { variant: 'success' }
            )
          } else {
            enqueueSnackbar(response.error || 'Failed to check debug status', { variant: 'error' })
          }
        },
        onError: (error) => {
          enqueueSnackbar(error instanceof Error ? error.message : 'Failed to check debug status', { variant: 'error' })
        },
      }
    )
  }

  const handleCubeEnableDebug = (commands: string[]) => {
    if (!host || !username || !password) {
      enqueueSnackbar('Please fill in host, username, and password', { variant: 'warning' })
      return
    }

    enableCubeDebugMutation.mutate(
      { host, port, username, password, commands },
      {
        onSuccess: (response) => {
          if (response.success) {
            enqueueSnackbar(`Enabled ${response.enabled.length} debug command(s) on ${response.host}`, { variant: 'success' })
            handleCubeCheckStatus()
          } else {
            enqueueSnackbar(`Failed: ${response.failed.join(', ')}`, { variant: 'warning' })
          }
        },
        onError: (error) => {
          enqueueSnackbar(error instanceof Error ? error.message : 'Failed to enable debug', { variant: 'error' })
        },
      }
    )
  }

  const handleCubeClearDebug = () => {
    if (!host || !username || !password) {
      enqueueSnackbar('Please fill in host, username, and password', { variant: 'warning' })
      return
    }

    clearCubeDebugMutation.mutate(
      { host, port, username, password },
      {
        onSuccess: (response) => {
          if (response.success) {
            enqueueSnackbar(`Cleared all debugs on ${response.host}`, { variant: 'success' })
            handleCubeCheckStatus()
          } else {
            enqueueSnackbar('Failed to clear debugs', { variant: 'error' })
          }
        },
        onError: (error) => {
          enqueueSnackbar(error instanceof Error ? error.message : 'Failed to clear debugs', { variant: 'error' })
        },
      }
    )
  }

  const isCubeLoading = getCubeDebugStatusMutation.isPending || enableCubeDebugMutation.isPending || clearCubeDebugMutation.isPending

  const generateReport = useCallback(() => {
    const lines: string[] = []
    lines.push('='.repeat(72))
    lines.push('CUCM TRACE LEVEL REPORT')
    lines.push('='.repeat(72))
    lines.push(`Generated: ${new Date().toLocaleString()}`)
    lines.push(`Cluster Publisher: ${host}`)
    lines.push(`Nodes: ${selectedNodes.join(', ')}`)
    if (activeProfile) {
      lines.push(`Collection Profile: ${activeProfile.name} - ${activeProfile.description}`)
      lines.push(`Target Services: ${activeServices.join(', ')}`)
    }
    lines.push('')

    for (const snap of snapshots) {
      lines.push('-'.repeat(72))
      lines.push(`[${snap.timestamp}] ${snap.label}`)
      lines.push('-'.repeat(72))

      if ('level' in snap) {
        const setSnap = snap as SetSnapshot
        lines.push(`Action: Set trace level to ${levelLabels[setSnap.level]}`)
        lines.push(`Services: ${setSnap.services.join(', ')}`)
        lines.push('')
        for (const node of setSnap.nodes) {
          lines.push(`  Node: ${node.host}`)
          lines.push(`  Status: ${node.success ? 'SUCCESS' : 'FAILED'}`)
          if (node.services_updated.length > 0) {
            lines.push(`  Services Updated: ${node.services_updated.join(', ')}`)
          }
          if (node.error) {
            lines.push(`  Error: ${node.error}`)
          }
          if (node.raw_output) {
            lines.push('')
            lines.push('  --- Raw CLI Output ---')
            for (const rl of node.raw_output.split('\n')) {
              lines.push(`  ${rl}`)
            }
            lines.push('  --- End Output ---')
          }
          lines.push('')
        }
      } else {
        const checkSnap = snap as TraceSnapshot
        lines.push('Action: Check current trace levels')
        lines.push('')
        for (const node of checkSnap.nodes) {
          lines.push(`  Node: ${node.host}`)
          lines.push(`  Status: ${node.success ? 'SUCCESS' : 'FAILED'}`)
          if (node.error) {
            lines.push(`  Error: ${node.error}`)
          }
          if (node.services && node.services.length > 0) {
            lines.push('  Trace Tasks:')
            for (const svc of node.services) {
              lines.push(`    ${svc.service_name}: ${svc.current_level}`)
            }
          }
          if (node.raw_output) {
            lines.push('')
            lines.push('  --- Raw CLI Output ---')
            for (const rl of node.raw_output.split('\n')) {
              lines.push(`  ${rl}`)
            }
            lines.push('  --- End Output ---')
          }
          lines.push('')
        }
      }
    }

    lines.push('='.repeat(72))
    lines.push('END OF REPORT')
    lines.push('='.repeat(72))

    return lines.join('\n')
  }, [snapshots, host, selectedNodes, activeProfile, activeServices])

  const handleDownload = () => {
    const report = generateReport()
    const blob = new Blob([report], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const profileTag = activeProfile ? `-${activeProfile.name}` : ''
    a.download = `trace-level-report${profileTag}-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    enqueueSnackbar('Report downloaded', { variant: 'success' })
  }

  const levelLabels: Record<DebugLevel, string> = {
    basic: 'Basic (Informational)',
    detailed: 'Detailed',
    verbose: 'Verbose (Debug)',
  }

  const isAnyLoading = getTraceLevelsMutation.isPending || setTraceLevelsMutation.isPending
  const isSessionLoading = createSessionMutation.isPending || deleteSessionMutation.isPending

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <IconButton onClick={() => navigate('/')}>
            <ArrowBack />
          </IconButton>
          <DebugIcon sx={{ color: 'warning.main', fontSize: 28 }} />
          <Typography variant="h5" fontWeight={600}>
            {deviceMode === 'cucm' ? 'Trace Level Management' : 'Debug Settings'}
          </Typography>
        </Box>
        {deviceMode === 'cucm' && snapshots.length > 0 && (
          <Button
            variant="outlined"
            startIcon={<Download />}
            onClick={handleDownload}
            size="small"
          >
            Download Report
          </Button>
        )}
      </Box>

      {/* Device Type Selector */}
      <Paper
        sx={{
          p: 2,
          mb: 3,
          borderRadius: 3,
          border: theme => `1px solid ${theme.palette.divider}`,
          display: 'flex',
          alignItems: 'center',
          gap: 2,
        }}
      >
        <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
          Device Type
        </Typography>
        <ToggleButtonGroup
          value={deviceMode}
          exclusive
          onChange={(_, val) => {
            if (val) {
              setDeviceMode(val as DeviceMode)
              // Reset form when switching
              setDiscoveredNodes([])
              setSelectedNodes([])
              setSnapshots([])
              setActiveTab(0)
              setCubeDebugStatus([])
              setCubeConnected(false)
              setCubeRawOutput(null)
              setPort(val === 'cucm' ? 22 : 22)
            }
          }}
          size="small"
        >
          <ToggleButton value="cucm" sx={{ px: 2.5 }}>
            <CucmIcon sx={{ mr: 1, fontSize: 20 }} />
            CUCM
          </ToggleButton>
          <ToggleButton value="cube" sx={{ px: 2.5 }}>
            <CubeIcon sx={{ mr: 1, fontSize: 20 }} />
            CUBE / IOS-XE
          </ToggleButton>
        </ToggleButtonGroup>
      </Paper>

      {/* Connection Form */}
      <Paper
        sx={{
          p: 3,
          mb: 3,
          borderRadius: 3,
          border: theme => `1px solid ${theme.palette.divider}`,
        }}
      >
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
          {deviceMode === 'cucm' ? 'CUCM Connection' : 'CUBE Connection'}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          {deviceMode === 'cucm'
            ? 'Enter your CUCM publisher credentials to discover cluster nodes and manage trace levels'
            : 'Enter your CUBE credentials to check and manage IOS-XE debug categories'}
        </Typography>

        <Grid container spacing={2} alignItems="flex-end">
          <Grid item xs={12} sm={4}>
            <TextField
              label={deviceMode === 'cucm' ? 'Publisher Host' : 'CUBE Host'}
              value={host}
              onChange={e => setHost(e.target.value)}
              placeholder="10.1.1.10"
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={12} sm={2}>
            <TextField
              label="Port"
              type="number"
              value={port}
              onChange={e => setPort(Number(e.target.value))}
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={12} sm={2}>
            <TextField
              label="Username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              fullWidth
              size="small"
            />
          </Grid>
          <Grid item xs={12} sm={2}>
            <TextField
              label="Password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              fullWidth
              size="small"
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowPassword(!showPassword)} edge="end" size="small">
                      {showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
          <Grid item xs={12} sm={2}>
            {deviceMode === 'cucm' ? (
              <Button
                variant="contained"
                fullWidth
                startIcon={isDiscovering ? <CircularProgress size={18} color="inherit" /> : <Search />}
                onClick={handleDiscover}
                disabled={isDiscovering || !host || !username || !password}
              >
                {isDiscovering ? 'Discovering...' : 'Discover'}
              </Button>
            ) : (
              <Button
                variant="contained"
                fullWidth
                color="warning"
                startIcon={getCubeDebugStatusMutation.isPending ? <CircularProgress size={18} color="inherit" /> : <Refresh />}
                onClick={handleCubeCheckStatus}
                disabled={isCubeLoading || !host || !username || !password}
              >
                {getCubeDebugStatusMutation.isPending ? 'Checking...' : 'Check Status'}
              </Button>
            )}
          </Grid>
        </Grid>
      </Paper>

      {/* CUBE Debug Content */}
      {deviceMode === 'cube' && (
        <>
          {/* CUBE debug results */}
          {cubeConnected ? (
            <Grid container spacing={3}>
              {/* Left: Current Status */}
              <Grid item xs={12} md={5}>
                <Paper
                  sx={{
                    p: 2,
                    mb: 2,
                    borderRadius: 3,
                    border: theme => `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                    background: theme => theme.palette.mode === 'dark'
                      ? `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.08)} 0%, ${alpha(theme.palette.background.paper, 0.95)} 100%)`
                      : `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.06)} 0%, ${theme.palette.background.paper} 100%)`,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                    <CubeIcon sx={{ color: 'warning.main', fontSize: 22 }} />
                    <Typography variant="subtitle1" fontWeight={600}>
                      Current Debug Status
                    </Typography>
                    <Chip
                      size="small"
                      label={`${cubeDebugStatus.filter(c => c.enabled).length} active`}
                      color={cubeDebugStatus.some(c => c.enabled) ? 'warning' : 'default'}
                      sx={{ ml: 'auto', height: 22, fontSize: '0.7rem' }}
                    />
                  </Box>

                  {cubeDebugStatus.length === 0 ? (
                    <Alert severity="info" variant="outlined" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        No debug categories found. The CUBE has no active debugs.
                      </Typography>
                    </Alert>
                  ) : (
                    <List dense sx={{ bgcolor: 'background.paper', borderRadius: 2, border: '1px solid', borderColor: 'divider', mb: 2 }}>
                      {cubeDebugStatus.map((cat, index) => (
                        <ListItem key={cat.name} divider={index < cubeDebugStatus.length - 1}>
                          <ListItemIcon sx={{ minWidth: 36 }}>
                            {cat.enabled ? (
                              <CheckCircle color="success" sx={{ fontSize: 20 }} />
                            ) : (
                              <ErrorIcon color="disabled" sx={{ fontSize: 20 }} />
                            )}
                          </ListItemIcon>
                          <ListItemText
                            primary={cat.name}
                            primaryTypographyProps={{ variant: 'body2', fontWeight: 500 }}
                          />
                          <Chip
                            size="small"
                            label={cat.enabled ? 'ON' : 'OFF'}
                            color={cat.enabled ? 'success' : 'default'}
                            sx={{ height: 22, fontSize: '0.7rem', fontWeight: 600 }}
                          />
                        </ListItem>
                      ))}
                    </List>
                  )}

                  <Button
                    variant="outlined"
                    fullWidth
                    size="small"
                    startIcon={getCubeDebugStatusMutation.isPending ? <CircularProgress size={16} color="inherit" /> : <Refresh />}
                    onClick={handleCubeCheckStatus}
                    disabled={isCubeLoading}
                  >
                    {getCubeDebugStatusMutation.isPending ? 'Refreshing...' : 'Refresh Status'}
                  </Button>
                </Paper>

                {/* Quick Actions */}
                <Paper
                  sx={{
                    p: 2,
                    borderRadius: 3,
                    border: theme => `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                    <DebugIcon sx={{ color: 'warning.main', fontSize: 20 }} />
                    <Typography variant="subtitle2" fontWeight={600}>Quick Actions</Typography>
                  </Box>

                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                    <Button
                      variant="outlined"
                      color="warning"
                      fullWidth
                      startIcon={enableCubeDebugMutation.isPending ? <CircularProgress size={18} color="inherit" /> : <PlayArrow />}
                      onClick={() => handleCubeEnableDebug(['debug ccsip messages'])}
                      disabled={isCubeLoading}
                    >
                      Enable SIP Debug
                    </Button>

                    <Button
                      variant="outlined"
                      color="warning"
                      fullWidth
                      startIcon={enableCubeDebugMutation.isPending ? <CircularProgress size={18} color="inherit" /> : <PlayArrow />}
                      onClick={() => handleCubeEnableDebug([
                        'debug ccsip messages',
                        'debug voip ccapi inout',
                        'debug voip dialpeer',
                      ])}
                      disabled={isCubeLoading}
                    >
                      Enable Full Voice Debug
                    </Button>

                    <Divider sx={{ my: 0.5 }} />

                    <Button
                      variant="contained"
                      color="error"
                      fullWidth
                      startIcon={clearCubeDebugMutation.isPending ? <CircularProgress size={18} color="inherit" /> : <Stop />}
                      onClick={handleCubeClearDebug}
                      disabled={isCubeLoading}
                    >
                      Clear All Debugs
                    </Button>
                  </Box>

                  <Alert severity="warning" sx={{ mt: 2 }} variant="outlined">
                    <Typography variant="caption">
                      Active debugs consume CPU resources. Always clear debugs after troubleshooting
                      to avoid performance degradation on the CUBE.
                    </Typography>
                  </Alert>
                </Paper>
              </Grid>

              {/* Right: Raw output */}
              <Grid item xs={12} md={7}>
                {isCubeLoading && (
                  <Paper sx={{ p: 2, mb: 2, borderRadius: 3 }}>
                    <LinearProgress color="warning" />
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: 'center' }}>
                      Connecting to CUBE and executing command...
                    </Typography>
                  </Paper>
                )}

                {cubeRawOutput && (
                  <Paper sx={{ p: 2, borderRadius: 3 }}>
                    <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                      Raw CLI Output
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                      Output from <code>show debug</code> on {host}
                    </Typography>
                    <Box
                      component="pre"
                      sx={{
                        p: 1.5,
                        bgcolor: 'grey.900',
                        color: 'grey.100',
                        borderRadius: 1,
                        fontSize: '0.75rem',
                        fontFamily: 'monospace',
                        overflow: 'auto',
                        maxHeight: 400,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        border: '1px solid',
                        borderColor: 'grey.700',
                      }}
                    >
                      {cubeRawOutput}
                    </Box>
                  </Paper>
                )}

                {!cubeRawOutput && !isCubeLoading && (
                  <Paper sx={{ p: 4, textAlign: 'center', borderRadius: 3, border: '1px dashed', borderColor: 'divider' }}>
                    <DebugIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
                    <Typography variant="h6" color="text.secondary" gutterBottom>
                      CUBE Debug Workflow
                    </Typography>
                    <Box sx={{ textAlign: 'left', maxWidth: 420, mx: 'auto', mt: 2 }}>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        1. <strong>Check Status</strong> - See which debug categories are currently active
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        2. <strong>Enable Debug</strong> - Turn on SIP or full voice debug before reproducing the issue
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        3. <strong>Reproduce Issue</strong> - Make test calls or wait for the problem to occur
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        4. <strong>Collect Logs</strong> - Go to Call Routing to collect the debug output
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        5. <strong>Clear Debugs</strong> - Always disable debugs after troubleshooting
                      </Typography>
                    </Box>
                  </Paper>
                )}
              </Grid>
            </Grid>
          ) : (
            // CUBE empty state
            <Paper sx={{ p: 6, textAlign: 'center', borderRadius: 3 }}>
              <CubeIcon sx={{ fontSize: 64, color: 'text.disabled', mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                Connect to CUBE
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Enter your CUBE credentials above and click Check Status to view active debug categories
              </Typography>
            </Paper>
          )}
        </>
      )}

      {/* CUCM Main Content */}
      {deviceMode === 'cucm' && discoveredNodes.length > 0 && (
        <Grid container spacing={3}>
          {/* Left Column: Nodes + Session + Profile + Actions */}
          <Grid item xs={12} md={4}>
            {/* Discovered Nodes */}
            <Paper
              sx={{
                p: 2,
                mb: 2,
                borderRadius: 3,
                border: theme => `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <CucmIcon sx={{ color: 'primary.main', fontSize: 22 }} />
                <Typography variant="subtitle1" fontWeight={600}>
                  Cluster Nodes ({discoveredNodes.length})
                </Typography>
                <Chip
                  size="small"
                  label={`${selectedNodes.length} selected`}
                  color="primary"
                  sx={{ ml: 'auto', height: 22, fontSize: '0.7rem' }}
                />
              </Box>

              {discoveredNodes.map(node => {
                const isSelected = selectedNodes.includes(node.ip)
                const isPublisher = node.role?.toLowerCase() === 'publisher'
                const isConnected = sessionConnectedNodes.includes(node.ip)
                return (
                  <Box
                    key={node.ip}
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                      p: 1,
                      mb: 0.5,
                      borderRadius: 1.5,
                      bgcolor: isSelected
                        ? isPublisher ? alpha('#ff9800', 0.08) : alpha('#1976d2', 0.06)
                        : 'transparent',
                      border: '1px solid',
                      borderColor: isSelected
                        ? isPublisher ? alpha('#ff9800', 0.3) : alpha('#1976d2', 0.2)
                        : 'divider',
                      cursor: sessionStatus === 'connected' ? 'default' : 'pointer',
                      '&:hover': { bgcolor: alpha('#1976d2', 0.04) },
                    }}
                    onClick={() => sessionStatus !== 'connected' && handleToggleNode(node.ip)}
                  >
                    <Checkbox
                      size="small"
                      checked={isSelected}
                      disabled={sessionStatus === 'connected'}
                      sx={{ p: 0.25 }}
                    />
                    {isPublisher ? (
                      <Star sx={{ fontSize: 16, color: '#ff9800' }} />
                    ) : (
                      <Computer sx={{ fontSize: 16, color: isSelected ? '#1976d2' : 'text.disabled' }} />
                    )}
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="body2" fontWeight={isSelected ? 600 : 400}>
                        {node.host}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}>
                        {node.ip}
                      </Typography>
                    </Box>
                    {isPublisher && (
                      <Chip size="small" label="Publisher" sx={{ height: 20, fontSize: '0.65rem', bgcolor: alpha('#ff9800', 0.15), color: '#ed6c02' }} />
                    )}
                    {sessionStatus === 'connected' && isConnected && (
                      <Chip size="small" label="SSH" color="success" sx={{ height: 20, fontSize: '0.65rem' }} />
                    )}
                  </Box>
                )
              })}
            </Paper>

            {/* SSH Session Control */}
            <Paper
              sx={{
                p: 2,
                mb: 2,
                borderRadius: 3,
                border: theme => `1px solid ${alpha(
                  sessionStatus === 'connected' ? theme.palette.success.main
                  : sessionStatus === 'error' ? theme.palette.error.main
                  : theme.palette.divider, 0.4
                )}`,
                background: theme => sessionStatus === 'connected'
                  ? `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.06)} 0%, ${theme.palette.background.paper} 100%)`
                  : theme.palette.background.paper,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
                {sessionStatus === 'connected'
                  ? <LinkIcon sx={{ color: 'success.main', fontSize: 20 }} />
                  : <LinkOff sx={{ color: 'text.secondary', fontSize: 20 }} />
                }
                <Typography variant="subtitle2" fontWeight={600}>
                  SSH Session
                </Typography>
                {sessionStatus === 'connected' && (
                  <Chip
                    size="small"
                    label={`${sessionConnectedNodes.length} connected`}
                    color="success"
                    sx={{ ml: 'auto', height: 22, fontSize: '0.7rem' }}
                  />
                )}
                {sessionStatus === 'connecting' && (
                  <CircularProgress size={16} sx={{ ml: 'auto' }} />
                )}
              </Box>

              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
                {sessionStatus === 'connected'
                  ? 'Persistent connections active. Trace operations will be fast.'
                  : sessionStatus === 'connecting'
                  ? 'Connecting to nodes...'
                  : 'Connect once, then run multiple checks/sets without reconnecting.'}
              </Typography>

              {sessionStatus === 'connected' ? (
                <Button
                  variant="outlined"
                  fullWidth
                  color="error"
                  size="small"
                  startIcon={deleteSessionMutation.isPending ? <CircularProgress size={16} color="inherit" /> : <LinkOff />}
                  onClick={handleDestroySession}
                  disabled={isSessionLoading || isAnyLoading}
                >
                  Disconnect
                </Button>
              ) : (
                <Button
                  variant="contained"
                  fullWidth
                  color="success"
                  size="small"
                  startIcon={createSessionMutation.isPending ? <CircularProgress size={16} color="inherit" /> : <LinkIcon />}
                  onClick={handleCreateSession}
                  disabled={isSessionLoading || selectedNodes.length === 0 || !username || !password}
                >
                  {createSessionMutation.isPending ? 'Connecting...' : 'Connect SSH Session'}
                </Button>
              )}

              {sessionStatus === 'error' && (
                <Alert severity="error" sx={{ mt: 1 }} variant="outlined">
                  <Typography variant="caption">
                    Session failed. You can still use trace operations without a session (slower).
                  </Typography>
                </Alert>
              )}
            </Paper>

            {/* Profile Selection + Actions */}
            <Paper
              sx={{
                p: 2,
                borderRadius: 3,
                border: theme => `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                background: theme => theme.palette.mode === 'dark'
                  ? `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.08)} 0%, ${alpha(theme.palette.background.paper, 0.95)} 100%)`
                  : `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.06)} 0%, ${theme.palette.background.paper} 100%)`,
              }}
            >
              {/* Profile Selector */}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <FolderOpen sx={{ color: 'warning.main', fontSize: 20 }} />
                <Typography variant="subtitle2" fontWeight={600}>Collection Profile</Typography>
              </Box>

              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>Select Profile</InputLabel>
                <Select
                  value={selectedProfile}
                  label="Select Profile"
                  onChange={e => setSelectedProfile(e.target.value)}
                >
                  {traceProfiles.map((p: LogProfile) => (
                    <MenuItem key={p.name} value={p.name}>
                      <Box>
                        <Typography variant="body2" fontWeight={500}>
                          {p.name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {p.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {/* Services for selected profile */}
              {activeServices.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                    Services to configure:
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {activeServices.map(svc => (
                      <Chip
                        key={svc}
                        size="small"
                        label={svc}
                        color="warning"
                        variant="outlined"
                        sx={{ height: 24, fontSize: '0.75rem' }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {activeProfile && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                    Log paths collected:
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                    {activeProfile.logTypes.map((path: string) => (
                      <Chip
                        key={path}
                        size="small"
                        label={path}
                        variant="outlined"
                        sx={{ height: 22, fontSize: '0.7rem', fontFamily: 'monospace' }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              <Divider sx={{ my: 2 }} />

              {/* Check Levels Button */}
              <Tooltip title={selectedNodes.length === 0 ? 'Select at least one node' : 'Query current trace task levels from CUCM CLI'}>
                <span>
                  <Button
                    variant="outlined"
                    fullWidth
                    color="info"
                    startIcon={getTraceLevelsMutation.isPending ? <CircularProgress size={18} color="inherit" /> : <Preview />}
                    onClick={handleCheckLevels}
                    disabled={isAnyLoading || selectedNodes.length === 0}
                    sx={{ mb: 2 }}
                  >
                    {getTraceLevelsMutation.isPending
                      ? `Checking ${selectedNodes.length} node${selectedNodes.length !== 1 ? 's' : ''}...`
                      : 'Check Current Levels'}
                  </Button>
                </span>
              </Tooltip>

              <Divider sx={{ my: 2 }} />

              {/* Set Level Controls */}
              <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                <InputLabel>Target Debug Level</InputLabel>
                <Select
                  value={targetDebugLevel}
                  label="Target Debug Level"
                  onChange={e => setTargetDebugLevel(e.target.value as DebugLevel)}
                >
                  <MenuItem value="basic">Basic (Informational)</MenuItem>
                  <MenuItem value="detailed">Detailed - TAC Recommended</MenuItem>
                  <MenuItem value="verbose">Verbose (Debug)</MenuItem>
                </Select>
              </FormControl>

              <Tooltip title={
                selectedNodes.length === 0 ? 'Select at least one node'
                : !selectedProfile ? 'Select a collection profile first'
                : ''
              }>
                <span>
                  <Button
                    variant="contained"
                    fullWidth
                    color="warning"
                    startIcon={setTraceLevelsMutation.isPending ? <CircularProgress size={18} color="inherit" /> : <SaveIcon />}
                    onClick={handleSetTraceLevels}
                    disabled={isAnyLoading || selectedNodes.length === 0 || !selectedProfile}
                  >
                    {setTraceLevelsMutation.isPending
                      ? `Applying to ${selectedNodes.length} node${selectedNodes.length !== 1 ? 's' : ''}...`
                      : `Apply "${levelLabels[targetDebugLevel]}"`}
                  </Button>
                </span>
              </Tooltip>

              {targetDebugLevel !== 'basic' && !isAnyLoading && (
                <Alert severity="warning" sx={{ mt: 2 }} variant="outlined">
                  <Typography variant="caption">
                    Higher trace levels may impact performance. Reset to Basic after troubleshooting.
                  </Typography>
                </Alert>
              )}
            </Paper>
          </Grid>

          {/* Right Column: Results */}
          <Grid item xs={12} md={8}>
            {/* Progress indicator */}
            {isAnyLoading && (
              <Paper sx={{ p: 2, mb: 2, borderRadius: 3 }}>
                <LinearProgress color={setTraceLevelsMutation.isPending ? 'warning' : 'info'} />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1, textAlign: 'center' }}>
                  {setTraceLevelsMutation.isPending
                    ? sessionStatus === 'connected'
                      ? 'Applying trace levels in parallel using persistent session...'
                      : 'Applying trace levels... This may take 1-2 minutes per node.'
                    : sessionStatus === 'connected'
                      ? 'Querying trace levels in parallel using persistent session...'
                      : 'Querying trace levels... This may take 1-2 minutes per node.'}
                </Typography>
              </Paper>
            )}

            {/* Workflow guide when no snapshots */}
            {snapshots.length === 0 && !isAnyLoading && (
              <Paper sx={{ p: 4, textAlign: 'center', borderRadius: 3, border: '1px dashed', borderColor: 'divider' }}>
                <DebugIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  Trace Level Workflow
                </Typography>
                <Box sx={{ textAlign: 'left', maxWidth: 420, mx: 'auto', mt: 2 }}>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    1. <strong>Connect SSH Session</strong> - Establish persistent connections to all nodes (avoids repeated 60-120s CLI startup)
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    2. <strong>Select a Collection Profile</strong> - This determines which CUCM services will have their trace levels changed
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    3. <strong>Check Current Levels</strong> - Capture the current state as a "before" snapshot
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    4. <strong>Apply New Level</strong> - Set the desired trace level (e.g. Detailed for TAC)
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    5. <strong>Check Again</strong> - Capture the new state as an "after" snapshot
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    6. <strong>Download Report</strong> - Save all snapshots as proof with raw CLI output
                  </Typography>
                </Box>
              </Paper>
            )}

            {/* Snapshot tabs and content */}
            {snapshots.length > 0 && (
              <Paper sx={{ borderRadius: 3, overflow: 'hidden' }}>
                <Tabs
                  value={activeTab < snapshots.length ? activeTab : 0}
                  onChange={(_, v) => setActiveTab(v)}
                  variant="scrollable"
                  scrollButtons="auto"
                  sx={{ borderBottom: 1, borderColor: 'divider', bgcolor: 'action.hover' }}
                >
                  {snapshots.map((snap, idx) => (
                    <Tab
                      key={idx}
                      label={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          {'level' in snap ? (
                            <SaveIcon sx={{ fontSize: 14, color: 'warning.main' }} />
                          ) : (
                            <Preview sx={{ fontSize: 14, color: 'info.main' }} />
                          )}
                          <Typography variant="caption" fontWeight={600}>
                            {snap.label}
                          </Typography>
                        </Box>
                      }
                    />
                  ))}
                </Tabs>

                {snapshots.map((snap, idx) => (
                  <Box
                    key={idx}
                    role="tabpanel"
                    hidden={activeTab !== idx}
                    sx={{ p: 2 }}
                  >
                    {activeTab === idx && (
                      <>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                          <Typography variant="subtitle2" color="text.secondary">
                            {snap.timestamp}
                          </Typography>
                          {'level' in snap && (
                            <Box sx={{ display: 'flex', gap: 1 }}>
                              <Chip
                                size="small"
                                label={levelLabels[(snap as SetSnapshot).level]}
                                color="warning"
                                variant="outlined"
                              />
                            </Box>
                          )}
                        </Box>

                        {'level' in snap ? (
                          // Set results
                          <>
                            {/* Show which services were targeted */}
                            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 2 }}>
                              {(snap as SetSnapshot).services.map(svc => (
                                <Chip key={svc} size="small" label={svc} color="warning" variant="outlined" sx={{ height: 24, fontSize: '0.75rem' }} />
                              ))}
                            </Box>
                            {(() => {
                              const s = snap as SetSnapshot
                              const successCount = s.nodes.filter(n => n.success).length
                              return (
                                <Alert
                                  severity={successCount === s.nodes.length ? 'success' : successCount > 0 ? 'warning' : 'error'}
                                  sx={{ mb: 2 }}
                                >
                                  Applied to {successCount} of {s.nodes.length} nodes
                                </Alert>
                              )
                            })()}
                            <List dense sx={{ bgcolor: 'background.default', borderRadius: 2, border: '1px solid', borderColor: 'divider', mb: 2 }}>
                              {(snap as SetSnapshot).nodes.map((node, ni) => (
                                <ListItem key={node.host} divider={ni < (snap as SetSnapshot).nodes.length - 1}>
                                  <ListItemIcon sx={{ minWidth: 32 }}>
                                    {node.success ? <CheckCircle color="success" sx={{ fontSize: 20 }} /> : <ErrorIcon color="error" sx={{ fontSize: 20 }} />}
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={<Typography variant="body2" fontWeight={500}>{node.host}</Typography>}
                                    secondary={
                                      node.success
                                        ? <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                                            {node.services_updated.map(s => (
                                              <Chip key={s} size="small" label={s} color="success" variant="outlined" sx={{ height: 22, fontSize: '0.7rem' }} />
                                            ))}
                                          </Box>
                                        : <Typography variant="caption" color="error">{node.error}</Typography>
                                    }
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </>
                        ) : (
                          // Check results
                          <>
                            {(() => {
                              const c = snap as TraceSnapshot
                              const successCount = c.nodes.filter(n => n.success).length
                              return (
                                <Alert
                                  severity={successCount === c.nodes.length ? 'info' : successCount > 0 ? 'warning' : 'error'}
                                  sx={{ mb: 2 }}
                                >
                                  Checked {successCount} of {c.nodes.length} nodes
                                </Alert>
                              )
                            })()}
                            {(snap as TraceSnapshot).nodes.map(node => (
                              <Box key={node.host} sx={{ mb: 2 }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                                  {node.success ? <CheckCircle color="success" sx={{ fontSize: 18 }} /> : <ErrorIcon color="error" sx={{ fontSize: 18 }} />}
                                  <Typography variant="body2" fontWeight={600}>{node.host}</Typography>
                                </Box>
                                {node.services && node.services.length > 0 && (
                                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1, ml: 3.5 }}>
                                    {node.services.map(svc => (
                                      <Chip
                                        key={svc.service_name}
                                        size="small"
                                        label={`${svc.service_name}: ${svc.current_level}`}
                                        variant="outlined"
                                        color={svc.current_level === 'Unknown' ? 'default' : 'info'}
                                        sx={{ height: 24, fontSize: '0.75rem' }}
                                      />
                                    ))}
                                  </Box>
                                )}
                                {node.error && (
                                  <Typography variant="caption" color="error" sx={{ ml: 3.5 }}>
                                    {node.error}
                                  </Typography>
                                )}
                              </Box>
                            ))}
                          </>
                        )}

                        {/* Raw output section */}
                        {(() => {
                          const nodes = 'level' in snap
                            ? (snap as SetSnapshot).nodes
                            : (snap as TraceSnapshot).nodes
                          const hasRaw = nodes.some(n => n.raw_output)
                          if (!hasRaw) return null

                          return (
                            <>
                              <Divider sx={{ my: 2 }} />
                              <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                                Raw CLI Output
                              </Typography>
                              {nodes.map(node => (
                                node.raw_output ? (
                                  <Box key={node.host} sx={{ mb: 2 }}>
                                    <Typography variant="caption" fontWeight={600} color="text.secondary">
                                      {node.host}
                                    </Typography>
                                    <Box
                                      component="pre"
                                      sx={{
                                        mt: 0.5,
                                        p: 1.5,
                                        bgcolor: 'grey.900',
                                        color: 'grey.100',
                                        borderRadius: 1,
                                        fontSize: '0.75rem',
                                        fontFamily: 'monospace',
                                        overflow: 'auto',
                                        maxHeight: 300,
                                        whiteSpace: 'pre-wrap',
                                        wordBreak: 'break-all',
                                        border: '1px solid',
                                        borderColor: 'grey.700',
                                      }}
                                    >
                                      {node.raw_output}
                                    </Box>
                                  </Box>
                                ) : null
                              ))}
                            </>
                          )
                        })()}
                      </>
                    )}
                  </Box>
                ))}
              </Paper>
            )}
          </Grid>
        </Grid>
      )}

      {/* CUCM Empty state when no nodes discovered */}
      {deviceMode === 'cucm' && discoveredNodes.length === 0 && !isDiscovering && (
        <Paper sx={{ p: 6, textAlign: 'center', borderRadius: 3 }}>
          <DebugIcon sx={{ fontSize: 64, color: 'text.disabled', mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            Connect to CUCM
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Enter your CUCM publisher credentials above and click Discover to find cluster nodes
          </Typography>
        </Paper>
      )}
    </Box>
  )
}
