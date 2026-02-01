import { useState } from 'react'
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
  Checkbox,
  Alert,
  Tooltip,
  alpha,
} from '@mui/material'
import {
  Visibility,
  VisibilityOff,
  ArrowBack,
  CheckCircle,
  Error as ErrorIcon,
  Refresh,
  BugReport as DebugIcon,
  Info as InfoIcon,
  Save as SaveIcon,
  Dns as CucmIcon,
  Star,
  Computer,
  Warning as WarningIcon,
  Edit as EditIcon,
  Delete,
  Search,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { logService } from '@/services'
import { useGetTraceLevels, useSetTraceLevels } from '@/hooks'
import type { TraceLevelNodeResult } from '@/services/traceService'
import type { ClusterNode, DebugLevel } from '@/types'

interface CucmDevice {
  host: string
  port: number
  username: string
  password: string
  discoveredNodes?: ClusterNode[]
  selectedNodes?: string[]
  nodeIpOverrides?: Record<string, string>
}

export default function TraceLevel() {
  const navigate = useNavigate()
  const { enqueueSnackbar } = useSnackbar()

  // Device state
  const [device, setDevice] = useState<CucmDevice | null>(null)
  const [isDiscovering, setIsDiscovering] = useState(false)

  // Form fields
  const [host, setHost] = useState('')
  const [port, setPort] = useState(22)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  // IP editing state
  const [editingIp, setEditingIp] = useState<{ originalIp: string; currentIp: string } | null>(null)

  // Trace level state
  const [traceLevels, setTraceLevels] = useState<TraceLevelNodeResult[]>([])
  const [targetDebugLevel, setTargetDebugLevel] = useState<DebugLevel>('basic')
  const [lastApplyResult, setLastApplyResult] = useState<{ success: boolean; message: string } | null>(null)

  // Hooks
  const getTraceLevelsMutation = useGetTraceLevels()
  const setTraceLevelsMutation = useSetTraceLevels()

  // Map trace level names to chip colors
  // CUCM CLI levels (least to most verbose): Error < Special < State_Transition < Significant < Entry_exit < Arbitrary < Detailed
  const getTraceLevelChipColor = (level: string): 'error' | 'warning' | 'info' | 'success' | 'default' => {
    const lvl = level.toLowerCase()
    if (lvl.includes('error')) return 'error'
    if (lvl === 'special' || lvl === 'state_transition') return 'default'
    if (lvl === 'significant' || lvl === 'entry_exit') return 'info'
    if (lvl === 'arbitrary') return 'warning'
    if (lvl === 'detailed') return 'success'
    if (lvl === 'unknown') return 'default'
    return 'default'
  }

  // Format trace level label for display - extract short task name from "Display Name (task)"
  const getTraceLevelLabel = (serviceName: string, level: string): string => {
    const match = serviceName.match(/\((\w+)\)/)
    const shortName = match ? match[1] : serviceName
    return `${shortName}: ${level}`
  }

  const handleConnect = async () => {
    if (!host || !username || !password) {
      enqueueSnackbar('Please fill in all required fields', { variant: 'warning' })
      return
    }

    const newDevice: CucmDevice = { host, port, username, password }
    setDevice(newDevice)
    setTraceLevels([])
    setIsDiscovering(true)

    try {
      const response = await logService.discoverNodes({
        publisher_host: host,
        username,
        password,
        port,
      })

      const initialOverrides: Record<string, string> = {}
      response.nodes.forEach(n => {
        initialOverrides[n.ip] = n.ip
      })

      setDevice({
        ...newDevice,
        discoveredNodes: response.nodes,
        selectedNodes: response.nodes.map(n => n.ip),
        nodeIpOverrides: initialOverrides,
      })

      enqueueSnackbar(`Discovered ${response.nodes.length} nodes`, { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(error instanceof Error ? error.message : 'Discovery failed', { variant: 'error' })
      setDevice(null)
    } finally {
      setIsDiscovering(false)
    }
  }

  const handleDisconnect = () => {
    setDevice(null)
    setTraceLevels([])
  }

  const handleToggleNode = (nodeIp: string) => {
    if (!device) return
    setDevice({
      ...device,
      selectedNodes: device.selectedNodes?.includes(nodeIp)
        ? device.selectedNodes.filter(ip => ip !== nodeIp)
        : [...(device.selectedNodes || []), nodeIp],
    })
  }

  const handleIpOverride = (originalIp: string, newIp: string) => {
    if (!device) return
    setDevice({
      ...device,
      nodeIpOverrides: { ...device.nodeIpOverrides, [originalIp]: newIp },
    })
  }

  const getEffectiveIp = (originalIp: string): string => {
    return device?.nodeIpOverrides?.[originalIp] || originalIp
  }

  const isIpModified = (originalIp: string): boolean => {
    return getEffectiveIp(originalIp) !== originalIp
  }

  const getEffectiveHosts = (): string[] => {
    if (!device?.selectedNodes) return []
    return device.selectedNodes.map(originalIp =>
      device.nodeIpOverrides?.[originalIp] || originalIp
    )
  }

  const handleFetchTraceLevels = () => {
    if (!device?.selectedNodes?.length) {
      enqueueSnackbar('No nodes selected', { variant: 'warning' })
      return
    }

    getTraceLevelsMutation.mutate(
      {
        hosts: getEffectiveHosts(),
        username: device.username,
        password: device.password,
        port: device.port,
      },
      {
        onSuccess: (response) => {
          setTraceLevels(response.results)
          enqueueSnackbar(
            `Retrieved trace levels from ${response.successful_nodes} of ${response.total_nodes} nodes`,
            { variant: 'success' }
          )
        },
        onError: (error) => {
          enqueueSnackbar(error instanceof Error ? error.message : 'Failed to fetch trace levels', { variant: 'error' })
        },
      }
    )
  }

  const handleSetTraceLevels = () => {
    if (!device?.selectedNodes?.length) {
      enqueueSnackbar('No nodes selected', { variant: 'warning' })
      return
    }

    setLastApplyResult(null)

    setTraceLevelsMutation.mutate(
      {
        hosts: getEffectiveHosts(),
        username: device.username,
        password: device.password,
        port: device.port,
        level: targetDebugLevel,
      },
      {
        onSuccess: (response) => {
          if (response.successful_nodes > 0) {
            setLastApplyResult({
              success: true,
              message: `Successfully applied "${targetDebugLevel}" trace level to ${response.successful_nodes} of ${response.total_nodes} node(s)`,
            })
            handleFetchTraceLevels()
          } else {
            setLastApplyResult({
              success: false,
              message: response.message || 'Failed to set trace levels on any nodes',
            })
          }
        },
        onError: (error) => {
          setLastApplyResult({
            success: false,
            message: error instanceof Error ? error.message : 'Failed to set trace levels',
          })
        },
      }
    )
  }

  const hasNodes = device?.discoveredNodes && device.discoveredNodes.length > 0

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <IconButton onClick={() => navigate('/')}>
            <ArrowBack />
          </IconButton>
          <DebugIcon sx={{ color: 'warning.main', fontSize: 28 }} />
          <Typography variant="h5" fontWeight={600}>Trace Level Configuration</Typography>
        </Box>
      </Box>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          Configure CUCM trace levels <strong>before</strong> reproducing the issue.
          After changing trace levels, wait for the issue to occur, then collect logs from the
          <strong> Call Routing</strong> tab.
        </Typography>
      </Alert>

      {/* Step 1: Connect to CUCM */}
      <Paper
        sx={{
          p: 3,
          mb: 3,
          borderRadius: 3,
          border: theme => `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
          background: theme => theme.palette.mode === 'dark'
            ? `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.08)} 0%, ${alpha(theme.palette.background.paper, 0.95)} 100%)`
            : `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.04)} 0%, ${theme.palette.background.paper} 100%)`,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2.5 }}>
          <Box sx={{ width: 8, height: 28, borderRadius: 1, bgcolor: 'primary.main' }} />
          <CucmIcon sx={{ color: 'primary.main', fontSize: 24 }} />
          <Typography variant="h6" fontWeight={600}>
            {hasNodes ? 'CUCM Cluster' : 'Connect to CUCM Publisher'}
          </Typography>
          {hasNodes && (
            <Chip
              size="small"
              label={`${device.discoveredNodes!.length} nodes`}
              color="success"
              sx={{ ml: 1 }}
            />
          )}
        </Box>

        {!hasNodes ? (
          <Grid container spacing={2} alignItems="flex-end">
            <Grid item xs={12} sm={4}>
              <TextField
                label="Publisher Host"
                value={host}
                onChange={e => setHost(e.target.value)}
                placeholder="10.1.1.10"
                fullWidth
                size="small"
                disabled={isDiscovering}
              />
            </Grid>
            <Grid item xs={6} sm={2}>
              <TextField
                label="Port"
                type="number"
                value={port}
                onChange={e => setPort(Number(e.target.value))}
                fullWidth
                size="small"
                disabled={isDiscovering}
              />
            </Grid>
            <Grid item xs={12} sm={3}>
              <TextField
                label="Username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                fullWidth
                size="small"
                disabled={isDiscovering}
              />
            </Grid>
            <Grid item xs={12} sm={3}>
              <TextField
                label="Password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                fullWidth
                size="small"
                disabled={isDiscovering}
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
            <Grid item xs={12}>
              <Button
                variant="contained"
                startIcon={isDiscovering ? <CircularProgress size={20} color="inherit" /> : <Search />}
                onClick={handleConnect}
                disabled={isDiscovering || !host || !username || !password}
              >
                {isDiscovering ? 'Discovering Nodes...' : 'Connect & Discover'}
              </Button>
            </Grid>
          </Grid>
        ) : (
          <Box>
            {/* Connection info */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <Chip
                size="small"
                label={device.host}
                icon={<CucmIcon sx={{ fontSize: 16 }} />}
                sx={{ bgcolor: alpha('#1976d2', 0.1) }}
              />
              <Chip size="small" label={`Port ${device.port}`} variant="outlined" />
              <Chip size="small" label={device.username} variant="outlined" />
              <Button
                size="small"
                color="error"
                startIcon={<Delete sx={{ fontSize: 16 }} />}
                onClick={handleDisconnect}
              >
                Disconnect
              </Button>
            </Box>

            {/* Node list */}
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {device.discoveredNodes!.map(node => {
                const isSelected = device.selectedNodes?.includes(node.ip) || false
                const isPublisher = node.role?.toLowerCase() === 'publisher'
                const effectiveIp = getEffectiveIp(node.ip)
                const ipModified = isIpModified(node.ip)
                const isEditing = editingIp?.originalIp === node.ip

                return (
                  <Box
                    key={node.ip}
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 0.5,
                      p: 0.75,
                      borderRadius: 1.5,
                      bgcolor: isSelected
                        ? isPublisher ? alpha('#ff9800', 0.08) : alpha('#1976d2', 0.06)
                        : 'transparent',
                      border: '1px solid',
                      borderColor: isSelected
                        ? isPublisher ? alpha('#ff9800', 0.3) : alpha('#1976d2', 0.2)
                        : 'divider',
                      minWidth: 220,
                    }}
                  >
                    <Checkbox
                      size="small"
                      checked={isSelected}
                      onChange={() => handleToggleNode(node.ip)}
                      sx={{ p: 0.25 }}
                    />
                    {isPublisher ? (
                      <Star sx={{ fontSize: 14, color: '#ff9800' }} />
                    ) : (
                      <Computer sx={{ fontSize: 14, color: isSelected ? '#1976d2' : 'text.disabled' }} />
                    )}
                    <Typography
                      variant="caption"
                      sx={{
                        fontWeight: isSelected ? 600 : 400,
                        color: isSelected ? 'text.primary' : 'text.secondary',
                        minWidth: 60,
                      }}
                    >
                      {node.host}
                    </Typography>

                    {isEditing ? (
                      <TextField
                        size="small"
                        value={editingIp.currentIp}
                        onChange={(e) => setEditingIp({ ...editingIp, currentIp: e.target.value })}
                        onBlur={() => {
                          handleIpOverride(node.ip, editingIp.currentIp)
                          setEditingIp(null)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            handleIpOverride(node.ip, editingIp.currentIp)
                            setEditingIp(null)
                          } else if (e.key === 'Escape') {
                            setEditingIp(null)
                          }
                        }}
                        autoFocus
                        sx={{
                          flex: 1,
                          '& .MuiInputBase-input': { fontSize: '0.7rem', py: 0.25, px: 0.5 },
                        }}
                      />
                    ) : (
                      <Box
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 0.5,
                          flex: 1,
                          cursor: 'pointer',
                          '&:hover': { bgcolor: alpha('#000', 0.04) },
                          borderRadius: 0.5,
                          px: 0.5,
                        }}
                        onClick={() => setEditingIp({ originalIp: node.ip, currentIp: effectiveIp })}
                      >
                        <Typography
                          variant="caption"
                          sx={{
                            fontFamily: 'monospace',
                            fontSize: '0.65rem',
                            color: ipModified ? 'warning.main' : 'text.secondary',
                          }}
                        >
                          {effectiveIp}
                        </Typography>
                        {ipModified && <WarningIcon sx={{ fontSize: 12, color: 'warning.main' }} />}
                        <EditIcon sx={{ fontSize: 10, color: 'text.disabled', ml: 'auto' }} />
                      </Box>
                    )}
                  </Box>
                )
              })}
            </Box>
          </Box>
        )}
      </Paper>

      {/* Step 2: Trace Level Management - only show when nodes are discovered */}
      {hasNodes && (
        <Grid container spacing={3}>
          {/* Current Trace Levels */}
          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                height: '100%',
                borderRadius: 3,
                border: theme => `1px solid ${alpha(theme.palette.warning.main, 0.2)}`,
                background: theme => theme.palette.mode === 'dark'
                  ? `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.06)} 0%, ${alpha(theme.palette.background.paper, 0.95)} 100%)`
                  : `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.04)} 0%, ${theme.palette.background.paper} 100%)`,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <Box sx={{ width: 8, height: 28, borderRadius: 1, bgcolor: 'warning.main' }} />
                <Typography variant="h6" fontWeight={600}>Current Trace Levels</Typography>
                <Tooltip title="Shows the current trace level for each CUCM service on each node">
                  <InfoIcon sx={{ fontSize: 18, color: 'text.secondary', cursor: 'help' }} />
                </Tooltip>
              </Box>

              <Button
                variant="outlined"
                color="warning"
                fullWidth
                startIcon={getTraceLevelsMutation.isPending ? <CircularProgress size={16} /> : <Refresh />}
                onClick={handleFetchTraceLevels}
                disabled={getTraceLevelsMutation.isPending || !device?.selectedNodes?.length}
                sx={{ mb: 2 }}
              >
                {getTraceLevelsMutation.isPending ? 'Checking...' : 'Check Status'}
              </Button>

              {traceLevels.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <Search sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
                  <Typography variant="body2" color="text.secondary">
                    Click "Check Status" to fetch current trace levels from the selected CUCM nodes
                  </Typography>
                </Box>
              ) : (
                <List dense sx={{ bgcolor: 'background.paper', borderRadius: 2, border: '1px solid', borderColor: 'divider' }}>
                  {traceLevels.map((nodeResult, index) => (
                    <ListItem key={nodeResult.host} divider={index < traceLevels.length - 1}>
                      <ListItemIcon sx={{ minWidth: 36 }}>
                        {nodeResult.success ? (
                          <CheckCircle color="success" sx={{ fontSize: 20 }} />
                        ) : (
                          <ErrorIcon color="error" sx={{ fontSize: 20 }} />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={nodeResult.host}
                        secondary={
                          nodeResult.success ? (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                              {nodeResult.services.map((svc) => (
                                <Tooltip key={svc.service_name} title={svc.service_name} arrow>
                                  <Chip
                                    size="small"
                                    label={getTraceLevelLabel(svc.service_name, svc.current_level)}
                                    color={getTraceLevelChipColor(svc.current_level)}
                                    sx={{ height: 22, fontSize: '0.7rem' }}
                                  />
                                </Tooltip>
                              ))}
                            </Box>
                          ) : (
                            <Typography variant="caption" color="error">
                              {nodeResult.error || 'Error fetching level'}
                            </Typography>
                          )
                        }
                        primaryTypographyProps={{ variant: 'body2', fontWeight: 500 }}
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </Paper>
          </Grid>

          {/* Set Trace Levels */}
          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                p: 3,
                height: '100%',
                borderRadius: 3,
                border: theme => `1px solid ${alpha(theme.palette.warning.main, 0.2)}`,
                background: theme => theme.palette.mode === 'dark'
                  ? `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.06)} 0%, ${alpha(theme.palette.background.paper, 0.95)} 100%)`
                  : `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.04)} 0%, ${theme.palette.background.paper} 100%)`,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <Box sx={{ width: 8, height: 28, borderRadius: 1, bgcolor: 'warning.main' }} />
                <DebugIcon sx={{ color: 'warning.main', fontSize: 24 }} />
                <Typography variant="h6" fontWeight={600}>Set Trace Level</Typography>
              </Box>

              <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                Select a trace level and apply it to all selected CUCM nodes.
                Higher levels provide more detail for troubleshooting.
              </Typography>

              <FormControl fullWidth size="small" sx={{ mb: 2.5 }}>
                <InputLabel>Target Debug Level</InputLabel>
                <Select
                  value={targetDebugLevel}
                  label="Target Debug Level"
                  onChange={e => setTargetDebugLevel(e.target.value as DebugLevel)}
                >
                  <MenuItem value="basic">
                    <Box>
                      <Typography variant="body2">Basic (Default)</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Standard trace levels, minimal performance impact
                      </Typography>
                    </Box>
                  </MenuItem>
                  <MenuItem value="detailed">
                    <Box>
                      <Typography variant="body2">Detailed - TAC Troubleshooting</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Increased verbosity for troubleshooting
                      </Typography>
                    </Box>
                  </MenuItem>
                  <MenuItem value="verbose">
                    <Box>
                      <Typography variant="body2">Verbose - Full Debug</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Maximum detail (may impact performance)
                      </Typography>
                    </Box>
                  </MenuItem>
                </Select>
              </FormControl>

              <Button
                variant="contained"
                fullWidth
                color="warning"
                startIcon={setTraceLevelsMutation.isPending ? <CircularProgress size={20} color="inherit" /> : <SaveIcon />}
                onClick={handleSetTraceLevels}
                disabled={setTraceLevelsMutation.isPending || getTraceLevelsMutation.isPending || !device?.selectedNodes?.length}
                sx={{ mb: 2 }}
              >
                {setTraceLevelsMutation.isPending ? 'Applying...' : `Apply to ${device?.selectedNodes?.length || 0} Selected Nodes`}
              </Button>

              {lastApplyResult && (
                <Alert
                  severity={lastApplyResult.success ? 'success' : 'error'}
                  sx={{ mb: 2 }}
                  onClose={() => setLastApplyResult(null)}
                >
                  <Typography variant="body2">{lastApplyResult.message}</Typography>
                  {lastApplyResult.success && getTraceLevelsMutation.isPending && (
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                      Verifying changes...
                    </Typography>
                  )}
                </Alert>
              )}

              {targetDebugLevel !== 'basic' && (
                <Alert severity="warning">
                  <Typography variant="caption">
                    Higher trace levels generate more logs and may impact system performance.
                    Remember to reset to "Basic" after troubleshooting.
                  </Typography>
                </Alert>
              )}

              {targetDebugLevel === 'basic' && (
                <Alert severity="info">
                  <Typography variant="caption">
                    Setting to "Basic" resets trace levels to their default values.
                    This is recommended after troubleshooting is complete.
                  </Typography>
                </Alert>
              )}
            </Paper>
          </Grid>
        </Grid>
      )}
    </Box>
  )
}
