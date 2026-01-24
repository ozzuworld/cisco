import { useState } from 'react'
import {
  Box,
  Typography,
  Button,
  Paper,
  Grid,
  Card,
  CardContent,
  CardActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Slider,
  CircularProgress,
  Alert,
  Divider,
  IconButton,
  InputAdornment,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Collapse,
  Tooltip,
  LinearProgress,
} from '@mui/material'
import {
  PlayArrow,
  Stop,
  Download,
  Delete,
  Visibility,
  VisibilityOff,
  ExpandMore,
  ExpandLess,
  NetworkCheck,
  Refresh,
  Add,
  Close,
  CheckCircle,
  Error as ErrorIcon,
  HelpOutline,
  ContentCopy,
  Phone as CucmIcon,
  Router as CubeIcon,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { useCaptures, useStartCapture, useStopCapture, useDeleteCapture } from '@/hooks'
import { captureService } from '@/services'
import type { CaptureStatus, CaptureInfo, CaptureProtocol, CaptureDeviceType } from '@/types'

const statusConfig: Record<CaptureStatus, { color: string; label: string }> = {
  pending: { color: '#6b7280', label: 'Pending' },
  running: { color: '#3b82f6', label: 'Running' },
  stopping: { color: '#eab308', label: 'Stopping' },
  completed: { color: '#22c55e', label: 'Completed' },
  failed: { color: '#ef4444', label: 'Failed' },
  cancelled: { color: '#eab308', label: 'Cancelled' },
}

const deviceTypeConfig: Record<CaptureDeviceType, { label: string; icon: React.ReactElement; color: string; defaultPort: number }> = {
  cucm: { label: 'CUCM', icon: <CucmIcon />, color: '#1976d2', defaultPort: 22 },
  cube: { label: 'CUBE', icon: <CubeIcon />, color: '#ed6c02', defaultPort: 22 },
  csr1000v: { label: 'CSR1000V', icon: <CubeIcon />, color: '#0d9488', defaultPort: 22 },
  expressway: { label: 'Expressway', icon: <NetworkCheck />, color: '#9c27b0', defaultPort: 443 },
}

export default function Captures() {
  const { enqueueSnackbar } = useSnackbar()
  const { data: capturesData, isLoading, refetch } = useCaptures()
  const startCapture = useStartCapture()
  const stopCapture = useStopCapture()
  const deleteCapture = useDeleteCapture()

  // Add capture dialog
  const [showAddCapture, setShowAddCapture] = useState(false)
  const [deviceType, setDeviceType] = useState<CaptureDeviceType>('cucm')
  const [host, setHost] = useState('')
  const [port, setPort] = useState<number>(22)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [interfaceName, setInterfaceName] = useState('')
  const [duration, setDuration] = useState(60)

  // Filters
  const [showFilters, setShowFilters] = useState(false)
  const [filterHost, setFilterHost] = useState('')
  const [filterPort, setFilterPort] = useState<number | ''>('')
  const [filterProtocol, setFilterProtocol] = useState<CaptureProtocol>('ip')

  // Detail modal
  const [selectedCapture, setSelectedCapture] = useState<CaptureInfo | null>(null)
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({})

  const deviceConfig = {
    cucm: { defaultPort: 22, interfaceHint: 'eth0', interfaceRequired: true },
    cube: { defaultPort: 22, interfaceHint: 'GigabitEthernet1', interfaceRequired: true },
    csr1000v: { defaultPort: 22, interfaceHint: 'GigabitEthernet1', interfaceRequired: true },
    expressway: { defaultPort: 443, interfaceHint: 'eth0', interfaceRequired: false },
  }
  const config = deviceConfig[deviceType]

  const handleDeviceTypeChange = (type: CaptureDeviceType) => {
    setDeviceType(type)
    setPort(deviceConfig[type].defaultPort)
    setInterfaceName('')
  }

  const handleStartCapture = async () => {
    if (!host || !username || !password) {
      enqueueSnackbar('Please fill in all required fields', { variant: 'warning' })
      return
    }

    try {
      const request = {
        device_type: deviceType,
        host,
        port: port || undefined,
        username,
        password,
        duration_sec: duration,
        interface: interfaceName || undefined,
        filter: showFilters ? {
          host: filterHost || undefined,
          port: filterPort || undefined,
          protocol: filterProtocol,
        } : undefined,
      }

      await startCapture.mutateAsync(request)
      enqueueSnackbar('Packet capture started', { variant: 'success' })

      // Clear form and close dialog
      setHost('')
      setUsername('')
      setPassword('')
      setInterfaceName('')
      setShowAddCapture(false)
    } catch (error) {
      enqueueSnackbar(
        error instanceof Error ? error.message : 'Failed to start capture',
        { variant: 'error' }
      )
    }
  }

  const handleStopCapture = async (captureId: string) => {
    try {
      await stopCapture.mutateAsync(captureId)
      enqueueSnackbar('Capture stopped', { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(
        error instanceof Error ? error.message : 'Failed to stop capture',
        { variant: 'error' }
      )
    }
  }

  const handleDownload = (capture: CaptureInfo) => {
    captureService.downloadCapture(capture.capture_id, capture.filename)
    enqueueSnackbar('Download started', { variant: 'success' })
  }

  const handleDelete = async (captureId: string) => {
    try {
      await deleteCapture.mutateAsync(captureId)
      enqueueSnackbar('Capture deleted', { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(
        error instanceof Error ? error.message : 'Failed to delete capture',
        { variant: 'error' }
      )
    }
  }

  const formatBytes = (bytes?: number): string => {
    if (!bytes) return '-'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const formatDate = (dateStr?: string): string => {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleString()
  }

  const getStatusIcon = (status: CaptureStatus, size: number = 24) => {
    switch (status) {
      case 'completed':
        return <CheckCircle sx={{ fontSize: size }} color="success" />
      case 'failed':
      case 'cancelled':
        return <ErrorIcon sx={{ fontSize: size }} color="error" />
      case 'running':
      case 'pending':
      case 'stopping':
        return <CircularProgress size={size} />
      default:
        return <HelpOutline sx={{ fontSize: size }} color="disabled" />
    }
  }

  const getStatusColor = (status: CaptureStatus) => {
    return statusConfig[status]?.color || '#6b7280'
  }

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }))
  }

  const copyToClipboard = async (data: unknown, label: string) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2))
      enqueueSnackbar(`${label} copied to clipboard`, { variant: 'success' })
    } catch {
      enqueueSnackbar('Failed to copy', { variant: 'error' })
    }
  }

  const captures = capturesData?.captures || []

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Packet Capture
          </Typography>
          <Typography color="text.secondary">
            Capture network traffic from CUCM, CUBE, and IOS-XE devices
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Tooltip title="Refresh">
            <IconButton onClick={() => refetch()}>
              <Refresh />
            </IconButton>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setShowAddCapture(true)}
          >
            New Capture
          </Button>
        </Box>
      </Box>

      {/* No captures state */}
      {!isLoading && captures.length === 0 && (
        <Paper sx={{ p: 6, textAlign: 'center' }}>
          <NetworkCheck sx={{ fontSize: 80, color: 'text.disabled', mb: 2 }} />
          <Typography variant="h5" color="text.secondary" gutterBottom>
            No Packet Captures
          </Typography>
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            Start a new capture to analyze network traffic for SIP/RTP troubleshooting
          </Typography>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setShowAddCapture(true)}
          >
            Start Your First Capture
          </Button>
        </Paper>
      )}

      {/* Loading state */}
      {isLoading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
          <CircularProgress size={60} />
        </Box>
      )}

      {/* Capture Cards */}
      {captures.length > 0 && (
        <Grid container spacing={3}>
          {captures.map(capture => {
            const statusConf = statusConfig[capture.status] || statusConfig.pending
            const isRunning = capture.status === 'running' || capture.status === 'pending'
            const isCompleted = capture.status === 'completed'
            const deviceConf = deviceTypeConfig[capture.device_type as CaptureDeviceType] || deviceTypeConfig.cucm

            return (
              <Grid item xs={12} sm={6} md={4} key={capture.capture_id}>
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    borderLeft: 4,
                    borderColor: getStatusColor(capture.status),
                    transition: 'transform 0.2s, box-shadow 0.2s',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                      boxShadow: 4,
                    },
                  }}
                >
                  <CardContent sx={{ flexGrow: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
                      <Chip
                        icon={deviceConf.icon}
                        label={deviceConf.label}
                        size="small"
                        sx={{ bgcolor: deviceConf.color, color: 'white' }}
                      />
                      <IconButton
                        size="small"
                        onClick={() => handleDelete(capture.capture_id)}
                        disabled={isRunning}
                      >
                        <Delete fontSize="small" />
                      </IconButton>
                    </Box>

                    <Typography variant="h6" gutterBottom>
                      {capture.host}
                    </Typography>

                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Interface: {capture.interface || 'All'}
                    </Typography>

                    {/* Status */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      {getStatusIcon(capture.status, 20)}
                      <Typography
                        variant="body2"
                        fontWeight="medium"
                        sx={{ color: getStatusColor(capture.status) }}
                      >
                        {statusConf.label}
                      </Typography>
                    </Box>

                    {/* Progress for running captures */}
                    {isRunning && (
                      <Box sx={{ mb: 2 }}>
                        <LinearProgress
                          sx={{
                            height: 6,
                            borderRadius: 3,
                            '& .MuiLinearProgress-bar': {
                              animation: 'pulse 1.5s infinite',
                            },
                          }}
                        />
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                          Duration: {capture.duration_sec}s
                        </Typography>
                      </Box>
                    )}

                    {/* Stats chips */}
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
                      {capture.packets_captured != null && (
                        <Chip
                          label={`${capture.packets_captured.toLocaleString()} packets`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                      {capture.file_size_bytes != null && capture.file_size_bytes > 0 && (
                        <Chip
                          label={formatBytes(capture.file_size_bytes)}
                          size="small"
                          variant="outlined"
                        />
                      )}
                      <Chip
                        label={`${capture.duration_sec}s`}
                        size="small"
                        variant="outlined"
                      />
                    </Box>

                    {/* Timestamp */}
                    <Typography variant="caption" color="text.secondary" sx={{ mt: 2, display: 'block' }}>
                      {formatDate(capture.created_at)}
                    </Typography>
                  </CardContent>

                  <CardActions sx={{ justifyContent: 'space-between', px: 2, pb: 2 }}>
                    {isRunning ? (
                      <Button
                        size="small"
                        color="error"
                        startIcon={<Stop />}
                        onClick={() => handleStopCapture(capture.capture_id)}
                      >
                        Stop
                      </Button>
                    ) : (
                      <Button
                        size="small"
                        onClick={() => setSelectedCapture(capture)}
                      >
                        View Details
                      </Button>
                    )}
                    <Button
                      size="small"
                      startIcon={<Download />}
                      onClick={() => handleDownload(capture)}
                      disabled={!isCompleted}
                    >
                      Download
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            )
          })}
        </Grid>
      )}

      {/* Failed captures alert */}
      {captures.some(c => c.status === 'failed') && (
        <Alert severity="error" sx={{ mt: 3 }}>
          Some captures failed. View details for error information.
        </Alert>
      )}

      {/* New Capture Dialog */}
      <Dialog open={showAddCapture} onClose={() => setShowAddCapture(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Start Packet Capture</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
            <FormControl fullWidth>
              <InputLabel>Device Type</InputLabel>
              <Select
                value={deviceType}
                label="Device Type"
                onChange={e => handleDeviceTypeChange(e.target.value as CaptureDeviceType)}
              >
                <MenuItem value="cucm">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CucmIcon /> CUCM / UC Servers
                  </Box>
                </MenuItem>
                <MenuItem value="cube">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CubeIcon /> CUBE (IOS-XE Voice Gateway)
                  </Box>
                </MenuItem>
                <MenuItem value="csr1000v">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CubeIcon /> CSR1000V / ISR / ASR Routers
                  </Box>
                </MenuItem>
                <MenuItem value="expressway">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <NetworkCheck /> Expressway / VCS
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>

            <Grid container spacing={2}>
              <Grid item xs={8}>
                <TextField
                  label="Target Host"
                  value={host}
                  onChange={e => setHost(e.target.value)}
                  placeholder="172.168.0.101"
                  fullWidth
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Port"
                  type="number"
                  value={port}
                  onChange={e => setPort(Number(e.target.value))}
                  fullWidth
                />
              </Grid>
            </Grid>

            <TextField
              label="Username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              fullWidth
            />

            <TextField
              label="Password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              fullWidth
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />

            <TextField
              label={config.interfaceRequired ? 'Interface' : 'Interface (Optional)'}
              value={interfaceName}
              onChange={e => setInterfaceName(e.target.value)}
              placeholder={config.interfaceHint}
              helperText={config.interfaceRequired ? `e.g., ${config.interfaceHint}` : 'Leave empty for all interfaces'}
              fullWidth
            />

            <Box>
              <Typography variant="body2" gutterBottom>
                Duration: {duration} seconds ({Math.floor(duration / 60)}:{(duration % 60).toString().padStart(2, '0')})
              </Typography>
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
              />
            </Box>

            {/* Filters */}
            <Box
              sx={{
                p: 2,
                border: 1,
                borderColor: 'divider',
                borderRadius: 1,
                cursor: 'pointer',
              }}
              onClick={() => setShowFilters(!showFilters)}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="body2">Packet Filters (Optional)</Typography>
                {showFilters ? <ExpandLess /> : <ExpandMore />}
              </Box>
            </Box>
            <Collapse in={showFilters}>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <TextField
                  label="Filter by Host IP"
                  value={filterHost}
                  onChange={e => setFilterHost(e.target.value)}
                  placeholder="e.g., 10.0.0.50"
                  size="small"
                  fullWidth
                />
                <TextField
                  label="Filter by Port"
                  type="number"
                  value={filterPort}
                  onChange={e => setFilterPort(e.target.value ? Number(e.target.value) : '')}
                  placeholder="e.g., 5060"
                  size="small"
                  fullWidth
                />
                <FormControl size="small" fullWidth>
                  <InputLabel>Protocol</InputLabel>
                  <Select
                    value={filterProtocol}
                    label="Protocol"
                    onChange={e => setFilterProtocol(e.target.value as CaptureProtocol)}
                  >
                    <MenuItem value="ip">IP (All IP traffic)</MenuItem>
                    <MenuItem value="arp">ARP</MenuItem>
                    <MenuItem value="rarp">RARP</MenuItem>
                    <MenuItem value="all">All Protocols</MenuItem>
                  </Select>
                </FormControl>
              </Box>
            </Collapse>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAddCapture(false)}>Cancel</Button>
          <Button
            variant="contained"
            startIcon={startCapture.isPending ? <CircularProgress size={20} color="inherit" /> : <PlayArrow />}
            onClick={handleStartCapture}
            disabled={startCapture.isPending || !host || !username || !password}
          >
            {startCapture.isPending ? 'Starting...' : 'Start Capture'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Capture Detail Dialog */}
      <Dialog
        open={!!selectedCapture}
        onClose={() => setSelectedCapture(null)}
        maxWidth="md"
        fullWidth
      >
        {selectedCapture && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  {(() => {
                    const deviceConf = deviceTypeConfig[selectedCapture.device_type as CaptureDeviceType] || deviceTypeConfig.cucm
                    return (
                      <Chip
                        icon={deviceConf.icon}
                        label={deviceConf.label}
                        sx={{ bgcolor: deviceConf.color, color: 'white' }}
                      />
                    )
                  })()}
                  <Typography variant="h6">{selectedCapture.host}</Typography>
                  <Chip
                    label={statusConfig[selectedCapture.status]?.label || selectedCapture.status}
                    size="small"
                    sx={{
                      bgcolor: getStatusColor(selectedCapture.status),
                      color: 'white',
                    }}
                  />
                </Box>
                <IconButton onClick={() => setSelectedCapture(null)}>
                  <Close />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent>
              {/* Capture Info */}
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
                  <Typography variant="subtitle1" fontWeight="medium">Capture Information</Typography>
                  {expandedSections.info !== false ? <ExpandLess /> : <ExpandMore />}
                </Box>
                <Collapse in={expandedSections.info !== false}>
                  <Divider />
                  <Box sx={{ p: 2 }}>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Host</Typography>
                        <Typography variant="body1">{selectedCapture.host}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Interface</Typography>
                        <Typography variant="body1">{selectedCapture.interface || 'All'}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Duration</Typography>
                        <Typography variant="body1">{selectedCapture.duration_sec} seconds</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Status</Typography>
                        <Typography variant="body1">{statusConfig[selectedCapture.status]?.label}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">Packets Captured</Typography>
                        <Typography variant="body1">
                          {selectedCapture.packets_captured?.toLocaleString() || '-'}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">File Size</Typography>
                        <Typography variant="body1">{formatBytes(selectedCapture.file_size_bytes)}</Typography>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">Created</Typography>
                        <Typography variant="body1">{formatDate(selectedCapture.created_at)}</Typography>
                      </Grid>
                      {selectedCapture.filename && (
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Filename</Typography>
                          <Typography variant="body1">{selectedCapture.filename}</Typography>
                        </Grid>
                      )}
                    </Grid>
                  </Box>
                </Collapse>
              </Paper>

              {/* Error info if failed */}
              {selectedCapture.status === 'failed' && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  Capture failed. Please check device connectivity and credentials.
                </Alert>
              )}
            </DialogContent>
            <DialogActions>
              <Button
                startIcon={<ContentCopy />}
                onClick={() => copyToClipboard(selectedCapture, 'Capture data')}
              >
                Copy
              </Button>
              <Button
                startIcon={<Download />}
                onClick={() => handleDownload(selectedCapture)}
                disabled={selectedCapture.status !== 'completed'}
              >
                Download .pcap
              </Button>
              <Button variant="contained" onClick={() => setSelectedCapture(null)}>
                Close
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  )
}
