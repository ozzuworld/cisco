import React, { useState } from 'react'
import {
  Box,
  Typography,
  Button,
  Paper,
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormGroup,
  FormControlLabel,
  Checkbox,
  CircularProgress,
  Alert,
  Divider,
  IconButton,
  InputAdornment,
  Chip,
  Card,
  CardContent,
  CardActions,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Collapse,
  Tooltip,
  alpha,
} from '@mui/material'
import {
  Visibility,
  VisibilityOff,
  HealthAndSafety,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  HelpOutline,
  Add,
  Delete,
  ExpandMore,
  ExpandLess,
  Phone as CucmIcon,
  Router as CubeIcon,
  Link as ExpresswayIcon,
  Download,
  ContentCopy,
  Close,
  PlayArrow,
  DevicesOther,
  Assessment,
  Checklist,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { healthService } from '@/services'
import { HealthStatusBadge } from '@/components/health'
import type {
  DeviceType,
  DeviceHealthTarget,
  DeviceHealthResponse,
  DeviceHealthResult,
  HealthStatus,
  CUCMHealthCheck,
  CUBEHealthCheck,
  ExpresswayHealthCheck,
} from '@/types'
import {
  defaultCUCMChecks,
  defaultCUBEChecks,
  defaultExpresswayChecks,
} from '@/types'

// Emerald accent theme for Health Check (distinct from blue LogCollection and teal Packet Capture)
const ACCENT_COLOR = '#10b981' // emerald-500

// Device entry for the form
interface DeviceEntry extends DeviceHealthTarget {
  id: string
}

// Device type configuration
const deviceTypeConfig: Record<DeviceType, { label: string; icon: React.ReactElement; color: string; defaultPort: number }> = {
  cucm: { label: 'CUCM', icon: <CucmIcon />, color: '#0891b2', defaultPort: 22 },      // cyan-600
  cube: { label: 'CUBE', icon: <CubeIcon />, color: '#d97706', defaultPort: 22 },       // amber-600
  expressway: { label: 'Expressway', icon: <ExpresswayIcon />, color: '#7c3aed', defaultPort: 443 }, // violet-600
}

// Check labels
const cucmCheckLabels: Record<CUCMHealthCheck, string> = {
  replication: 'Database Replication',
  services: 'Services Status',
  ntp: 'NTP Synchronization',
  diagnostics: 'Diagnostics',
  cores: 'Core Files',
}

const cubeCheckLabels: Record<CUBEHealthCheck, string> = {
  system: 'System Info',
  environment: 'Environment',
  interfaces: 'Interfaces',
  voice_calls: 'Voice Calls',
  sip_status: 'SIP Status',
  sip_registration: 'SIP Registration',
  dsp: 'DSP Resources',
  ntp: 'NTP Status',
  redundancy: 'Redundancy/HA',
}

const expresswayCheckLabels: Record<ExpresswayHealthCheck, string> = {
  cluster: 'Cluster Status',
  licensing: 'Licensing',
  alarms: 'Alarms',
  ntp: 'NTP Status',
}

export default function Health() {
  const { enqueueSnackbar } = useSnackbar()

  // Device list state
  const [devices, setDevices] = useState<DeviceEntry[]>([])

  // Add device form state
  const [showAddDevice, setShowAddDevice] = useState(false)
  const [newDeviceType, setNewDeviceType] = useState<DeviceType>('cucm')
  const [newHost, setNewHost] = useState('')
  const [newPort, setNewPort] = useState<number>(22)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [showNewPassword, setShowNewPassword] = useState(false)

  // Check selections for new device
  const [cucmChecks, setCucmChecks] = useState<CUCMHealthCheck[]>(defaultCUCMChecks)
  const [cubeChecks, setCubeChecks] = useState<CUBEHealthCheck[]>(defaultCUBEChecks)
  const [expresswayChecks, setExpresswayChecks] = useState<ExpresswayHealthCheck[]>(defaultExpresswayChecks)

  // Loading and result state
  const [isChecking, setIsChecking] = useState(false)
  const [healthResult, setHealthResult] = useState<DeviceHealthResponse | null>(null)

  // Detail modal state
  const [selectedDevice, setSelectedDevice] = useState<DeviceHealthResult | null>(null)
  const [expandedChecks, setExpandedChecks] = useState<Record<string, boolean>>({})

  // Handle device type change
  const handleDeviceTypeChange = (type: DeviceType) => {
    setNewDeviceType(type)
    setNewPort(deviceTypeConfig[type].defaultPort)
  }

  // Add device to list
  const handleAddDevice = () => {
    if (!newHost) {
      enqueueSnackbar('Please enter a host address', { variant: 'warning' })
      return
    }
    if (!newUsername || !newPassword) {
      enqueueSnackbar('Please enter credentials', { variant: 'warning' })
      return
    }

    const newDevice: DeviceEntry = {
      id: `${newDeviceType}-${Date.now()}`,
      device_type: newDeviceType,
      host: newHost,
      port: newPort,
      username: newUsername,
      password: newPassword,
      cucm_checks: newDeviceType === 'cucm' ? cucmChecks : undefined,
      cube_checks: newDeviceType === 'cube' ? cubeChecks : undefined,
      expressway_checks: newDeviceType === 'expressway' ? expresswayChecks : undefined,
    }

    setDevices([...devices, newDevice])
    setNewHost('')
    setNewUsername('')
    setNewPassword('')
    setShowAddDevice(false)
    enqueueSnackbar(`Added ${deviceTypeConfig[newDeviceType].label}: ${newHost}`, { variant: 'success' })
  }

  // Remove device from list
  const handleRemoveDevice = (id: string) => {
    setDevices(devices.filter(d => d.id !== id))
    // Clear results if removing a device
    setHealthResult(null)
  }

  // Run health check
  const handleRunHealthCheck = async () => {
    if (devices.length === 0) {
      enqueueSnackbar('Please add at least one device', { variant: 'warning' })
      return
    }

    // Validate all devices have credentials
    const missingCreds = devices.some(d => !d.username || !d.password)
    if (missingCreds) {
      enqueueSnackbar('Please ensure all devices have credentials', { variant: 'warning' })
      return
    }

    setIsChecking(true)
    setHealthResult(null)
    try {
      const result = await healthService.checkDeviceHealth({
        devices: devices.map(d => ({
          device_type: d.device_type,
          host: d.host,
          port: d.port,
          username: d.username,
          password: d.password,
          cucm_checks: d.cucm_checks,
          cube_checks: d.cube_checks,
          expressway_checks: d.expressway_checks,
        })),
      })
      setHealthResult(result)
      enqueueSnackbar('Health check completed', { variant: 'success' })
    } catch (error) {
      enqueueSnackbar(
        error instanceof Error ? error.message : 'Health check failed',
        { variant: 'error' }
      )
    } finally {
      setIsChecking(false)
    }
  }

  // Get status icon
  const getStatusIcon = (status: HealthStatus, size: number = 48) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle sx={{ fontSize: size }} color="success" />
      case 'degraded':
        return <Warning sx={{ fontSize: size }} color="warning" />
      case 'critical':
        return <ErrorIcon sx={{ fontSize: size }} color="error" />
      default:
        return <HelpOutline sx={{ fontSize: size }} color="disabled" />
    }
  }

  // Get status color
  const getStatusColor = (status: HealthStatus) => {
    switch (status) {
      case 'healthy': return '#22c55e'
      case 'degraded': return '#eab308'
      case 'critical': return '#ef4444'
      default: return '#6b7280'
    }
  }

  // Format time
  const formatTime = (dateStr: string) => {
    return new Date(dateStr).toLocaleString()
  }

  // Format uptime
  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    return `${days}d ${hours}h`
  }

  // Copy to clipboard
  const copyToClipboard = async (data: unknown, label: string) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2))
      enqueueSnackbar(`${label} copied to clipboard`, { variant: 'success' })
    } catch {
      enqueueSnackbar('Failed to copy', { variant: 'error' })
    }
  }

  // Download device report
  const downloadDeviceReport = (device: DeviceHealthResult, format: 'json' | 'txt') => {
    const report = {
      report_type: 'device_health',
      generated_at: new Date().toISOString(),
      device: {
        type: device.device_type,
        host: device.host,
        status: device.status,
        reachable: device.reachable,
        checked_at: device.checked_at,
        message: device.message,
      },
      checks: device.cucm_checks || device.cube_checks || device.expressway_checks,
    }

    let content: string
    let mimeType: string
    let extension: string

    if (format === 'json') {
      content = JSON.stringify(report, null, 2)
      mimeType = 'application/json'
      extension = 'json'
    } else {
      content = `Device Health Report\n${'='.repeat(50)}\n\n`
      content += `Device: ${device.device_type.toUpperCase()}\n`
      content += `Host: ${device.host}\n`
      content += `Status: ${device.status.toUpperCase()}\n`
      content += `Checked: ${formatTime(device.checked_at)}\n`
      content += `Message: ${device.message}\n\n`
      content += `Checks:\n${JSON.stringify(report.checks, null, 2)}`
      mimeType = 'text/plain'
      extension = 'txt'
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `health-report-${device.host}-${Date.now()}.${extension}`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Download full report
  const downloadFullReport = () => {
    if (!healthResult) return

    const report = {
      report_type: 'infrastructure_health',
      generated_at: new Date().toISOString(),
      overall_status: healthResult.overall_status,
      summary: {
        total: healthResult.total_devices,
        healthy: healthResult.healthy_devices,
        degraded: healthResult.degraded_devices,
        critical: healthResult.critical_devices,
        unknown: healthResult.unknown_devices,
      },
      devices: healthResult.devices,
    }

    const content = JSON.stringify(report, null, 2)
    const blob = new Blob([content], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `infrastructure-health-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Toggle check expansion
  const toggleCheckExpansion = (checkName: string) => {
    setExpandedChecks(prev => ({ ...prev, [checkName]: !prev[checkName] }))
  }

  // Get quick status for device card
  const getDeviceQuickStatus = (device: DeviceHealthResult) => {
    const checks: Array<{ name: string; ok: boolean }> = []

    if (device.cucm_checks) {
      if (device.cucm_checks.services) checks.push({ name: 'Services', ok: device.cucm_checks.services.status === 'healthy' })
      if (device.cucm_checks.ntp) checks.push({ name: 'NTP', ok: device.cucm_checks.ntp.status === 'healthy' })
      if (device.cucm_checks.replication) checks.push({ name: 'Replication', ok: device.cucm_checks.replication.status === 'healthy' })
    }
    if (device.cube_checks) {
      if (device.cube_checks.system) checks.push({ name: 'System', ok: device.cube_checks.system.status === 'healthy' })
      if (device.cube_checks.sip_status) checks.push({ name: 'SIP', ok: device.cube_checks.sip_status.status === 'healthy' })
      if (device.cube_checks.voice_calls) checks.push({ name: 'Calls', ok: device.cube_checks.voice_calls.status === 'healthy' })
    }
    if (device.expressway_checks) {
      if (device.expressway_checks.cluster) checks.push({ name: 'Cluster', ok: device.expressway_checks.cluster.status === 'healthy' })
      if (device.expressway_checks.alarms) checks.push({ name: 'Alarms', ok: device.expressway_checks.alarms.status === 'healthy' })
      if (device.expressway_checks.licensing) checks.push({ name: 'License', ok: device.expressway_checks.licensing.status === 'healthy' })
    }

    return checks.slice(0, 4)
  }

  // Render check section in detail modal
  const renderCheckSection = (title: string, checkName: string, status: HealthStatus, content: React.ReactNode, data: unknown) => {
    const isExpanded = expandedChecks[checkName] !== false // Default to expanded

    return (
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
          onClick={() => toggleCheckExpansion(checkName)}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {getStatusIcon(status, 24)}
            <Typography variant="subtitle1" fontWeight="medium">{title}</Typography>
            <HealthStatusBadge status={status} />
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Tooltip title="Copy">
              <IconButton size="small" onClick={e => { e.stopPropagation(); copyToClipboard(data, title) }}>
                <ContentCopy fontSize="small" />
              </IconButton>
            </Tooltip>
            {isExpanded ? <ExpandLess /> : <ExpandMore />}
          </Box>
        </Box>
        <Collapse in={isExpanded}>
          <Divider />
          <Box sx={{ p: 2 }}>
            {content}
          </Box>
        </Collapse>
      </Paper>
    )
  }

  // Render device detail modal content
  const renderDeviceDetails = (device: DeviceHealthResult) => {
    return (
      <>
        {device.error && (
          <Alert severity="error" sx={{ mb: 2 }}>{device.error}</Alert>
        )}

        {/* CUCM Checks */}
        {device.cucm_checks?.services && renderCheckSection(
          'Services',
          'services',
          device.cucm_checks.services.status,
          <Box>
            <Typography variant="body2">
              Running: {device.cucm_checks.services.running_services} / {device.cucm_checks.services.total_services}
            </Typography>
            <Typography variant="body2">
              Stopped: {device.cucm_checks.services.stopped_services}
            </Typography>
            {device.cucm_checks.services.critical_services_down.length > 0 && (
              <Alert severity="error" sx={{ mt: 1 }}>
                Down: {device.cucm_checks.services.critical_services_down.join(', ')}
              </Alert>
            )}
          </Box>,
          device.cucm_checks.services
        )}

        {device.cucm_checks?.ntp && renderCheckSection(
          'NTP',
          'ntp',
          device.cucm_checks.ntp.status,
          <Box>
            <Typography variant="body2">
              Synchronized: {device.cucm_checks.ntp.synchronized ? 'Yes' : 'No'}
            </Typography>
            {device.cucm_checks.ntp.stratum && (
              <Typography variant="body2">Stratum: {device.cucm_checks.ntp.stratum}</Typography>
            )}
            {device.cucm_checks.ntp.ntp_server && (
              <Typography variant="body2">Server: {device.cucm_checks.ntp.ntp_server}</Typography>
            )}
          </Box>,
          device.cucm_checks.ntp
        )}

        {device.cucm_checks?.replication && renderCheckSection(
          'Replication',
          'replication',
          device.cucm_checks.replication.status,
          <Box>
            <Typography variant="body2">
              Tables: {device.cucm_checks.replication.tables_checked} / {device.cucm_checks.replication.tables_total}
            </Typography>
            {device.cucm_checks.replication.errors_found && (
              <Alert severity="error" sx={{ mt: 1 }}>Errors found in replication</Alert>
            )}
          </Box>,
          device.cucm_checks.replication
        )}

        {device.cucm_checks?.diagnostics && renderCheckSection(
          'Diagnostics',
          'diagnostics',
          device.cucm_checks.diagnostics.status,
          <Box>
            <Typography variant="body2">
              Tests Passed: {device.cucm_checks.diagnostics.passed_tests} / {device.cucm_checks.diagnostics.total_tests}
            </Typography>
            {device.cucm_checks.diagnostics.failed_tests > 0 && (
              <Typography variant="body2" color="error">
                Failed: {device.cucm_checks.diagnostics.failed_tests}
              </Typography>
            )}
          </Box>,
          device.cucm_checks.diagnostics
        )}

        {/* CUBE Checks */}
        {device.cube_checks?.system && renderCheckSection(
          'System',
          'system',
          device.cube_checks.system.status,
          <Box>
            {device.cube_checks.system.hostname && (
              <Typography variant="body2">Hostname: {device.cube_checks.system.hostname}</Typography>
            )}
            {device.cube_checks.system.version && (
              <Typography variant="body2">Version: {device.cube_checks.system.version}</Typography>
            )}
            {device.cube_checks.system.uptime_seconds && (
              <Typography variant="body2">Uptime: {formatUptime(device.cube_checks.system.uptime_seconds)}</Typography>
            )}
          </Box>,
          device.cube_checks.system
        )}

        {device.cube_checks?.interfaces && renderCheckSection(
          'Interfaces',
          'interfaces',
          device.cube_checks.interfaces.status,
          <Box>
            <Typography variant="body2">
              Up: {device.cube_checks.interfaces.up_interfaces} / {device.cube_checks.interfaces.total_interfaces}
            </Typography>
            {device.cube_checks.interfaces.down_interfaces != null && device.cube_checks.interfaces.down_interfaces > 0 && (
              <Typography variant="body2" color="warning.main">
                Down: {device.cube_checks.interfaces.down_interfaces}
              </Typography>
            )}
          </Box>,
          device.cube_checks.interfaces
        )}

        {device.cube_checks?.voice_calls && renderCheckSection(
          'Voice Calls',
          'voice_calls',
          device.cube_checks.voice_calls.status,
          <Box>
            <Typography variant="body2">
              Active Calls: {device.cube_checks.voice_calls.active_calls}
            </Typography>
            {device.cube_checks.voice_calls.total_calls != null && (
              <Typography variant="body2">Total Today: {device.cube_checks.voice_calls.total_calls}</Typography>
            )}
          </Box>,
          device.cube_checks.voice_calls
        )}

        {device.cube_checks?.sip_status && renderCheckSection(
          'SIP Status',
          'sip_status',
          device.cube_checks.sip_status.status,
          <Box>
            <Typography variant="body2">
              Active Calls: {device.cube_checks.sip_status.active_calls}
            </Typography>
            <Typography variant="body2">
              Registrations: {device.cube_checks.sip_status.total_registrations}
            </Typography>
          </Box>,
          device.cube_checks.sip_status
        )}

        {device.cube_checks?.ntp && renderCheckSection(
          'NTP',
          'cube_ntp',
          device.cube_checks.ntp.status,
          <Box>
            <Typography variant="body2">
              Synchronized: {device.cube_checks.ntp.synchronized ? 'Yes' : 'No'}
            </Typography>
            {device.cube_checks.ntp.stratum && (
              <Typography variant="body2">Stratum: {device.cube_checks.ntp.stratum}</Typography>
            )}
          </Box>,
          device.cube_checks.ntp
        )}

        {/* Expressway Checks */}
        {device.expressway_checks?.cluster && renderCheckSection(
          'Cluster',
          'cluster',
          device.expressway_checks.cluster.status,
          <Box>
            <Typography variant="body2">
              Peers: {device.expressway_checks.cluster.peer_count}
            </Typography>
            <Typography variant="body2">
              All Active: {device.expressway_checks.cluster.all_peers_active ? 'Yes' : 'No'}
            </Typography>
          </Box>,
          device.expressway_checks.cluster
        )}

        {device.expressway_checks?.licensing && renderCheckSection(
          'Licensing',
          'licensing',
          device.expressway_checks.licensing.status,
          <Box>
            <Typography variant="body2">
              Valid: {device.expressway_checks.licensing.license_valid ? 'Yes' : 'No'}
            </Typography>
            {device.expressway_checks.licensing.days_remaining != null && (
              <Typography variant="body2">
                Days Remaining: {device.expressway_checks.licensing.days_remaining}
              </Typography>
            )}
          </Box>,
          device.expressway_checks.licensing
        )}

        {device.expressway_checks?.alarms && renderCheckSection(
          'Alarms',
          'alarms',
          device.expressway_checks.alarms.status,
          <Box>
            <Typography variant="body2">
              Total Alarms: {device.expressway_checks.alarms.alarm_count}
            </Typography>
            {device.expressway_checks.alarms.critical_count != null && device.expressway_checks.alarms.critical_count > 0 && (
              <Typography variant="body2" color="error">
                Critical: {device.expressway_checks.alarms.critical_count}
              </Typography>
            )}
            {device.expressway_checks.alarms.warning_count != null && device.expressway_checks.alarms.warning_count > 0 && (
              <Typography variant="body2" color="warning.main">
                Warning: {device.expressway_checks.alarms.warning_count}
              </Typography>
            )}
          </Box>,
          device.expressway_checks.alarms
        )}

        {device.expressway_checks?.ntp && renderCheckSection(
          'NTP',
          'exp_ntp',
          device.expressway_checks.ntp.status,
          <Box>
            <Typography variant="body2">
              Synchronized: {device.expressway_checks.ntp.synchronized ? 'Yes' : 'No'}
            </Typography>
          </Box>,
          device.expressway_checks.ntp
        )}
      </>
    )
  }

  // Render check selection based on device type
  const renderCheckSelection = () => {
    if (newDeviceType === 'cucm') {
      return (
        <FormGroup row>
          {(Object.keys(cucmCheckLabels) as CUCMHealthCheck[]).map(check => (
            <FormControlLabel
              key={check}
              control={
                <Checkbox
                  checked={cucmChecks.includes(check)}
                  onChange={() => setCucmChecks(prev =>
                    prev.includes(check) ? prev.filter(c => c !== check) : [...prev, check]
                  )}
                  size="small"
                />
              }
              label={cucmCheckLabels[check]}
            />
          ))}
        </FormGroup>
      )
    }
    if (newDeviceType === 'cube') {
      return (
        <FormGroup row>
          {(Object.keys(cubeCheckLabels) as CUBEHealthCheck[]).map(check => (
            <FormControlLabel
              key={check}
              control={
                <Checkbox
                  checked={cubeChecks.includes(check)}
                  onChange={() => setCubeChecks(prev =>
                    prev.includes(check) ? prev.filter(c => c !== check) : [...prev, check]
                  )}
                  size="small"
                />
              }
              label={cubeCheckLabels[check]}
            />
          ))}
        </FormGroup>
      )
    }
    return (
      <FormGroup row>
        {(Object.keys(expresswayCheckLabels) as ExpresswayHealthCheck[]).map(check => (
          <FormControlLabel
            key={check}
            control={
              <Checkbox
                checked={expresswayChecks.includes(check)}
                onChange={() => setExpresswayChecks(prev =>
                  prev.includes(check) ? prev.filter(c => c !== check) : [...prev, check]
                )}
                size="small"
              />
            }
            label={expresswayCheckLabels[check]}
          />
        ))}
      </FormGroup>
    )
  }

  // Find device result by host
  const getDeviceResult = (host: string): DeviceHealthResult | undefined => {
    return healthResult?.devices.find(d => d.host === host)
  }

  // Workflow steps with icons
  const workflowSteps = [
    { label: 'Devices', icon: <DevicesOther sx={{ fontSize: 16 }} /> },
    { label: 'Configure', icon: <Checklist sx={{ fontSize: 16 }} /> },
    { label: 'Check', icon: <HealthAndSafety sx={{ fontSize: 16 }} /> },
    { label: 'Results', icon: <Assessment sx={{ fontSize: 16 }} /> },
  ]

  const getActiveStep = () => {
    if (healthResult) return 3
    if (isChecking) return 2
    if (devices.length > 0) return 1
    return 0
  }

  // Device counts by type
  const deviceCounts = {
    cucm: devices.filter(d => d.device_type === 'cucm').length,
    cube: devices.filter(d => d.device_type === 'cube').length,
    expressway: devices.filter(d => d.device_type === 'expressway').length,
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h5" fontWeight={600}>
            Device Health Check
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Check the health of CUCM, CUBE, and Expressway devices
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<Add />}
            onClick={() => setShowAddDevice(true)}
            sx={{ borderColor: ACCENT_COLOR, color: ACCENT_COLOR, '&:hover': { borderColor: ACCENT_COLOR, bgcolor: alpha(ACCENT_COLOR, 0.08) } }}
          >
            Add Device
          </Button>
          {devices.length > 0 && (
            <Button
              variant="contained"
              startIcon={isChecking ? <CircularProgress size={20} color="inherit" /> : <PlayArrow />}
              onClick={handleRunHealthCheck}
              disabled={isChecking}
              sx={{ bgcolor: ACCENT_COLOR, '&:hover': { bgcolor: '#059669' } }}
            >
              {isChecking ? 'Checking...' : 'Check Health'}
            </Button>
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
        {devices.length > 0 && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Chip
              size="small"
              icon={<DevicesOther sx={{ fontSize: 16 }} />}
              label={`${devices.length} devices`}
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
            {deviceCounts.cube > 0 && (
              <Chip
                size="small"
                icon={<CubeIcon sx={{ fontSize: 16, color: deviceTypeConfig.cube.color }} />}
                label={deviceCounts.cube}
                sx={{ bgcolor: alpha(deviceTypeConfig.cube.color, 0.1), minWidth: 50 }}
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
            {healthResult && (
              <Chip
                size="small"
                icon={<CheckCircle sx={{ fontSize: 16 }} />}
                label={`${healthResult.healthy_devices}/${healthResult.total_devices} healthy`}
                color={healthResult.overall_status === 'healthy' ? 'success' : healthResult.overall_status === 'degraded' ? 'warning' : 'error'}
              />
            )}
          </Box>
        )}
      </Box>

      {/* No devices state */}
      {devices.length === 0 && (
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
            <HealthAndSafety sx={{ fontSize: 40, color: ACCENT_COLOR }} />
          </Box>
          <Typography variant="h6" color="text.primary" fontWeight={600} gutterBottom>
            No Devices Configured
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Add devices to check their health status
          </Typography>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setShowAddDevice(true)}
            sx={{ bgcolor: ACCENT_COLOR, '&:hover': { bgcolor: '#059669' } }}
          >
            Add Your First Device
          </Button>
        </Paper>
      )}

      {/* Results Summary */}
      {healthResult && (
        <Paper
          sx={{
            p: 3,
            mb: 3,
            borderRadius: 3,
            background: theme => theme.palette.mode === 'dark'
              ? `linear-gradient(135deg, ${alpha(getStatusColor(healthResult.overall_status), 0.1)} 0%, ${alpha(theme.palette.background.paper, 0.95)} 40%)`
              : `linear-gradient(135deg, ${alpha(getStatusColor(healthResult.overall_status), 0.08)} 0%, ${theme.palette.background.paper} 40%)`,
            border: `1px solid ${alpha(getStatusColor(healthResult.overall_status), 0.2)}`,
          }}
        >
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Box
                sx={{
                  width: 64,
                  height: 64,
                  borderRadius: 3,
                  bgcolor: alpha(getStatusColor(healthResult.overall_status), 0.1),
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: `2px solid ${getStatusColor(healthResult.overall_status)}`,
                  ...(healthResult.overall_status !== 'healthy' ? {
                    animation: 'statusPulse 2s ease-in-out infinite',
                    '@keyframes statusPulse': {
                      '0%, 100%': {
                        boxShadow: `0 0 0 0 ${alpha(getStatusColor(healthResult.overall_status), 0.4)}`,
                      },
                      '50%': {
                        boxShadow: `0 0 0 8px ${alpha(getStatusColor(healthResult.overall_status), 0)}`,
                      },
                    },
                  } : {}),
                }}
              >
                {getStatusIcon(healthResult.overall_status, 32)}
              </Box>
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography variant="h5" fontWeight={700}>
                    {healthResult.overall_status.charAt(0).toUpperCase() + healthResult.overall_status.slice(1)}
                  </Typography>
                  <Chip
                    size="small"
                    sx={{
                      bgcolor: getStatusColor(healthResult.overall_status),
                      color: 'white',
                      fontWeight: 600,
                    }}
                    label={healthResult.overall_status}
                  />
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Health check completed at {formatTime(healthResult.checked_at)}
                </Typography>
              </Box>
            </Box>
            <Button
              variant="outlined"
              startIcon={<Download />}
              onClick={downloadFullReport}
              sx={{ borderColor: ACCENT_COLOR, color: ACCENT_COLOR, '&:hover': { borderColor: ACCENT_COLOR, bgcolor: alpha(ACCENT_COLOR, 0.08) } }}
            >
              Download Report
            </Button>
          </Box>

          <Divider sx={{ my: 2 }} />

          {/* Summary Stats */}
          <Grid container spacing={2}>
            <Grid item xs={6} sm={3}>
              <Box
                sx={{
                  textAlign: 'center',
                  p: 2,
                  borderRadius: 2,
                  bgcolor: theme => alpha(theme.palette.text.primary, 0.03),
                  border: '1px solid',
                  borderColor: 'divider',
                }}
              >
                <DevicesOther sx={{ fontSize: 24, color: 'text.secondary', mb: 0.5 }} />
                <Typography variant="h3" fontWeight={700} color="text.primary">
                  {healthResult.total_devices}
                </Typography>
                <Typography variant="caption" color="text.secondary" fontWeight={500}>
                  Total Devices
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box
                sx={{
                  textAlign: 'center',
                  p: 2,
                  borderRadius: 2,
                  bgcolor: alpha('#22c55e', 0.1),
                  border: `1px solid ${alpha('#22c55e', 0.3)}`,
                }}
              >
                <CheckCircle sx={{ fontSize: 24, color: '#22c55e', mb: 0.5 }} />
                <Typography variant="h3" fontWeight={700} sx={{ color: '#22c55e' }}>
                  {healthResult.healthy_devices}
                </Typography>
                <Typography variant="caption" color="text.secondary" fontWeight={500}>
                  Healthy
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box
                sx={{
                  textAlign: 'center',
                  p: 2,
                  borderRadius: 2,
                  bgcolor: alpha('#eab308', 0.1),
                  border: `1px solid ${alpha('#eab308', 0.3)}`,
                }}
              >
                <Warning sx={{ fontSize: 24, color: '#eab308', mb: 0.5 }} />
                <Typography variant="h3" fontWeight={700} sx={{ color: '#eab308' }}>
                  {healthResult.degraded_devices}
                </Typography>
                <Typography variant="caption" color="text.secondary" fontWeight={500}>
                  Degraded
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box
                sx={{
                  textAlign: 'center',
                  p: 2,
                  borderRadius: 2,
                  bgcolor: alpha('#ef4444', 0.1),
                  border: `1px solid ${alpha('#ef4444', 0.3)}`,
                }}
              >
                <ErrorIcon sx={{ fontSize: 24, color: '#ef4444', mb: 0.5 }} />
                <Typography variant="h3" fontWeight={700} sx={{ color: '#ef4444' }}>
                  {(healthResult.critical_devices || 0) + (healthResult.unknown_devices || 0)}
                </Typography>
                <Typography variant="caption" color="text.secondary" fontWeight={500}>
                  Critical/Unknown
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>
      )}

      {/* Device Cards */}
      {devices.length > 0 && (
        <Grid container spacing={2}>
          {devices.map((device) => {
            const config = deviceTypeConfig[device.device_type]
            const result = getDeviceResult(device.host)
            const hasResult = !!result
            const status: HealthStatus = result?.status || 'unknown'
            const quickStatus = result ? getDeviceQuickStatus(result) : []
            const statusColor = hasResult ? getStatusColor(status) : config.color

            return (
              <Grid item xs={12} sm={6} md={4} lg={3} key={device.id}>
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    borderRadius: 3,
                    overflow: 'hidden',
                    border: 'none',
                    boxShadow: `0 2px 8px ${alpha(statusColor, 0.15)}`,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: `0 8px 24px ${alpha(statusColor, 0.25)}`,
                    },
                  }}
                >
                  {/* Gradient header with floating icon */}
                  <Box
                    sx={{
                      px: 2,
                      py: 1.5,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      background: `linear-gradient(135deg, ${alpha(config.color, 0.15)} 0%, ${alpha(config.color, 0.05)} 100%)`,
                      borderBottom: `2px solid ${hasResult ? statusColor : config.color}`,
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
                              bgcolor: hasResult ? statusColor : '#9ca3af',
                              ...(isChecking && !hasResult ? {
                                animation: 'pulse 1.5s ease-in-out infinite',
                                '@keyframes pulse': {
                                  '0%, 100%': { opacity: 1, transform: 'scale(1)' },
                                  '50%': { opacity: 0.5, transform: 'scale(1.3)' },
                                },
                              } : {}),
                            }}
                          />
                          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                            {hasResult ? status.charAt(0).toUpperCase() + status.slice(1) :
                             isChecking ? 'Checking' : 'Pending'}
                          </Typography>
                        </Box>
                      </Box>
                    </Box>
                    <IconButton
                      size="small"
                      onClick={() => handleRemoveDevice(device.id)}
                      sx={{ p: 0.5, color: 'text.secondary', '&:hover': { color: 'error.main' } }}
                    >
                      <Delete sx={{ fontSize: 18 }} />
                    </IconButton>
                  </Box>

                  <CardContent sx={{ flexGrow: 1, p: 2 }}>
                    {/* Host */}
                    <Typography variant="body1" sx={{ fontWeight: 600, mb: 1.5, color: 'text.primary' }}>
                      {device.host}
                    </Typography>

                    {hasResult ? (
                      <>
                        {/* Quick status message */}
                        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
                          {result?.message}
                        </Typography>

                        {/* Quick status chips */}
                        {quickStatus.length > 0 && (
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                            {quickStatus.map(({ name, ok }) => (
                              <Chip
                                key={name}
                                label={name}
                                size="small"
                                icon={ok ? <CheckCircle sx={{ fontSize: 14 }} /> : <Warning sx={{ fontSize: 14 }} />}
                                sx={{
                                  height: 24,
                                  fontSize: '0.7rem',
                                  fontWeight: ok ? 400 : 600,
                                  bgcolor: ok ? alpha('#22c55e', 0.1) : '#eab308',
                                  color: ok ? '#22c55e' : 'white',
                                  border: ok ? `1px solid ${alpha('#22c55e', 0.3)}` : 'none',
                                  '& .MuiChip-icon': { color: ok ? '#22c55e' : 'white' },
                                }}
                              />
                            ))}
                          </Box>
                        )}

                        {result && !result.reachable && (
                          <Chip
                            size="small"
                            label="Unreachable"
                            color="error"
                            sx={{ height: 24, fontSize: '0.7rem', mt: 1 }}
                          />
                        )}
                      </>
                    ) : (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {isChecking ? (
                          <CircularProgress size={14} sx={{ color: ACCENT_COLOR }} />
                        ) : (
                          <HelpOutline sx={{ fontSize: 14, color: 'text.disabled' }} />
                        )}
                        <Typography variant="caption" color="text.secondary">
                          {isChecking ? 'Running checks...' : 'Not checked yet'}
                        </Typography>
                      </Box>
                    )}
                  </CardContent>

                  <CardActions sx={{ px: 2, pb: 1.5, pt: 0, borderTop: '1px solid', borderColor: 'divider' }}>
                    <Button
                      size="small"
                      onClick={() => result && setSelectedDevice(result)}
                      disabled={!hasResult}
                      sx={{
                        fontSize: '0.75rem',
                        color: hasResult ? config.color : 'text.disabled',
                        '&:hover': { bgcolor: alpha(config.color, 0.08) },
                      }}
                    >
                      View Details
                    </Button>
                    <Button
                      size="small"
                      startIcon={<Download sx={{ fontSize: 14 }} />}
                      onClick={() => result && downloadDeviceReport(result, 'json')}
                      disabled={!hasResult}
                      variant={hasResult ? 'contained' : 'text'}
                      sx={{
                        ml: 'auto',
                        fontSize: '0.75rem',
                        ...(hasResult ? {
                          bgcolor: ACCENT_COLOR,
                          '&:hover': { bgcolor: '#059669' },
                        } : {}),
                      }}
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

      {/* Loading overlay */}
      {isChecking && devices.length > 0 && !healthResult && (
        <Paper
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            py: 6,
            mt: 3,
            borderRadius: 3,
            border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
            bgcolor: alpha(ACCENT_COLOR, 0.02),
          }}
        >
          <Box sx={{ position: 'relative', display: 'inline-flex' }}>
            <CircularProgress
              size={70}
              thickness={3}
              sx={{ color: ACCENT_COLOR }}
            />
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
              }}
            >
              <HealthAndSafety sx={{ fontSize: 28, color: ACCENT_COLOR }} />
            </Box>
          </Box>
          <Typography variant="h6" fontWeight={600} sx={{ mt: 2, color: 'text.primary' }}>
            Running Health Checks
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Checking {devices.length} device{devices.length > 1 ? 's' : ''}...
          </Typography>
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
                onChange={e => handleDeviceTypeChange(e.target.value as DeviceType)}
              >
                <MenuItem value="cucm">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CucmIcon /> CUCM
                  </Box>
                </MenuItem>
                <MenuItem value="cube">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CubeIcon /> CUBE / IOS-XE
                  </Box>
                </MenuItem>
                <MenuItem value="expressway">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <ExpresswayIcon /> Expressway
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>

            <TextField
              label="Host"
              value={newHost}
              onChange={e => setNewHost(e.target.value)}
              placeholder="172.168.0.101"
              fullWidth
            />

            <TextField
              label={newDeviceType === 'expressway' ? 'HTTPS Port' : 'SSH Port'}
              type="number"
              value={newPort}
              onChange={e => setNewPort(Number(e.target.value))}
              fullWidth
            />

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

            <Divider sx={{ my: 1 }} />
            <Typography variant="subtitle2">Checks to Run</Typography>
            {renderCheckSelection()}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAddDevice(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAddDevice}
            disabled={!newHost || !newUsername || !newPassword}
          >
            Add Device
          </Button>
        </DialogActions>
      </Dialog>

      {/* Device Detail Dialog */}
      <Dialog
        open={!!selectedDevice}
        onClose={() => setSelectedDevice(null)}
        maxWidth="md"
        fullWidth
      >
        {selectedDevice && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Chip
                    icon={deviceTypeConfig[selectedDevice.device_type].icon}
                    label={deviceTypeConfig[selectedDevice.device_type].label}
                    sx={{
                      bgcolor: deviceTypeConfig[selectedDevice.device_type].color,
                      color: 'white',
                    }}
                  />
                  <Typography variant="h6">{selectedDevice.host}</Typography>
                  <HealthStatusBadge status={selectedDevice.status} />
                </Box>
                <IconButton onClick={() => setSelectedDevice(null)}>
                  <Close />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent>
              <Box sx={{ mb: 2 }}>
                <Typography color="text.secondary">
                  {selectedDevice.message}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Checked at {formatTime(selectedDevice.checked_at)}
                </Typography>
              </Box>

              {renderDeviceDetails(selectedDevice)}
            </DialogContent>
            <DialogActions>
              <Button
                startIcon={<ContentCopy />}
                onClick={() => copyToClipboard(selectedDevice, 'Device data')}
              >
                Copy All
              </Button>
              <Button
                startIcon={<Download />}
                onClick={() => downloadDeviceReport(selectedDevice, 'json')}
              >
                Download JSON
              </Button>
              <Button
                startIcon={<Download />}
                onClick={() => downloadDeviceReport(selectedDevice, 'txt')}
              >
                Download TXT
              </Button>
              <Button variant="contained" onClick={() => setSelectedDevice(null)}>
                Close
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  )
}
