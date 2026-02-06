import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Button,
  Stepper,
  Step,
  StepLabel,
  Card,
  CardContent,
  CardActionArea,
  Grid,
  Checkbox,
  FormControlLabel,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Divider,
  IconButton,
  Tooltip,
  alpha,
  Switch,
} from '@mui/material'
import {
  Troubleshoot as TroubleshootIcon,
  PhoneInTalk as PhoneIcon,
  Route as RouteIcon,
  AppRegistration as RegisterIcon,
  Hub as HubIcon,
  Build as BuildIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Storage as StorageIcon,
  Router as RouterIcon,
  Computer as ComputerIcon,
  Cloud as CloudIcon,
} from '@mui/icons-material'
import { useSnackbar } from 'notistack'
import { LoadingSpinner } from '@/components'
import { useScenarios, useCreateInvestigation } from '@/hooks/useInvestigation'
import { useCredentials } from '@/context'
import type { ScenarioTemplate, CreateInvestigationRequest, InlineDevice } from '@/types/investigation'
import type { EnvironmentDeviceType } from '@/types/environment'

// ---------- Fun name generator ----------
const COLORS = [
  'Red', 'Blue', 'Green', 'Gold', 'Purple', 'Orange', 'Silver', 'Teal',
  'Coral', 'Amber', 'Crimson', 'Jade', 'Cobalt', 'Scarlet', 'Ivory',
]
const EMOTIONS = [
  'Happy', 'Brave', 'Swift', 'Bold', 'Calm', 'Fierce', 'Sleepy', 'Wise',
  'Grumpy', 'Lucky', 'Noble', 'Sneaky', 'Jolly', 'Lazy', 'Spicy',
]
const ANIMALS = [
  'Panda', 'Tiger', 'Falcon', 'Otter', 'Wolf', 'Eagle', 'Dolphin', 'Fox',
  'Owl', 'Bear', 'Hawk', 'Lynx', 'Penguin', 'Raven', 'Badger',
]

function generateFunName(): string {
  const pick = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)]
  return `${pick(COLORS)} ${pick(EMOTIONS)} ${pick(ANIMALS)}`
}

// ---------- Constants ----------
const SCENARIO_ICONS: Record<string, JSX.Element> = {
  call_quality: <PhoneIcon sx={{ fontSize: 40 }} />,
  call_routing: <RouteIcon sx={{ fontSize: 40 }} />,
  registration: <RegisterIcon sx={{ fontSize: 40 }} />,
  b2b_federation: <HubIcon sx={{ fontSize: 40 }} />,
  custom: <BuildIcon sx={{ fontSize: 40 }} />,
}

const SCENARIO_COLORS: Record<string, string> = {
  call_quality: '#1976d2',
  call_routing: '#7c3aed',
  registration: '#0d9488',
  b2b_federation: '#ed6c02',
  custom: '#64748b',
}

const DEVICE_TYPE_LABELS: Record<EnvironmentDeviceType, string> = {
  cucm: 'CUCM',
  cube: 'CUBE',
  csr1000v: 'CSR1000v',
  expressway: 'Expressway',
}

const DEVICE_TYPE_COLORS: Record<EnvironmentDeviceType, string> = {
  cucm: '#1976d2',
  cube: '#0d9488',
  csr1000v: '#7c3aed',
  expressway: '#ed6c02',
}

const DEVICE_INTERFACE_DEFAULTS: Record<EnvironmentDeviceType, string> = {
  cucm: 'eth0',
  cube: 'GigabitEthernet1',
  csr1000v: 'GigabitEthernet1',
  expressway: 'eth0',
}

function DeviceTypeIcon({ type }: { type: EnvironmentDeviceType }) {
  const props = { sx: { color: DEVICE_TYPE_COLORS[type], fontSize: 20 } }
  switch (type) {
    case 'cucm': return <StorageIcon {...props} />
    case 'cube': return <RouterIcon {...props} />
    case 'csr1000v': return <ComputerIcon {...props} />
    case 'expressway': return <CloudIcon {...props} />
  }
}

const STEPS = ['Scenario', 'Devices', 'Operations', 'Configure', 'Credentials & Start']

const ALL_OPERATIONS = [
  { key: 'trace', label: 'Trace Levels', desc: 'Set CUCM trace levels for debugging' },
  { key: 'capture', label: 'Packet Capture', desc: 'Capture network packets on devices' },
  { key: 'logs', label: 'Log Collection', desc: 'Collect logs from CUCM/CUBE/Expressway' },
  { key: 'health', label: 'Health Check', desc: 'Run device health checks' },
]

// Per-device credential state
interface DeviceCredential {
  username: string
  password: string
}

// Extended inline device with interface for the form
interface WizardDevice extends InlineDevice {
  interface_name: string
}

const EMPTY_DEVICE: WizardDevice = { name: '', device_type: 'cucm', host: '', interface_name: 'eth0' }

export default function InvestigationWizard() {
  const navigate = useNavigate()
  const { enqueueSnackbar } = useSnackbar()
  const { data: scenarioData, isLoading: scenariosLoading } = useScenarios()
  const createInv = useCreateInvestigation()
  const { setGlobalCredentials } = useCredentials()

  const [activeStep, setActiveStep] = useState(0)

  // Wizard state
  const [selectedScenario, setSelectedScenario] = useState<ScenarioTemplate | null>(null)
  const [devices, setDevices] = useState<WizardDevice[]>([])
  const [operations, setOperations] = useState<string[]>([])
  const [investigationName, setInvestigationName] = useState('')
  const [envName] = useState(() => generateFunName())
  // Add-device form
  const [newDevice, setNewDevice] = useState<WizardDevice>({ ...EMPTY_DEVICE })
  // Config
  const [traceLevel, setTraceLevel] = useState('detailed')
  const [captureMode, setCaptureMode] = useState('standard')
  const [captureDuration, setCaptureDuration] = useState(120)
  const [cucmProfile, setCucmProfile] = useState('callmanager_full')
  // Credentials
  const [globalUsername, setGlobalUsername] = useState('')
  const [globalPassword, setGlobalPassword] = useState('')
  const [perDeviceCreds, setPerDeviceCreds] = useState<Record<number, DeviceCredential>>({})
  const [usePerDevice, setUsePerDevice] = useState(false)

  const scenarios = scenarioData?.scenarios || []

  const handleSelectScenario = (scenario: ScenarioTemplate) => {
    setSelectedScenario(scenario)
    if (scenario.name !== 'custom') {
      setOperations([...scenario.operations])
      if (scenario.trace_level) setTraceLevel(scenario.trace_level)
      if (scenario.capture_mode) setCaptureMode(scenario.capture_mode)
      if (scenario.capture_duration_sec) setCaptureDuration(scenario.capture_duration_sec)
      if (scenario.cucm_profile) setCucmProfile(scenario.cucm_profile)
    }
    if (!investigationName) {
      setInvestigationName(`${scenario.display_name} - ${new Date().toLocaleDateString()}`)
    }
    setActiveStep(1)
  }

  const handleDeviceTypeChange = (type: EnvironmentDeviceType) => {
    setNewDevice(prev => ({
      ...prev,
      device_type: type,
      interface_name: DEVICE_INTERFACE_DEFAULTS[type],
    }))
  }

  const handleAddDevice = () => {
    if (!newDevice.host.trim()) return
    const deviceName = newDevice.name.trim() || `${DEVICE_TYPE_LABELS[newDevice.device_type].toLowerCase()}-${newDevice.host.trim()}`
    setDevices(prev => [...prev, {
      ...newDevice,
      name: deviceName,
      host: newDevice.host.trim(),
      interface_name: newDevice.interface_name || DEVICE_INTERFACE_DEFAULTS[newDevice.device_type],
    }])
    setNewDevice({ ...EMPTY_DEVICE })
  }

  const handleRemoveDevice = (index: number) => {
    setDevices(prev => prev.filter((_, i) => i !== index))
    setPerDeviceCreds(prev => {
      const next = { ...prev }
      delete next[index]
      // Re-index
      const reindexed: Record<number, DeviceCredential> = {}
      Object.entries(next).forEach(([key, val]) => {
        const k = parseInt(key)
        reindexed[k > index ? k - 1 : k] = val
      })
      return reindexed
    })
  }

  const handleToggleOperation = (op: string) => {
    setOperations(prev =>
      prev.includes(op) ? prev.filter(o => o !== op) : [...prev, op]
    )
  }

  const handlePerDeviceCredChange = (index: number, field: 'username' | 'password', value: string) => {
    setPerDeviceCreds(prev => ({
      ...prev,
      [index]: {
        ...prev[index] || { username: '', password: '' },
        [field]: value,
      },
    }))
  }

  const handleStart = async () => {
    if (!selectedScenario || devices.length === 0) {
      enqueueSnackbar('Please fill in all required fields', { variant: 'warning' })
      return
    }

    if (!usePerDevice && (!globalUsername || !globalPassword)) {
      enqueueSnackbar('Please enter credentials', { variant: 'warning' })
      return
    }

    // Build credentials dict
    const credentials: Record<string, { username: string; password: string }> = {}
    if (usePerDevice) {
      // Per-device credentials - use global as fallback for any missing
      credentials.global = { username: globalUsername, password: globalPassword }
      devices.forEach((_, idx) => {
        const dc = perDeviceCreds[idx]
        if (dc?.username && dc?.password) {
          credentials[`device_${idx}`] = { username: dc.username, password: dc.password }
        }
      })
    } else {
      credentials.global = { username: globalUsername, password: globalPassword }
    }

    setGlobalCredentials({ username: globalUsername, password: globalPassword })

    // Convert WizardDevice to InlineDevice
    const inlineDevices: InlineDevice[] = devices.map(d => ({
      name: d.name,
      device_type: d.device_type,
      host: d.host,
      port: d.port,
      interface: d.interface_name || DEVICE_INTERFACE_DEFAULTS[d.device_type],
    }))

    const request: CreateInvestigationRequest = {
      name: investigationName || `${envName} - ${new Date().toLocaleDateString()}`,
      scenario: selectedScenario.name,
      inline_devices: inlineDevices,
      operations,
      cucm_profile: operations.includes('logs') ? cucmProfile : undefined,
      trace_level: operations.includes('trace') ? traceLevel : undefined,
      capture_mode: operations.includes('capture') ? captureMode : undefined,
      capture_duration_sec: operations.includes('capture') ? captureDuration : undefined,
      credentials,
    }

    try {
      const response = await createInv.mutateAsync(request)
      enqueueSnackbar('Investigation created', { variant: 'success' })
      navigate(`/investigations/${response.investigation_id}`)
    } catch (err) {
      enqueueSnackbar('Failed to create investigation', { variant: 'error' })
    }
  }

  const allCredsValid = useMemo(() => {
    if (!usePerDevice) return !!globalUsername && !!globalPassword
    // Per-device mode: every device needs creds (either its own or global fallback)
    const hasGlobal = !!globalUsername && !!globalPassword
    for (let i = 0; i < devices.length; i++) {
      const dc = perDeviceCreds[i]
      const hasOwn = !!dc?.username && !!dc?.password
      if (!hasOwn && !hasGlobal) return false
    }
    return true
  }, [usePerDevice, globalUsername, globalPassword, devices.length, perDeviceCreds])

  const canNext = useMemo(() => {
    switch (activeStep) {
      case 0: return !!selectedScenario
      case 1: return devices.length > 0
      case 2: return operations.length > 0
      case 3: return true
      case 4: return allCredsValid
      default: return false
    }
  }, [activeStep, selectedScenario, devices, operations, allCredsValid])

  if (scenariosLoading) return <LoadingSpinner message="Loading..." />

  return (
    <Box sx={{ maxWidth: 960, mx: 'auto' }}>
      <Typography variant="h4" fontWeight={700} sx={{ mb: 1 }}>
        New Investigation
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Configure and start an orchestrated troubleshooting session.
      </Typography>

      <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
        {STEPS.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      {/* Step 0: Scenario */}
      {activeStep === 0 && (
        <Grid container spacing={2}>
          {scenarios.map((scenario) => {
            const color = SCENARIO_COLORS[scenario.name] || '#64748b'
            return (
              <Grid item xs={12} sm={6} md={4} key={scenario.name}>
                <Card
                  sx={{
                    border: selectedScenario?.name === scenario.name ? `2px solid ${color}` : '2px solid transparent',
                    transition: 'all 0.2s',
                    '&:hover': { borderColor: alpha(color, 0.5) },
                  }}
                >
                  <CardActionArea onClick={() => handleSelectScenario(scenario)} sx={{ p: 3 }}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Box sx={{ color, mb: 1 }}>
                        {SCENARIO_ICONS[scenario.name] || <TroubleshootIcon sx={{ fontSize: 40 }} />}
                      </Box>
                      <Typography variant="h6" fontWeight={600}>{scenario.display_name}</Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        {scenario.description || 'No description'}
                      </Typography>
                      {scenario.operations.length > 0 && (
                        <Box sx={{ mt: 2, display: 'flex', flexWrap: 'wrap', gap: 0.5, justifyContent: 'center' }}>
                          {scenario.operations.map(op => (
                            <Chip key={op} label={op} size="small" variant="outlined" />
                          ))}
                        </Box>
                      )}
                    </Box>
                  </CardActionArea>
                </Card>
              </Grid>
            )
          })}
        </Grid>
      )}

      {/* Step 1: Devices - Inline entry */}
      {activeStep === 1 && (
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
            <Box>
              <Typography variant="subtitle1" fontWeight={600}>
                Add devices for this case
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Quick session: <strong>{envName}</strong>
              </Typography>
            </Box>
          </Box>

          {/* Add device form - inline row */}
          <Card variant="outlined" sx={{ p: 2, mb: 3 }}>
            <Grid container spacing={1.5} alignItems="center">
              <Grid item xs={12} sm={3}>
                <TextField
                  autoFocus
                  fullWidth
                  size="small"
                  label="Host / IP"
                  placeholder="10.10.10.10"
                  value={newDevice.host}
                  onChange={(e) => setNewDevice(prev => ({ ...prev, host: e.target.value }))}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleAddDevice() }}
                />
              </Grid>
              <Grid item xs={6} sm={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Type</InputLabel>
                  <Select
                    value={newDevice.device_type}
                    label="Type"
                    onChange={(e) => handleDeviceTypeChange(e.target.value as EnvironmentDeviceType)}
                  >
                    <MenuItem value="cucm">CUCM</MenuItem>
                    <MenuItem value="cube">CUBE</MenuItem>
                    <MenuItem value="csr1000v">CSR1000v</MenuItem>
                    <MenuItem value="expressway">Expressway</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6} sm={3}>
                <TextField
                  fullWidth
                  size="small"
                  label="Interface"
                  placeholder={DEVICE_INTERFACE_DEFAULTS[newDevice.device_type]}
                  value={newDevice.interface_name}
                  onChange={(e) => setNewDevice(prev => ({ ...prev, interface_name: e.target.value }))}
                />
              </Grid>
              <Grid item xs={8} sm={2.5}>
                <TextField
                  fullWidth
                  size="small"
                  label="Name (optional)"
                  placeholder={`auto: ${newDevice.device_type}-${newDevice.host || 'ip'}`}
                  value={newDevice.name}
                  onChange={(e) => setNewDevice(prev => ({ ...prev, name: e.target.value }))}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleAddDevice() }}
                />
              </Grid>
              <Grid item xs={4} sm={1.5}>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={handleAddDevice}
                  disabled={!newDevice.host.trim()}
                  fullWidth
                  sx={{ height: 40 }}
                >
                  Add
                </Button>
              </Grid>
            </Grid>
          </Card>

          {/* Device list */}
          {devices.length === 0 ? (
            <Alert severity="info">
              No devices added yet. Add at least one device above to continue.
            </Alert>
          ) : (
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Host</TableCell>
                    <TableCell>Interface</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {devices.map((device, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <DeviceTypeIcon type={device.device_type} />
                          {device.name}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={DEVICE_TYPE_LABELS[device.device_type]}
                          size="small"
                          sx={{
                            bgcolor: `${DEVICE_TYPE_COLORS[device.device_type]}20`,
                            color: DEVICE_TYPE_COLORS[device.device_type],
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{device.host}</TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{device.interface_name}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="Remove device">
                          <IconButton size="small" color="error" onClick={() => handleRemoveDevice(index)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            {devices.length} device{devices.length !== 1 ? 's' : ''} added
          </Typography>
        </Box>
      )}

      {/* Step 2: Operations */}
      {activeStep === 2 && (
        <Box>
          <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
            Select operations to run
          </Typography>
          <Grid container spacing={2}>
            {ALL_OPERATIONS.map(op => (
              <Grid item xs={12} sm={6} key={op.key}>
                <Card
                  sx={{
                    border: operations.includes(op.key) ? '2px solid' : '2px solid transparent',
                    borderColor: operations.includes(op.key) ? 'primary.main' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                  onClick={() => handleToggleOperation(op.key)}
                >
                  <CardContent>
                    <FormControlLabel
                      control={<Checkbox checked={operations.includes(op.key)} />}
                      label={
                        <Box>
                          <Typography fontWeight={600}>{op.label}</Typography>
                          <Typography variant="body2" color="text.secondary">{op.desc}</Typography>
                        </Box>
                      }
                    />
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Step 3: Configure */}
      {activeStep === 3 && (
        <Box>
          <TextField
            fullWidth
            label="Investigation Name"
            value={investigationName}
            onChange={(e) => setInvestigationName(e.target.value)}
            sx={{ mb: 3 }}
          />

          {operations.includes('trace') && (
            <Card variant="outlined" sx={{ mb: 2, p: 2 }}>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>Trace Level</Typography>
              <FormControl fullWidth size="small">
                <InputLabel>Level</InputLabel>
                <Select value={traceLevel} label="Level" onChange={(e) => setTraceLevel(e.target.value)}>
                  <MenuItem value="basic">Basic</MenuItem>
                  <MenuItem value="detailed">Detailed</MenuItem>
                  <MenuItem value="verbose">Verbose</MenuItem>
                </Select>
              </FormControl>
            </Card>
          )}

          {operations.includes('capture') && (
            <Card variant="outlined" sx={{ mb: 2, p: 2 }}>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>Packet Capture</Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Mode</InputLabel>
                    <Select value={captureMode} label="Mode" onChange={(e) => setCaptureMode(e.target.value)}>
                      <MenuItem value="standard">Standard</MenuItem>
                      <MenuItem value="rotating">Rotating</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    fullWidth
                    size="small"
                    type="number"
                    label="Duration (sec)"
                    value={captureDuration}
                    onChange={(e) => setCaptureDuration(parseInt(e.target.value) || 120)}
                    inputProps={{ min: 10, max: 600 }}
                  />
                </Grid>
              </Grid>
            </Card>
          )}

          {operations.includes('logs') && (
            <Card variant="outlined" sx={{ mb: 2, p: 2 }}>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>Log Collection</Typography>
              <FormControl fullWidth size="small">
                <InputLabel>CUCM Profile</InputLabel>
                <Select value={cucmProfile} label="CUCM Profile" onChange={(e) => setCucmProfile(e.target.value)}>
                  <MenuItem value="callmanager_full">CallManager Full</MenuItem>
                  <MenuItem value="callmanager_sdl">CallManager SDL</MenuItem>
                  <MenuItem value="cti_full">CTI Full</MenuItem>
                </Select>
              </FormControl>
            </Card>
          )}

          {operations.length === 0 && (
            <Alert severity="warning">No operations selected. Go back and select at least one operation.</Alert>
          )}
        </Box>
      )}

      {/* Step 4: Credentials & Start */}
      {activeStep === 4 && (
        <Box>
          <Alert severity="info" sx={{ mb: 3 }}>
            Credentials are held in memory only and are never stored to disk.
            They will be cleared when the investigation completes or after 30 minutes of inactivity.
          </Alert>

          {/* Global credentials */}
          <Card variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
              {usePerDevice ? 'Default Credentials (fallback)' : 'Device Credentials'}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {usePerDevice
                ? 'Used for any device without specific credentials below.'
                : 'These credentials will be used for all devices.'}
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Username"
                  value={globalUsername}
                  onChange={(e) => setGlobalUsername(e.target.value)}
                  autoComplete="off"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Password"
                  type="password"
                  value={globalPassword}
                  onChange={(e) => setGlobalPassword(e.target.value)}
                  autoComplete="off"
                />
              </Grid>
            </Grid>
          </Card>

          {/* Per-device toggle */}
          <Box sx={{ mb: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={usePerDevice}
                  onChange={(e) => setUsePerDevice(e.target.checked)}
                />
              }
              label="Different credentials per device"
            />
          </Box>

          {/* Per-device credentials */}
          {usePerDevice && (
            <Card variant="outlined" sx={{ p: 3, mb: 3 }}>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
                Per-Device Credentials
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Leave blank to use the default credentials above.
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Device</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Host</TableCell>
                      <TableCell>Username</TableCell>
                      <TableCell>Password</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {devices.map((device, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <DeviceTypeIcon type={device.device_type} />
                            {device.name}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip label={DEVICE_TYPE_LABELS[device.device_type]} size="small" />
                        </TableCell>
                        <TableCell sx={{ fontFamily: 'monospace' }}>{device.host}</TableCell>
                        <TableCell>
                          <TextField
                            size="small"
                            placeholder={globalUsername || 'username'}
                            value={perDeviceCreds[idx]?.username || ''}
                            onChange={(e) => handlePerDeviceCredChange(idx, 'username', e.target.value)}
                            autoComplete="off"
                            sx={{ minWidth: 120 }}
                          />
                        </TableCell>
                        <TableCell>
                          <TextField
                            size="small"
                            type="password"
                            placeholder={globalPassword ? '••••••' : 'password'}
                            value={perDeviceCreds[idx]?.password || ''}
                            onChange={(e) => handlePerDeviceCredChange(idx, 'password', e.target.value)}
                            autoComplete="off"
                            sx={{ minWidth: 120 }}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Card>
          )}

          {/* Summary */}
          <Card variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>Summary</Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Typography variant="body2">
                <strong>Session:</strong> {envName}
              </Typography>
              <Typography variant="body2">
                <strong>Scenario:</strong> {selectedScenario?.display_name}
              </Typography>
              <Typography variant="body2">
                <strong>Devices:</strong> {devices.length} device{devices.length !== 1 ? 's' : ''}
              </Typography>
              <Box sx={{ ml: 2 }}>
                {devices.map((d, i) => (
                  <Typography key={i} variant="body2" color="text.secondary">
                    {d.name} ({DEVICE_TYPE_LABELS[d.device_type]}) — {d.host} [{d.interface_name}]
                    {usePerDevice && perDeviceCreds[i]?.username ? ` (${perDeviceCreds[i].username})` : ''}
                  </Typography>
                ))}
              </Box>
              <Typography variant="body2">
                <strong>Operations:</strong>{' '}
                {operations.map(op => (
                  <Chip key={op} label={op} size="small" sx={{ mr: 0.5 }} />
                ))}
              </Typography>
              <Typography variant="body2">
                <strong>Active Phases:</strong>{' '}
                {operations.includes('trace') || operations.includes('health') ? 'Prepare ' : ''}
                {operations.includes('capture') ? 'Record ' : ''}
                {operations.includes('logs') || operations.includes('capture') ? 'Collect' : ''}
              </Typography>
            </Box>
          </Card>
        </Box>
      )}

      {/* Navigation */}
      <Divider sx={{ my: 3 }} />
      <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <Button
          onClick={() => activeStep === 0 ? navigate('/') : setActiveStep(prev => prev - 1)}
          variant="outlined"
        >
          {activeStep === 0 ? 'Cancel' : 'Back'}
        </Button>
        {activeStep < STEPS.length - 1 ? (
          <Button
            onClick={() => setActiveStep(prev => prev + 1)}
            variant="contained"
            disabled={!canNext}
          >
            Next
          </Button>
        ) : (
          <Button
            onClick={handleStart}
            variant="contained"
            color="success"
            disabled={!canNext || createInv.isPending}
          >
            {createInv.isPending ? 'Starting...' : 'Start Investigation'}
          </Button>
        )}
      </Box>
    </Box>
  )
}
