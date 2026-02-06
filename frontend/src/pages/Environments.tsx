import { useState } from 'react'
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  CardActions,
  Grid,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Tooltip,
  Alert,
  Collapse,
  Paper,
} from '@mui/material'
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Dns as DnsIcon,
  Search as SearchIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Router as RouterIcon,
  Storage as StorageIcon,
  Cloud as CloudIcon,
  Computer as ComputerIcon,
} from '@mui/icons-material'
import { LoadingSpinner, EmptyState } from '@/components'
import {
  useEnvironments,
  useCreateEnvironment,
  useDeleteEnvironment,
  useAddDevice,
  useRemoveDevice,
  useDiscoverNodes,
} from '@/hooks/useEnvironments'
import type { Environment, EnvironmentDeviceType, DeviceEntry } from '@/types/environment'

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

function DeviceTypeIcon({ type }: { type: EnvironmentDeviceType }) {
  const props = { sx: { color: DEVICE_TYPE_COLORS[type], fontSize: 20 } }
  switch (type) {
    case 'cucm': return <StorageIcon {...props} />
    case 'cube': return <RouterIcon {...props} />
    case 'csr1000v': return <ComputerIcon {...props} />
    case 'expressway': return <CloudIcon {...props} />
  }
}

// Create Environment Dialog
function CreateEnvironmentDialog({
  open,
  onClose,
  onCreate,
}: {
  open: boolean
  onClose: () => void
  onCreate: (name: string, description: string) => void
}) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  const handleSubmit = () => {
    if (!name.trim()) return
    onCreate(name.trim(), description.trim())
    setName('')
    setDescription('')
    onClose()
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Create Environment</DialogTitle>
      <DialogContent>
        <TextField
          autoFocus
          margin="dense"
          label="Environment Name"
          fullWidth
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g., Production Cluster, Lab Environment"
        />
        <TextField
          margin="dense"
          label="Description (optional)"
          fullWidth
          multiline
          rows={2}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="e.g., Main production CUCM cluster with 5 subscribers"
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" disabled={!name.trim()}>
          Create
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// Add Device Dialog
function AddDeviceDialog({
  open,
  onClose,
  onAdd,
}: {
  open: boolean
  onClose: () => void
  onAdd: (device: { name: string; device_type: EnvironmentDeviceType; host: string; port?: number; interface?: string; role?: string }) => void
}) {
  const [name, setName] = useState('')
  const [deviceType, setDeviceType] = useState<EnvironmentDeviceType>('cucm')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [iface, setIface] = useState('')
  const [role, setRole] = useState('')

  const handleSubmit = () => {
    if (!name.trim() || !host.trim()) return
    onAdd({
      name: name.trim(),
      device_type: deviceType,
      host: host.trim(),
      port: port ? parseInt(port) : undefined,
      interface: iface.trim() || undefined,
      role: role.trim() || undefined,
    })
    setName('')
    setHost('')
    setPort('')
    setIface('')
    setRole('')
    onClose()
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Add Device</DialogTitle>
      <DialogContent>
        <TextField
          autoFocus
          margin="dense"
          label="Device Name"
          fullWidth
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g., cucm-pub-01"
        />
        <FormControl fullWidth margin="dense">
          <InputLabel>Device Type</InputLabel>
          <Select
            value={deviceType}
            label="Device Type"
            onChange={(e) => setDeviceType(e.target.value as EnvironmentDeviceType)}
          >
            <MenuItem value="cucm">CUCM</MenuItem>
            <MenuItem value="cube">CUBE</MenuItem>
            <MenuItem value="csr1000v">CSR1000v</MenuItem>
            <MenuItem value="expressway">Expressway</MenuItem>
          </Select>
        </FormControl>
        <TextField
          margin="dense"
          label="Host (IP or FQDN)"
          fullWidth
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="e.g., 10.10.10.10"
        />
        <Grid container spacing={2}>
          <Grid item xs={6}>
            <TextField
              margin="dense"
              label="Port (optional)"
              fullWidth
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder={deviceType === 'expressway' ? '443' : '22'}
            />
          </Grid>
          <Grid item xs={6}>
            <TextField
              margin="dense"
              label="Interface (optional)"
              fullWidth
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              placeholder={deviceType === 'cube' || deviceType === 'csr1000v' ? 'GigabitEthernet1' : 'eth0'}
            />
          </Grid>
        </Grid>
        <TextField
          margin="dense"
          label="Role (optional)"
          fullWidth
          value={role}
          onChange={(e) => setRole(e.target.value)}
          placeholder="e.g., publisher, subscriber, primary"
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" disabled={!name.trim() || !host.trim()}>
          Add Device
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// Discover Dialog
function DiscoverDialog({
  open,
  onClose,
  onDiscover,
  isLoading,
}: {
  open: boolean
  onClose: () => void
  onDiscover: (host: string, username: string, password: string) => void
  isLoading: boolean
}) {
  const [host, setHost] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Discover CUCM Nodes</DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 2 }}>
          Connect to the CUCM Publisher to discover subscriber nodes automatically.
          Credentials are used only for this discovery and are not stored.
        </Alert>
        <TextField
          autoFocus
          margin="dense"
          label="Publisher Host"
          fullWidth
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="10.10.10.10"
        />
        <TextField
          margin="dense"
          label="Username"
          fullWidth
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <TextField
          margin="dense"
          label="Password"
          fullWidth
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={() => onDiscover(host, username, password)}
          variant="contained"
          disabled={!host || !username || !password || isLoading}
        >
          {isLoading ? 'Discovering...' : 'Discover'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// Environment Card
function EnvironmentCard({
  env,
  onDelete,
  onAddDevice,
  onRemoveDevice,
  onDiscover,
}: {
  env: Environment
  onDelete: (id: string) => void
  onAddDevice: (envId: string) => void
  onRemoveDevice: (envId: string, deviceId: string) => void
  onDiscover: (envId: string) => void
}) {
  const [expanded, setExpanded] = useState(true)

  const devicesByType: Record<string, DeviceEntry[]> = {}
  for (const d of env.devices) {
    const key = d.device_type
    if (!devicesByType[key]) devicesByType[key] = []
    devicesByType[key].push(d)
  }

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <DnsIcon color="primary" />
            <Typography variant="h6">{env.name}</Typography>
            <Chip label={`${env.devices.length} device${env.devices.length !== 1 ? 's' : ''}`} size="small" />
          </Box>
          <Box>
            <IconButton size="small" onClick={() => setExpanded(!expanded)}>
              {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </IconButton>
          </Box>
        </Box>
        {env.description && (
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {env.description}
          </Typography>
        )}
        <Collapse in={expanded}>
          {env.devices.length === 0 ? (
            <Alert severity="info" sx={{ mb: 2 }}>
              No devices yet. Add devices manually or discover CUCM nodes.
            </Alert>
          ) : (
            <TableContainer component={Paper} variant="outlined" sx={{ mb: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Host</TableCell>
                    <TableCell>Port</TableCell>
                    <TableCell>Interface</TableCell>
                    <TableCell>Role</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {env.devices.map((device) => (
                    <TableRow key={device.id}>
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
                      <TableCell>{device.port}</TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{device.interface}</TableCell>
                      <TableCell>{device.role || '-'}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="Remove device">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => onRemoveDevice(env.id, device.id)}
                          >
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
        </Collapse>
      </CardContent>
      <CardActions sx={{ px: 2, pb: 2, pt: 0 }}>
        <Button size="small" startIcon={<AddIcon />} onClick={() => onAddDevice(env.id)}>
          Add Device
        </Button>
        <Button size="small" startIcon={<SearchIcon />} onClick={() => onDiscover(env.id)}>
          Discover Nodes
        </Button>
        <Box sx={{ flexGrow: 1 }} />
        <Tooltip title="Delete environment">
          <IconButton size="small" color="error" onClick={() => onDelete(env.id)}>
            <DeleteIcon />
          </IconButton>
        </Tooltip>
      </CardActions>
    </Card>
  )
}

export default function Environments() {
  const { data, isLoading } = useEnvironments()
  const createEnv = useCreateEnvironment()
  const deleteEnv = useDeleteEnvironment()
  const addDevice = useAddDevice()
  const removeDevice = useRemoveDevice()
  const discover = useDiscoverNodes()

  const [createOpen, setCreateOpen] = useState(false)
  const [addDeviceEnvId, setAddDeviceEnvId] = useState<string | null>(null)
  const [discoverEnvId, setDiscoverEnvId] = useState<string | null>(null)

  if (isLoading) return <LoadingSpinner message="Loading environments..." />

  const environments = data?.environments || []

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h4" fontWeight={700}>Environments</Typography>
          <Typography variant="body2" color="text.secondary">
            Manage your device inventories. No credentials are stored.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
          New Environment
        </Button>
      </Box>

      {environments.length === 0 ? (
        <EmptyState
          title="No environments yet"
          description="Create an environment to organize your devices for investigations."
          actionLabel="Create Environment"
          onAction={() => setCreateOpen(true)}
        />
      ) : (
        environments.map((env) => (
          <EnvironmentCard
            key={env.id}
            env={env}
            onDelete={(id) => deleteEnv.mutate(id)}
            onAddDevice={(envId) => setAddDeviceEnvId(envId)}
            onRemoveDevice={(envId, deviceId) => removeDevice.mutate({ envId, deviceId })}
            onDiscover={(envId) => setDiscoverEnvId(envId)}
          />
        ))
      )}

      <CreateEnvironmentDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreate={(name, description) => createEnv.mutate({ name, description })}
      />

      <AddDeviceDialog
        open={!!addDeviceEnvId}
        onClose={() => setAddDeviceEnvId(null)}
        onAdd={(device) => {
          if (addDeviceEnvId) {
            addDevice.mutate({ envId: addDeviceEnvId, device })
          }
        }}
      />

      <DiscoverDialog
        open={!!discoverEnvId}
        onClose={() => setDiscoverEnvId(null)}
        onDiscover={(host, username, password) => {
          if (discoverEnvId) {
            discover.mutate(
              { envId: discoverEnvId, request: { publisher_host: host, username, password } },
              { onSuccess: () => setDiscoverEnvId(null) }
            )
          }
        }}
        isLoading={discover.isPending}
      />
    </Box>
  )
}
