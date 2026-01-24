import {
  Box,
  Typography,
  Button,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemText,
  Chip,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tooltip,
} from '@mui/material'
import {
  CheckCircle as CheckIcon,
  Storage as StorageIcon,
  Settings as SettingsIcon,
  Description as LogIcon,
  BugReport as DebugIcon,
  Info as InfoIcon,
} from '@mui/icons-material'
import type { ConnectionRequest, ClusterNode, LogProfile, DebugLevel } from '@/types'

interface ReviewStepProps {
  data: {
    connection: ConnectionRequest | null
    discoveredNodes: ClusterNode[]
    selectedNodes: string[]
    profile: LogProfile | null
    debugLevel: DebugLevel
  }
  onSubmit: () => void
  onBack: () => void
  onDebugLevelChange: (level: DebugLevel) => void
  isLoading: boolean
}

const DEBUG_LEVEL_OPTIONS: { value: DebugLevel; label: string; description: string }[] = [
  {
    value: 'basic',
    label: 'Basic (Default)',
    description: 'Standard trace levels, minimal performance impact',
  },
  {
    value: 'detailed',
    label: 'Detailed - TAC Troubleshooting',
    description: 'Increased verbosity for troubleshooting',
  },
  {
    value: 'verbose',
    label: 'Verbose - Full Debug',
    description: 'Maximum detail for deep debugging (may impact performance)',
  },
]

export function ReviewStep({ data, onSubmit, onBack, onDebugLevelChange, isLoading }: ReviewStepProps) {
  const { connection, discoveredNodes, selectedNodes, profile, debugLevel } = data

  const selectedNodeObjects = discoveredNodes.filter(n => selectedNodes.includes(n.ip))

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review Job Configuration
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Please review your selections before creating the log collection job.
      </Typography>

      {/* Connection Info */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <StorageIcon sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="subtitle1" fontWeight="medium">
            CUCM Connection
          </Typography>
        </Box>
        <Divider sx={{ my: 1 }} />
        <List dense>
          <ListItem>
            <ListItemText
              primary="Hostname"
              secondary={connection?.hostname}
              primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
              secondaryTypographyProps={{ variant: 'body1' }}
            />
          </ListItem>
          <ListItem>
            <ListItemText
              primary="Username"
              secondary={connection?.username}
              primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
              secondaryTypographyProps={{ variant: 'body1' }}
            />
          </ListItem>
          <ListItem>
            <ListItemText
              primary="Port"
              secondary={connection?.port || 22}
              primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
              secondaryTypographyProps={{ variant: 'body1' }}
            />
          </ListItem>
        </List>
      </Paper>

      {/* Selected Nodes */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <CheckIcon sx={{ mr: 1, color: 'success.main' }} />
          <Typography variant="subtitle1" fontWeight="medium">
            Selected Nodes ({selectedNodes.length})
          </Typography>
        </Box>
        <Divider sx={{ my: 1 }} />
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 2 }}>
          {selectedNodeObjects.map(node => (
            <Chip
              key={node.ip}
              label={`${node.host} (${node.role})`}
              color="primary"
              variant="outlined"
              size="small"
            />
          ))}
        </Box>
      </Paper>

      {/* Selected Profile */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <SettingsIcon sx={{ mr: 1, color: 'info.main' }} />
          <Typography variant="subtitle1" fontWeight="medium">
            Log Collection Profile
          </Typography>
        </Box>
        <Divider sx={{ my: 1 }} />
        <List dense>
          <ListItem>
            <ListItemText
              primary="Profile Name"
              secondary={profile?.name}
              primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
              secondaryTypographyProps={{ variant: 'body1', fontWeight: 'medium' }}
            />
          </ListItem>
          <ListItem>
            <ListItemText
              primary="Description"
              secondary={profile?.description}
              primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
              secondaryTypographyProps={{ variant: 'body2' }}
            />
          </ListItem>
          {profile?.logTypes && profile.logTypes.length > 0 && (
            <ListItem>
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Log Types ({profile.logTypes.length})
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
                  {profile.logTypes.map((logType, index) => (
                    <Chip
                      key={`${logType}-${index}`}
                      icon={<LogIcon />}
                      label={logType}
                      size="small"
                      variant="outlined"
                    />
                  ))}
                </Box>
              </Box>
            </ListItem>
          )}
        </List>
      </Paper>

      {/* Debug Level Selection */}
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <DebugIcon sx={{ mr: 1, color: 'warning.main' }} />
          <Typography variant="subtitle1" fontWeight="medium">
            Debug Level
          </Typography>
          <Tooltip title="Higher debug levels capture more detailed logs but may impact system performance. TAC typically requests 'Detailed' or 'Verbose' for troubleshooting.">
            <InfoIcon sx={{ ml: 1, fontSize: 18, color: 'text.secondary', cursor: 'help' }} />
          </Tooltip>
        </Box>
        <Divider sx={{ my: 1 }} />
        <FormControl fullWidth size="small" sx={{ mt: 1 }}>
          <InputLabel id="debug-level-label">Debug Level</InputLabel>
          <Select
            labelId="debug-level-label"
            value={debugLevel}
            label="Debug Level"
            onChange={(e) => onDebugLevelChange(e.target.value as DebugLevel)}
          >
            {DEBUG_LEVEL_OPTIONS.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                <Box>
                  <Typography variant="body2">{option.label}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {option.description}
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Paper>

      {/* Summary Alert */}
      <Alert severity="info" sx={{ mb: 3 }}>
        This job will collect <strong>{profile?.logTypes?.length || 0} log types</strong> from{' '}
        <strong>{selectedNodes.length} nodes</strong> in the cluster.
      </Alert>

      <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <Button onClick={onBack} disabled={isLoading}>
          Back
        </Button>
        <Button variant="contained" onClick={onSubmit} disabled={isLoading}>
          {isLoading ? 'Creating Job...' : 'Create Job'}
        </Button>
      </Box>
    </Box>
  )
}
