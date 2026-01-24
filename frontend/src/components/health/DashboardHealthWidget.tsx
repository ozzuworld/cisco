import { useNavigate } from 'react-router-dom'
import { Paper, Box, Typography, Button, Chip } from '@mui/material'
import {
  HealthAndSafety,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  HelpOutline,
  ArrowForward,
} from '@mui/icons-material'
import { useQueryClient } from '@tanstack/react-query'
import type { ClusterHealthResponse, HealthStatus } from '@/types'

const statusConfig: Record<HealthStatus, {
  color: 'success' | 'warning' | 'error' | 'default'
  icon: React.ReactElement
  label: string
}> = {
  healthy: {
    color: 'success',
    icon: <CheckCircle />,
    label: 'Healthy',
  },
  degraded: {
    color: 'warning',
    icon: <Warning />,
    label: 'Degraded',
  },
  critical: {
    color: 'error',
    icon: <ErrorIcon />,
    label: 'Critical',
  },
  unknown: {
    color: 'default',
    icon: <HelpOutline />,
    label: 'Unknown',
  },
}

export function DashboardHealthWidget() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  // Get cached health result
  const cachedHealth = queryClient.getQueryData<ClusterHealthResponse>(['clusterHealth', 'latest'])

  const formatTimeAgo = (dateStr: string) => {
    const diff = Date.now() - new Date(dateStr).getTime()
    const minutes = Math.floor(diff / 60000)
    if (minutes < 1) return 'Just now'
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    return `${Math.floor(hours / 24)}d ago`
  }

  if (!cachedHealth) {
    return (
      <Paper sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <HealthAndSafety color="primary" />
          <Typography variant="subtitle1">Cluster Health</Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          No health check has been run yet
        </Typography>
        <Button
          variant="outlined"
          size="small"
          endIcon={<ArrowForward />}
          onClick={() => navigate('/health')}
        >
          Run Health Check
        </Button>
      </Paper>
    )
  }

  const config = statusConfig[cachedHealth.cluster_status] || statusConfig.unknown

  return (
    <Paper sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <HealthAndSafety color="primary" />
        <Typography variant="subtitle1">Cluster Health</Typography>
        <Typography variant="caption" color="text.secondary" sx={{ ml: 'auto' }}>
          {formatTimeAgo(cachedHealth.checked_at)}
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
        <Chip
          icon={config.icon}
          label={config.label}
          color={config.color}
        />
        <Typography variant="body2" color="text.secondary">
          {cachedHealth.healthy_nodes}/{cachedHealth.total_nodes} nodes healthy
        </Typography>
      </Box>

      {cachedHealth.message && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {cachedHealth.message}
        </Typography>
      )}

      <Button
        variant="text"
        size="small"
        endIcon={<ArrowForward />}
        onClick={() => navigate('/health')}
      >
        View Details
      </Button>
    </Paper>
  )
}

export default DashboardHealthWidget
