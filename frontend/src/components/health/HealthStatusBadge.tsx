import { Chip, Tooltip } from '@mui/material'
import {
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Help,
} from '@mui/icons-material'
import type { HealthStatus } from '@/types'

interface HealthStatusBadgeProps {
  status: HealthStatus
  size?: 'small' | 'medium'
  showLabel?: boolean
}

const statusConfig: Record<HealthStatus, {
  color: 'success' | 'warning' | 'error' | 'default'
  icon: React.ReactElement
  label: string
  tooltip: string
}> = {
  healthy: {
    color: 'success',
    icon: <CheckCircle />,
    label: 'Healthy',
    tooltip: 'All checks passed, system operating normally',
  },
  degraded: {
    color: 'warning',
    icon: <Warning />,
    label: 'Degraded',
    tooltip: 'Some issues detected, system may have reduced functionality',
  },
  critical: {
    color: 'error',
    icon: <ErrorIcon />,
    label: 'Critical',
    tooltip: 'Major issues detected, immediate attention required',
  },
  unknown: {
    color: 'default',
    icon: <Help />,
    label: 'Unknown',
    tooltip: 'Unable to determine status',
  },
}

export function HealthStatusBadge({ status, size = 'medium', showLabel = true }: HealthStatusBadgeProps) {
  const config = statusConfig[status] || statusConfig.unknown

  return (
    <Tooltip title={config.tooltip} arrow>
      <Chip
        icon={config.icon}
        label={showLabel ? config.label : undefined}
        color={config.color}
        size={size}
        sx={showLabel ? undefined : { '& .MuiChip-label': { display: 'none' } }}
      />
    </Tooltip>
  )
}

export default HealthStatusBadge
