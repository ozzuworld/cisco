import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Chip,
  Box,
  LinearProgress,
  IconButton,
  Tooltip,
  Button,
  Stack,
} from '@mui/material'
import {
  CheckCircle,
  Error,
  HourglassEmpty,
  Cancel,
  Download,
  Visibility,
  Stop,
} from '@mui/icons-material'
import type { Job } from '@/types'

interface JobStatusCardProps {
  job: Job
  onView?: (jobId: string) => void
  onCancel?: (jobId: string) => void
  onDownload?: (jobId: string) => void
}

const statusConfig: Record<
  string,
  {
    color: 'default' | 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success'
    icon: React.ReactElement
    label: string
  }
> = {
  pending: {
    color: 'default',
    icon: <HourglassEmpty />,
    label: 'Pending',
  },
  accepted: {
    color: 'info',
    icon: <HourglassEmpty />,
    label: 'Accepted',
  },
  queued: {
    color: 'default',
    icon: <HourglassEmpty />,
    label: 'Queued',
  },
  running: {
    color: 'info',
    icon: <HourglassEmpty />,
    label: 'Running',
  },
  completed: {
    color: 'success',
    icon: <CheckCircle />,
    label: 'Completed',
  },
  failed: {
    color: 'error',
    icon: <Error />,
    label: 'Failed',
  },
  cancelled: {
    color: 'warning',
    icon: <Cancel />,
    label: 'Cancelled',
  },
}

function formatDuration(seconds?: number): string {
  if (!seconds) return 'N/A'
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60

  if (hours > 0) {
    return `${hours}h ${minutes}m ${secs}s`
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`
  } else {
    return `${secs}s`
  }
}

function formatDate(dateString: string): string {
  const date = new Date(dateString)
  return date.toLocaleString()
}

export default function JobStatusCard({ job, onView, onCancel, onDownload }: JobStatusCardProps) {
  // Fallback for unknown status values from backend
  const statusInfo = statusConfig[job.status] || {
    color: 'default' as const,
    icon: <HourglassEmpty />,
    label: job.status || 'Unknown',
  }
  const isRunning = job.status === 'running'
  const isCompleted = job.status === 'completed'
  const canCancel = isRunning && onCancel
  const canDownload = isCompleted && onDownload

  return (
    <Card elevation={2} sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <CardContent sx={{ flexGrow: 1 }}>
        <Box
          sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}
        >
          <Box>
            <Typography variant="h6" component="div" gutterBottom>
              {job.clusterName}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Job ID: {job.id}
            </Typography>
          </Box>
          <Chip
            icon={statusInfo.icon}
            label={statusInfo.label}
            color={statusInfo.color}
            size="small"
          />
        </Box>

        <Stack spacing={1} sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="body2" color="text.secondary">
              Profile:
            </Typography>
            <Typography variant="body2">{job.profileName}</Typography>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="body2" color="text.secondary">
              Nodes:
            </Typography>
            <Typography variant="body2">{job.nodes?.length || 0}</Typography>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="body2" color="text.secondary">
              Created:
            </Typography>
            <Typography variant="body2">{formatDate(job.createdAt)}</Typography>
          </Box>

          {job.duration && (
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="body2" color="text.secondary">
                Duration:
              </Typography>
              <Typography variant="body2">{formatDuration(job.duration)}</Typography>
            </Box>
          )}
        </Stack>

        {isRunning && job.progress !== undefined && (
          <Box sx={{ mt: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="body2" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="body2">{job.progress}%</Typography>
            </Box>
            <LinearProgress variant="determinate" value={job.progress} />
          </Box>
        )}

        {job.status === 'failed' && job.error && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" color="error">
              Error: {job.error}
            </Typography>
          </Box>
        )}
      </CardContent>

      <CardActions sx={{ justifyContent: 'space-between', px: 2, pb: 2 }}>
        <Box>
          {onView && (
            <Tooltip title="View Details">
              <IconButton size="small" onClick={() => onView(job.id)} color="primary">
                <Visibility />
              </IconButton>
            </Tooltip>
          )}
          {canDownload && (
            <Tooltip title="Download Logs">
              <IconButton size="small" onClick={() => onDownload(job.id)} color="primary">
                <Download />
              </IconButton>
            </Tooltip>
          )}
        </Box>
        {canCancel && (
          <Button size="small" startIcon={<Stop />} color="error" onClick={() => onCancel(job.id)}>
            Cancel
          </Button>
        )}
      </CardActions>
    </Card>
  )
}
