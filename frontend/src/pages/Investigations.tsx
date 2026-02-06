import { useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
} from '@mui/material'
import {
  Add as AddIcon,
  Download as DownloadIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material'
import { LoadingSpinner, EmptyState } from '@/components'
import { useInvestigations, useDeleteInvestigation } from '@/hooks/useInvestigation'
import { investigationService } from '@/services/investigationService'
import type { InvestigationStatus } from '@/types/investigation'

const STATUS_CONFIG: Record<InvestigationStatus, { label: string; color: string }> = {
  created: { label: 'Created', color: '#64748b' },
  preparing: { label: 'Preparing', color: '#f59e0b' },
  ready: { label: 'Ready', color: '#3b82f6' },
  recording: { label: 'Recording', color: '#ef4444' },
  collecting: { label: 'Collecting', color: '#8b5cf6' },
  bundling: { label: 'Bundling', color: '#6366f1' },
  completed: { label: 'Completed', color: '#10b981' },
  partial: { label: 'Partial', color: '#f59e0b' },
  failed: { label: 'Failed', color: '#ef4444' },
  cancelled: { label: 'Cancelled', color: '#6b7280' },
}

export default function Investigations() {
  const navigate = useNavigate()
  const { data, isLoading } = useInvestigations()
  const deleteInv = useDeleteInvestigation()

  if (isLoading) return <LoadingSpinner message="Loading investigations..." />

  const investigations = data?.investigations || []

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h4" fontWeight={700}>Investigations</Typography>
          <Typography variant="body2" color="text.secondary">
            View and manage your troubleshooting investigations.
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => navigate('/investigations/new')}
        >
          New Investigation
        </Button>
      </Box>

      {investigations.length === 0 ? (
        <EmptyState
          title="No investigations yet"
          description="Start your first investigation to orchestrate troubleshooting across multiple devices."
          actionLabel="New Investigation"
          onAction={() => navigate('/investigations/new')}
        />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Scenario</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Devices</TableCell>
                <TableCell>Created</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {investigations.map((inv) => {
                const cfg = STATUS_CONFIG[inv.status] || STATUS_CONFIG.created
                return (
                  <TableRow key={inv.investigation_id} hover>
                    <TableCell>
                      <Typography
                        variant="body2"
                        fontWeight={600}
                        sx={{ cursor: 'pointer', '&:hover': { textDecoration: 'underline' } }}
                        onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                      >
                        {inv.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={inv.scenario} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={cfg.label}
                        size="small"
                        sx={{
                          bgcolor: `${cfg.color}20`,
                          color: cfg.color,
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell>{inv.device_count}</TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {new Date(inv.created_at).toLocaleString()}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View">
                        <IconButton
                          size="small"
                          onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                        >
                          <ViewIcon />
                        </IconButton>
                      </Tooltip>
                      {inv.download_available && (
                        <Tooltip title="Download Bundle">
                          <IconButton
                            size="small"
                            color="primary"
                            onClick={() => investigationService.downloadBundle(inv.investigation_id)}
                          >
                            <DownloadIcon />
                          </IconButton>
                        </Tooltip>
                      )}
                      <Tooltip title="Delete">
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => deleteInv.mutate(inv.investigation_id)}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  )
}
