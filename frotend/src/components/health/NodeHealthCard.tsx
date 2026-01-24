import { useState } from 'react'
import {
  Paper,
  Box,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
} from '@mui/material'
import {
  ExpandMore,
  Storage,
  Sync,
  Schedule,
  BugReport,
  FolderOpen,
  CheckCircle,
  Error as ErrorIcon,
  Computer,
} from '@mui/icons-material'
import { HealthStatusBadge } from './HealthStatusBadge'
import type { NodeHealthStatus, HealthStatus } from '@/types'

interface NodeHealthCardProps {
  node: NodeHealthStatus
}

export function NodeHealthCard({ node }: NodeHealthCardProps) {
  const [expanded, setExpanded] = useState<string | false>(false)

  const handleChange = (panel: string) => (_: React.SyntheticEvent, isExpanded: boolean) => {
    setExpanded(isExpanded ? panel : false)
  }

  const getStatusIcon = (status: HealthStatus) => {
    return status === 'healthy' || status === 'unknown' ? (
      <CheckCircle color="success" fontSize="small" />
    ) : status === 'degraded' ? (
      <ErrorIcon color="warning" fontSize="small" />
    ) : (
      <ErrorIcon color="error" fontSize="small" />
    )
  }

  return (
    <Paper variant="outlined" sx={{ mb: 2 }}>
      {/* Node Header */}
      <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Computer color="primary" />
          <Box>
            <Typography variant="subtitle1" fontWeight="medium">
              {node.hostname || node.ip}
              {node.role && (
                <Chip label={node.role} size="small" sx={{ ml: 1 }} />
              )}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {node.ip}
            </Typography>
          </Box>
        </Box>
        <HealthStatusBadge status={node.status} />
      </Box>

      {/* Error Display */}
      {node.error && (
        <Alert severity="error" sx={{ mx: 2, mb: 2 }}>
          {node.error}
        </Alert>
      )}

      {/* Check Accordions */}
      {node.reachable && (
        <Box sx={{ px: 1, pb: 1 }}>
          {/* Replication */}
          {node.checks.replication && (
            <Accordion expanded={expanded === 'replication'} onChange={handleChange('replication')}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <Sync fontSize="small" />
                  <Typography>Replication</Typography>
                  <Box sx={{ ml: 'auto', mr: 2 }}>
                    {getStatusIcon(node.checks.replication.status)}
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {node.checks.replication.message}
                </Typography>
                {node.checks.replication.db_version && (
                  <Typography variant="body2" gutterBottom>
                    DB Version: {node.checks.replication.db_version}
                  </Typography>
                )}
                {node.checks.replication.tables_checked !== null && (
                  <Typography variant="body2" gutterBottom>
                    Tables: {node.checks.replication.tables_checked}/{node.checks.replication.tables_total}
                  </Typography>
                )}
                {node.checks.replication.nodes.length > 0 && (
                  <TableContainer sx={{ mt: 1 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Server</TableCell>
                          <TableCell>IP</TableCell>
                          <TableCell>Ping</TableCell>
                          <TableCell>DB Mon</TableCell>
                          <TableCell>Queue</TableCell>
                          <TableCell>Status</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {node.checks.replication.nodes.map((replNode) => (
                          <TableRow key={replNode.server_name}>
                            <TableCell>{replNode.server_name}</TableCell>
                            <TableCell>{replNode.ip_address}</TableCell>
                            <TableCell>{replNode.ping_ms?.toFixed(2)} ms</TableCell>
                            <TableCell>
                              <Chip
                                label={replNode.db_mon || 'N/A'}
                                size="small"
                                color={replNode.db_mon === 'Y/Y/Y' ? 'success' : 'warning'}
                              />
                            </TableCell>
                            <TableCell>{replNode.repl_queue}</TableCell>
                            <TableCell>{replNode.setup_status}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </AccordionDetails>
            </Accordion>
          )}

          {/* Services */}
          {node.checks.services && (
            <Accordion expanded={expanded === 'services'} onChange={handleChange('services')}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <Storage fontSize="small" />
                  <Typography>Services</Typography>
                  <Chip
                    label={`${node.checks.services.running_services}/${node.checks.services.total_services}`}
                    size="small"
                    sx={{ ml: 1 }}
                  />
                  <Box sx={{ ml: 'auto', mr: 2 }}>
                    {getStatusIcon(node.checks.services.status)}
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {node.checks.services.message}
                </Typography>
                {node.checks.services.critical_services_down.length > 0 && (
                  <Alert severity="error" sx={{ mb: 2 }}>
                    Critical services down: {node.checks.services.critical_services_down.join(', ')}
                  </Alert>
                )}
                <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
                  {node.checks.services.services.slice(0, 20).map((service) => (
                    <ListItem key={service.name}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        {service.is_running ? (
                          <CheckCircle color="success" fontSize="small" />
                        ) : (
                          <ErrorIcon color="error" fontSize="small" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={service.name}
                        secondary={service.status}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                  {node.checks.services.services.length > 20 && (
                    <ListItem>
                      <ListItemText
                        primary={`... and ${node.checks.services.services.length - 20} more`}
                        primaryTypographyProps={{ variant: 'body2', color: 'text.secondary' }}
                      />
                    </ListItem>
                  )}
                </List>
              </AccordionDetails>
            </Accordion>
          )}

          {/* NTP */}
          {node.checks.ntp && (
            <Accordion expanded={expanded === 'ntp'} onChange={handleChange('ntp')}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <Schedule fontSize="small" />
                  <Typography>NTP</Typography>
                  <Box sx={{ ml: 'auto', mr: 2 }}>
                    {getStatusIcon(node.checks.ntp.status)}
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {node.checks.ntp.message}
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <Chip
                    label={node.checks.ntp.synchronized ? 'Synchronized' : 'Not Synced'}
                    color={node.checks.ntp.synchronized ? 'success' : 'error'}
                    size="small"
                  />
                  {node.checks.ntp.stratum !== null && (
                    <Chip label={`Stratum ${node.checks.ntp.stratum}`} size="small" />
                  )}
                  {node.checks.ntp.ntp_server && (
                    <Chip label={`Server: ${node.checks.ntp.ntp_server}`} size="small" variant="outlined" />
                  )}
                  {node.checks.ntp.offset_ms !== null && (
                    <Chip label={`Offset: ${node.checks.ntp.offset_ms.toFixed(1)}ms`} size="small" variant="outlined" />
                  )}
                </Box>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Diagnostics */}
          {node.checks.diagnostics && (
            <Accordion expanded={expanded === 'diagnostics'} onChange={handleChange('diagnostics')}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <BugReport fontSize="small" />
                  <Typography>Diagnostics</Typography>
                  <Chip
                    label={`${node.checks.diagnostics.passed_tests}/${node.checks.diagnostics.total_tests} passed`}
                    size="small"
                    sx={{ ml: 1 }}
                  />
                  <Box sx={{ ml: 'auto', mr: 2 }}>
                    {getStatusIcon(node.checks.diagnostics.status)}
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {node.checks.diagnostics.message}
                </Typography>
                <List dense>
                  {node.checks.diagnostics.tests.map((test) => (
                    <ListItem key={test.name}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        {test.passed ? (
                          <CheckCircle color="success" fontSize="small" />
                        ) : (
                          <ErrorIcon color="error" fontSize="small" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={test.name}
                        secondary={test.message}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Core Files */}
          {node.checks.cores && (
            <Accordion expanded={expanded === 'cores'} onChange={handleChange('cores')}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <FolderOpen fontSize="small" />
                  <Typography>Core Files</Typography>
                  {node.checks.cores.core_count > 0 && (
                    <Chip
                      label={`${node.checks.cores.core_count} files`}
                      size="small"
                      color="warning"
                      sx={{ ml: 1 }}
                    />
                  )}
                  <Box sx={{ ml: 'auto', mr: 2 }}>
                    {getStatusIcon(node.checks.cores.status)}
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {node.checks.cores.message}
                </Typography>
                {node.checks.cores.core_files.length > 0 && (
                  <List dense>
                    {node.checks.cores.core_files.map((file, idx) => (
                      <ListItem key={idx}>
                        <ListItemText
                          primary={file}
                          primaryTypographyProps={{ variant: 'body2', fontFamily: 'monospace' }}
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </AccordionDetails>
            </Accordion>
          )}
        </Box>
      )}
    </Paper>
  )
}

export default NodeHealthCard
