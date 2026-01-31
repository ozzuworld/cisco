import { useState } from 'react'
import {
  Box,
  Typography,
  Button,
  Checkbox,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Paper,
} from '@mui/material'
import type { ClusterNode } from '@/types'

interface NodeSelectionStepProps {
  nodes: ClusterNode[]
  selectedNodes: string[]
  onNext: (selectedNodeIds: string[]) => void
  onBack: () => void
}

export function NodeSelectionStep({
  nodes,
  selectedNodes: initialSelectedNodes,
  onNext,
  onBack,
}: NodeSelectionStepProps) {
  const [selectedNodes, setSelectedNodes] = useState<string[]>(initialSelectedNodes)

  const handleToggleNode = (ip: string) => {
    setSelectedNodes(prev =>
      prev.includes(ip) ? prev.filter(h => h !== ip) : [...prev, ip]
    )
  }

  const handleSelectAll = () => {
    setSelectedNodes(nodes.map(n => n.ip))
  }

  const handleSelectNone = () => {
    setSelectedNodes([])
  }

  const handleNext = () => {
    onNext(selectedNodes)
  }

  const allSelected = selectedNodes.length === nodes.length
  const noneSelected = selectedNodes.length === 0

  const getRoleColor = (role: string) => {
    switch (role.toLowerCase()) {
      case 'publisher':
        return 'primary'
      case 'subscriber':
        return 'info'
      default:
        return 'default'
    }
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Select Cluster Nodes
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Choose which nodes to collect logs from. All nodes are selected by default.
      </Typography>

      <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
        <Button
          size="small"
          variant="outlined"
          onClick={handleSelectAll}
          disabled={allSelected}
        >
          Select All
        </Button>
        <Button
          size="small"
          variant="outlined"
          onClick={handleSelectNone}
          disabled={noneSelected}
        >
          Select None
        </Button>
        <Typography variant="body2" color="text.secondary" sx={{ ml: 'auto', alignSelf: 'center' }}>
          {selectedNodes.length} of {nodes.length} selected
        </Typography>
      </Box>

      <TableContainer component={Paper} variant="outlined">
        <Table>
          <TableHead>
            <TableRow>
              <TableCell padding="checkbox">
                <Checkbox
                  checked={allSelected}
                  indeterminate={selectedNodes.length > 0 && selectedNodes.length < nodes.length}
                  onChange={() => (allSelected ? handleSelectNone() : handleSelectAll())}
                />
              </TableCell>
              <TableCell>Hostname</TableCell>
              <TableCell>IP Address</TableCell>
              <TableCell>Role</TableCell>
              <TableCell>Product</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {nodes.map(node => (
              <TableRow
                key={node.ip}
                hover
                onClick={() => handleToggleNode(node.ip)}
                sx={{ cursor: 'pointer' }}
              >
                <TableCell padding="checkbox">
                  <Checkbox checked={selectedNodes.includes(node.ip)} />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" fontWeight="medium">
                    {node.host}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {node.ip}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip label={node.role} color={getRoleColor(node.role)} size="small" />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {node.product || 'N/A'}
                  </Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
        <Button onClick={onBack}>Back</Button>
        <Button variant="contained" onClick={handleNext} disabled={noneSelected}>
          Next
        </Button>
      </Box>
    </Box>
  )
}
