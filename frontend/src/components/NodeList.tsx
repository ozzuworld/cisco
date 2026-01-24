import { useState } from 'react'
import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Checkbox,
  Chip,
  Typography,
  Box,
  Alert,
} from '@mui/material'
import type { ClusterNode } from '@/types'

interface NodeListProps {
  nodes: ClusterNode[]
  selectedNodes?: string[]
  onSelectionChange?: (selectedIps: string[]) => void
  selectable?: boolean
}

type Order = 'asc' | 'desc'
type OrderBy = keyof ClusterNode

const roleColors: Record<string, 'primary' | 'secondary' | 'info' | 'warning' | 'default'> = {
  Publisher: 'primary',
  Subscriber: 'secondary',
  publisher: 'primary',
  subscriber: 'secondary',
}

export default function NodeList({
  nodes,
  selectedNodes = [],
  onSelectionChange,
  selectable = false,
}: NodeListProps) {
  const [order, setOrder] = useState<Order>('asc')
  const [orderBy, setOrderBy] = useState<OrderBy>('host')

  const handleRequestSort = (property: OrderBy) => {
    const isAsc = orderBy === property && order === 'asc'
    setOrder(isAsc ? 'desc' : 'asc')
    setOrderBy(property)
  }

  const handleSelectAll = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (!onSelectionChange) return
    if (event.target.checked) {
      onSelectionChange(nodes.map(node => node.ip))
    } else {
      onSelectionChange([])
    }
  }

  const handleSelectNode = (ip: string) => {
    if (!onSelectionChange) return
    const currentIndex = selectedNodes.indexOf(ip)
    const newSelected = [...selectedNodes]

    if (currentIndex === -1) {
      newSelected.push(ip)
    } else {
      newSelected.splice(currentIndex, 1)
    }

    onSelectionChange(newSelected)
  }

  const sortedNodes = [...nodes].sort((a, b) => {
    const aValue = a[orderBy]
    const bValue = b[orderBy]

    if (aValue === undefined || bValue === undefined) return 0

    if (order === 'asc') {
      return aValue < bValue ? -1 : aValue > bValue ? 1 : 0
    } else {
      return aValue > bValue ? -1 : aValue < bValue ? 1 : 0
    }
  })

  const isSelected = (ip: string) => selectedNodes.indexOf(ip) !== -1
  const numSelected = selectedNodes.length
  const rowCount = nodes.length

  if (nodes.length === 0) {
    return (
      <Alert severity="info">
        No cluster nodes discovered yet. Connect to CUCM to discover nodes.
      </Alert>
    )
  }

  return (
    <Paper elevation={2}>
      <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h6">Cluster Nodes</Typography>
        {selectable && numSelected > 0 && (
          <Typography variant="body2" color="primary">
            {numSelected} of {rowCount} selected
          </Typography>
        )}
      </Box>
      <TableContainer>
        <Table>
          <TableHead>
            <TableRow>
              {selectable && (
                <TableCell padding="checkbox">
                  <Checkbox
                    indeterminate={numSelected > 0 && numSelected < rowCount}
                    checked={rowCount > 0 && numSelected === rowCount}
                    onChange={handleSelectAll}
                  />
                </TableCell>
              )}
              <TableCell>
                <TableSortLabel
                  active={orderBy === 'host'}
                  direction={orderBy === 'host' ? order : 'asc'}
                  onClick={() => handleRequestSort('host')}
                >
                  Hostname
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={orderBy === 'ip'}
                  direction={orderBy === 'ip' ? order : 'asc'}
                  onClick={() => handleRequestSort('ip')}
                >
                  IP Address
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={orderBy === 'role'}
                  direction={orderBy === 'role' ? order : 'asc'}
                  onClick={() => handleRequestSort('role')}
                >
                  Role
                </TableSortLabel>
              </TableCell>
              <TableCell>Product</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sortedNodes.map(node => {
              const isItemSelected = isSelected(node.ip)
              return (
                <TableRow
                  key={node.ip}
                  hover
                  onClick={selectable ? () => handleSelectNode(node.ip) : undefined}
                  role={selectable ? 'checkbox' : undefined}
                  selected={isItemSelected}
                  sx={{ cursor: selectable ? 'pointer' : 'default' }}
                >
                  {selectable && (
                    <TableCell padding="checkbox">
                      <Checkbox checked={isItemSelected} />
                    </TableCell>
                  )}
                  <TableCell>
                    <Typography variant="body2">{node.host}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {node.ip}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={node.role.toUpperCase()}
                      color={roleColors[node.role] || 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {node.product || 'N/A'}
                    </Typography>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Paper>
  )
}
