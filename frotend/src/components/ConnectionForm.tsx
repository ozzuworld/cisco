import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  Box,
  TextField,
  Button,
  Paper,
  Typography,
  CircularProgress,
  Alert,
  InputAdornment,
  IconButton,
} from '@mui/material'
import { Visibility, VisibilityOff } from '@mui/icons-material'
import { useState } from 'react'
import type { ConnectionRequest } from '@/types'

const connectionSchema = z.object({
  hostname: z
    .string()
    .min(1, 'Hostname is required')
    .regex(
      /^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?|(?:\d{1,3}\.){3}\d{1,3})$/,
      'Invalid hostname or IP address'
    ),
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
  port: z.number().int().min(1).max(65535).optional().default(22),
})

type ConnectionFormData = z.infer<typeof connectionSchema>

interface ConnectionFormProps {
  onSubmit: (data: ConnectionRequest) => Promise<void>
  isLoading?: boolean
  error?: string | null
  success?: string | null
  defaultValues?: Partial<ConnectionFormData>
}

export default function ConnectionForm({
  onSubmit,
  isLoading = false,
  error = null,
  success = null,
  defaultValues,
}: ConnectionFormProps) {
  const [showPassword, setShowPassword] = useState(false)

  const {
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<ConnectionFormData>({
    resolver: zodResolver(connectionSchema),
    defaultValues: {
      hostname: defaultValues?.hostname || '',
      username: defaultValues?.username || '',
      password: defaultValues?.password || '',
      port: defaultValues?.port || 22,
    },
  })

  const handleFormSubmit = async (data: ConnectionFormData) => {
    await onSubmit(data)
  }

  return (
    <Paper elevation={2} sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        CUCM Connection
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Enter your CUCM Publisher credentials to discover cluster nodes
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      <Box component="form" onSubmit={handleSubmit(handleFormSubmit)} noValidate>
        <Controller
          name="hostname"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              label="Hostname or IP Address"
              fullWidth
              margin="normal"
              error={!!errors.hostname}
              helperText={errors.hostname?.message}
              disabled={isLoading}
              placeholder="cucm-pub.example.com or 10.10.10.10"
            />
          )}
        />

        <Controller
          name="username"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              label="Username"
              fullWidth
              margin="normal"
              error={!!errors.username}
              helperText={errors.username?.message}
              disabled={isLoading}
              autoComplete="username"
            />
          )}
        />

        <Controller
          name="password"
          control={control}
          render={({ field }) => (
            <TextField
              {...field}
              label="Password"
              type={showPassword ? 'text' : 'password'}
              fullWidth
              margin="normal"
              error={!!errors.password}
              helperText={errors.password?.message}
              disabled={isLoading}
              autoComplete="current-password"
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      aria-label="toggle password visibility"
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          )}
        />

        <Controller
          name="port"
          control={control}
          render={({ field: { onChange, value, ...field } }) => (
            <TextField
              {...field}
              value={value}
              onChange={e => onChange(Number(e.target.value))}
              label="SSH Port"
              type="number"
              fullWidth
              margin="normal"
              error={!!errors.port}
              helperText={errors.port?.message || 'Default: 22'}
              disabled={isLoading}
            />
          )}
        />

        <Button
          type="submit"
          variant="contained"
          fullWidth
          size="large"
          disabled={isLoading}
          sx={{ mt: 3 }}
        >
          {isLoading ? (
            <>
              <CircularProgress size={24} sx={{ mr: 1 }} color="inherit" />
              Connecting...
            </>
          ) : (
            'Connect & Discover Nodes'
          )}
        </Button>
      </Box>
    </Paper>
  )
}
