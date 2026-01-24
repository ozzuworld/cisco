import { Component, ErrorInfo, ReactNode } from 'react'
import { Box, Typography, Button, Container, Paper } from '@mui/material'
import { Error as ErrorIcon, Refresh as RefreshIcon } from '@mui/icons-material'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error?: Error
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: undefined })
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <Container maxWidth="md">
          <Box
            sx={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              minHeight: '100vh',
              py: 4,
            }}
          >
            <Paper
              sx={{
                p: 4,
                textAlign: 'center',
                maxWidth: 500,
                width: '100%',
              }}
            >
              <ErrorIcon
                color="error"
                sx={{
                  fontSize: 64,
                  mb: 2,
                }}
              />
              <Typography variant="h4" gutterBottom>
                Oops! Something went wrong
              </Typography>
              <Typography variant="body1" color="text.secondary" paragraph>
                An unexpected error occurred. Please try refreshing the page.
              </Typography>
              {this.state.error && (
                <Box
                  sx={{
                    mt: 2,
                    p: 2,
                    bgcolor: 'grey.100',
                    borderRadius: 1,
                    textAlign: 'left',
                  }}
                >
                  <Typography
                    variant="caption"
                    component="pre"
                    sx={{
                      fontFamily: 'monospace',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {this.state.error.message}
                  </Typography>
                </Box>
              )}
              <Button
                variant="contained"
                startIcon={<RefreshIcon />}
                onClick={this.handleReset}
                sx={{ mt: 3 }}
              >
                Refresh Page
              </Button>
            </Paper>
          </Box>
        </Container>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
