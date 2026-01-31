import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { CssBaseline } from '@mui/material'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SnackbarProvider } from 'notistack'
import { ThemeProvider } from './context'
import { ErrorBoundary } from './components'
import MainLayout from './layouts/MainLayout'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import Jobs from './pages/Jobs'
import JobDetails from './pages/JobDetails'
import NewJob from './pages/NewJob'
import LogCollection from './pages/LogCollection'
import Health from './pages/Health'
import CaptureSession from './pages/CaptureSession'
import Profiles from './pages/Profiles'
import Settings from './pages/Settings'

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
})

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <SnackbarProvider
            maxSnack={3}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            autoHideDuration={5000}
          >
            <CssBaseline />
            <BrowserRouter>
              <Routes>
                <Route path="/" element={<MainLayout />}>
                  <Route index element={<Landing />} />
                  <Route path="dashboard" element={<Dashboard />} />
                  <Route path="jobs" element={<Jobs />} />
                  <Route path="jobs/new" element={<NewJob />} />
                  <Route path="jobs/:jobId" element={<JobDetails />} />
                  <Route path="logs/new" element={<LogCollection />} />
                  <Route path="health" element={<Health />} />
                  <Route path="captures" element={<CaptureSession />} />
                  <Route path="profiles" element={<Profiles />} />
                  <Route path="settings" element={<Settings />} />
                </Route>
              </Routes>
            </BrowserRouter>
          </SnackbarProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
