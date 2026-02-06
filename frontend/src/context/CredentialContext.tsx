import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'

interface DeviceCredential {
  username: string
  password: string
}

interface CredentialContextType {
  credentials: Record<string, DeviceCredential>
  setDeviceCredentials: (deviceId: string, creds: DeviceCredential) => void
  setGlobalCredentials: (creds: DeviceCredential) => void
  clearAll: () => void
  hasAllCredentials: (deviceIds: string[]) => boolean
  getCredentialsPayload: () => Record<string, { username: string; password: string }>
}

const CredentialContext = createContext<CredentialContextType | null>(null)

export function CredentialProvider({ children }: { children: ReactNode }) {
  const [credentials, setCredentials] = useState<Record<string, DeviceCredential>>({})

  const setDeviceCredentials = useCallback((deviceId: string, creds: DeviceCredential) => {
    setCredentials(prev => ({ ...prev, [deviceId]: creds }))
  }, [])

  const setGlobalCredentials = useCallback((creds: DeviceCredential) => {
    setCredentials(prev => ({ ...prev, global: creds }))
  }, [])

  const clearAll = useCallback(() => {
    setCredentials({})
  }, [])

  const hasAllCredentials = useCallback((deviceIds: string[]) => {
    if (credentials.global) return true
    return deviceIds.every(id => !!credentials[id])
  }, [credentials])

  const getCredentialsPayload = useCallback(() => {
    const payload: Record<string, { username: string; password: string }> = {}
    for (const [key, cred] of Object.entries(credentials)) {
      payload[key] = { username: cred.username, password: cred.password }
    }
    return payload
  }, [credentials])

  return (
    <CredentialContext.Provider value={{
      credentials,
      setDeviceCredentials,
      setGlobalCredentials,
      clearAll,
      hasAllCredentials,
      getCredentialsPayload,
    }}>
      {children}
    </CredentialContext.Provider>
  )
}

export function useCredentials() {
  const ctx = useContext(CredentialContext)
  if (!ctx) {
    throw new Error('useCredentials must be used within CredentialProvider')
  }
  return ctx
}
