export type EnvironmentDeviceType = 'cucm' | 'cube' | 'csr1000v' | 'expressway'

export interface DeviceEntry {
  id: string
  name: string
  device_type: EnvironmentDeviceType
  host: string
  port: number
  interface: string
  role?: string
  tags: string[]
}

export interface DeviceEntryCreate {
  name: string
  device_type: EnvironmentDeviceType
  host: string
  port?: number
  interface?: string
  role?: string
  tags?: string[]
}

export interface EnvironmentCreate {
  name: string
  description?: string
  devices?: DeviceEntryCreate[]
}

export interface EnvironmentUpdate {
  name?: string
  description?: string
}

export interface Environment {
  id: string
  name: string
  description?: string
  devices: DeviceEntry[]
  created_at: string
  updated_at: string
}

export interface EnvironmentListResponse {
  environments: Environment[]
  total: number
}

export interface DiscoverRequest {
  publisher_host: string
  port?: number
  username: string
  password: string
  connect_timeout_sec?: number
  command_timeout_sec?: number
}
