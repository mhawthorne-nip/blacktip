import type {
  Device,
  TimelineEvent,
  SpeedTest,
  SpeedTestStatistics,
  NetworkInfo,
  Statistics,
} from '@/types'

const API_BASE = '/api'

async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })

  if (!response.ok) {
    throw new Error(`API error: ${response.statusText}`)
  }

  return response.json()
}

export const api = {
  // Devices
  getDevices: () => fetchAPI<Device[]>('/devices'),

  getDevice: (ip: string) => fetchAPI<Device>(`/devices/${ip}`),

  updateDeviceName: (ip: string, name: string) =>
    fetchAPI<{ success: boolean; device_name: string }>(`/devices/${ip}/name`, {
      method: 'PUT',
      body: JSON.stringify({ device_name: name }),
    }),

  // Statistics
  getStatistics: () => fetchAPI<Statistics>('/statistics'),

  // Timeline
  getTimeline: () => fetchAPI<TimelineEvent[]>('/timeline'),

  // Speed Tests
  getSpeedTests: () => fetchAPI<SpeedTest[]>('/speed-tests'),

  getSpeedTest: (id: number) => fetchAPI<SpeedTest>(`/speed-tests/${id}`),

  runSpeedTest: () =>
    fetchAPI<{ message: string; test_id: number }>('/speed-tests/run', {
      method: 'POST',
    }),

  getSpeedTestStatistics: (days?: number) => {
    const params = days ? `?days=${days}` : ''
    return fetchAPI<SpeedTestStatistics>(`/speed-tests/statistics${params}`)
  },

  getNetworkInfo: () => fetchAPI<NetworkInfo>('/network-info'),

  // Health
  getHealth: () => fetchAPI<{ status: string }>('/health'),
}
