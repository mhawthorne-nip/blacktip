import { useState, useEffect } from 'react'
import { api } from '@/services/api'
import type { Device } from '@/types'

export function useDevices() {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchDevices = async () => {
    try {
      const data = await api.getDevices()
      setDevices(data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch devices')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDevices()
    const interval = setInterval(fetchDevices, 30000) // Refresh every 30 seconds

    return () => clearInterval(interval)
  }, [])

  return { devices, loading, error, refetch: fetchDevices }
}
