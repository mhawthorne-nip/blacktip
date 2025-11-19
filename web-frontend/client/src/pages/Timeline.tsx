import { useState, useEffect, useMemo } from 'react'
import { api } from '@/services/api'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RefreshCw, Activity, AlertTriangle, Wifi, Monitor } from 'lucide-react'
import { timeAgo } from '@/lib/utils'
import type { TimelineEvent } from '@/types'

type EventFilter = 'all' | 'discovered' | 'online' | 'offline' | 'anomaly' | 'speedtest'

export function Timeline() {
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<EventFilter>('all')

  const fetchEvents = async () => {
    try {
      const data = await api.getTimeline()
      setEvents(data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch timeline')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchEvents()
    const interval = setInterval(fetchEvents, 30000) // Refresh every 30 seconds
    return () => clearInterval(interval)
  }, [])

  const filteredEvents = useMemo(() => {
    if (filter === 'all') return events
    return events.filter((event) => event.event_type === filter)
  }, [events, filter])

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'discovered':
        return <Monitor className="w-5 h-5" />
      case 'online':
        return <Activity className="w-5 h-5 text-green-600" />
      case 'offline':
        return <Activity className="w-5 h-5 text-gray-500" />
      case 'anomaly':
        return <AlertTriangle className="w-5 h-5 text-red-600" />
      case 'speedtest':
        return <Wifi className="w-5 h-5 text-blue-600" />
      default:
        return <Activity className="w-5 h-5" />
    }
  }

  const getEventColor = (type: string) => {
    switch (type) {
      case 'discovered':
        return 'border-l-primary'
      case 'online':
        return 'border-l-green-600'
      case 'offline':
        return 'border-l-gray-500'
      case 'anomaly':
        return 'border-l-red-600'
      case 'speedtest':
        return 'border-l-blue-600'
      default:
        return 'border-l-gray-300'
    }
  }

  if (error) {
    return (
      <div className="p-8">
        <Card className="border-destructive">
          <CardContent className="pt-6">
            <p className="text-destructive">Error: {error}</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Network Timeline</h1>
          <p className="text-muted-foreground mt-1">
            Track network events and device activity
          </p>
        </div>
        <Button onClick={fetchEvents} disabled={loading} variant="outline">
          <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-2 mb-6">
            <Button
              variant={filter === 'all' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilter('all')}
            >
              All ({events.length})
            </Button>
            <Button
              variant={filter === 'discovered' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilter('discovered')}
            >
              Discovered ({events.filter((e) => e.event_type === 'discovered').length})
            </Button>
            <Button
              variant={filter === 'online' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilter('online')}
            >
              Online ({events.filter((e) => e.event_type === 'online').length})
            </Button>
            <Button
              variant={filter === 'offline' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilter('offline')}
            >
              Offline ({events.filter((e) => e.event_type === 'offline').length})
            </Button>
            <Button
              variant={filter === 'anomaly' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilter('anomaly')}
            >
              Anomalies ({events.filter((e) => e.event_type === 'anomaly').length})
            </Button>
            <Button
              variant={filter === 'speedtest' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilter('speedtest')}
            >
              Speed Tests ({events.filter((e) => e.event_type === 'speedtest').length})
            </Button>
          </div>

          {loading && events.length === 0 ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          ) : filteredEvents.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-muted-foreground">No events found</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredEvents.map((event) => (
                <Card
                  key={event.id}
                  className={`border-l-4 ${getEventColor(event.event_type)}`}
                >
                  <CardContent className="pt-6">
                    <div className="flex items-start gap-4">
                      <div className="p-2 rounded-lg bg-secondary">
                        {getEventIcon(event.event_type)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="outline" className="capitalize">
                            {event.event_type}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            {timeAgo(event.timestamp)}
                          </span>
                        </div>
                        <p className="text-sm mb-2">{event.description}</p>
                        <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                          {event.ip_address && (
                            <span className="font-mono">IP: {event.ip_address}</span>
                          )}
                          {event.mac_address && (
                            <span className="font-mono">MAC: {event.mac_address}</span>
                          )}
                          <span>
                            {new Date(event.timestamp).toLocaleString()}
                          </span>
                        </div>
                        {event.event_type === 'speedtest' && event.metadata && (
                          <div className="mt-3 p-3 rounded-md bg-secondary/50 grid grid-cols-3 gap-3">
                            {event.metadata.download_speed && (
                              <div>
                                <span className="text-xs text-muted-foreground">
                                  Download
                                </span>
                                <p className="text-sm font-semibold">
                                  {event.metadata.download_speed.toFixed(2)} Mbps
                                </p>
                              </div>
                            )}
                            {event.metadata.upload_speed && (
                              <div>
                                <span className="text-xs text-muted-foreground">
                                  Upload
                                </span>
                                <p className="text-sm font-semibold">
                                  {event.metadata.upload_speed.toFixed(2)} Mbps
                                </p>
                              </div>
                            )}
                            {event.metadata.ping && (
                              <div>
                                <span className="text-xs text-muted-foreground">Ping</span>
                                <p className="text-sm font-semibold">
                                  {event.metadata.ping.toFixed(2)} ms
                                </p>
                              </div>
                            )}
                          </div>
                        )}
                        {event.event_type === 'online' &&
                          event.metadata?.duration_offline && (
                            <div className="mt-2 text-xs text-muted-foreground">
                              Was offline for {event.metadata.duration_offline}
                            </div>
                          )}
                        {event.event_type === 'offline' &&
                          event.metadata?.duration_online && (
                            <div className="mt-2 text-xs text-muted-foreground">
                              Was online for {event.metadata.duration_online}
                            </div>
                          )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
