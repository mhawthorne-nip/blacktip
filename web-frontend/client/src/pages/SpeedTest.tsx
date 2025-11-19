import { useState, useEffect } from 'react'
import { api } from '@/services/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Download,
  Upload,
  Activity,
  RefreshCw,
  Zap,
  ExternalLink,
} from 'lucide-react'
import { timeAgo } from '@/lib/utils'
import type { SpeedTest as SpeedTestType, NetworkInfo, SpeedTestStatistics } from '@/types'

export function SpeedTest() {
  const [tests, setTests] = useState<SpeedTestType[]>([])
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo | null>(null)
  const [statistics, setStatistics] = useState<SpeedTestStatistics | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [statsPeriod, setStatsPeriod] = useState(7)

  const latestTest = tests[0]

  const fetchData = async () => {
    try {
      const [testsData, networkData, statsData] = await Promise.all([
        api.getSpeedTests(),
        api.getNetworkInfo(),
        api.getSpeedTestStatistics(statsPeriod),
      ])
      setTests(testsData)
      setNetworkInfo(networkData)
      setStatistics(statsData)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch speed test data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [statsPeriod])

  const handleRunTest = async () => {
    setRunning(true)
    try {
      const result = await api.runSpeedTest()
      // Poll for results
      const pollInterval = setInterval(async () => {
        const updatedTests = await api.getSpeedTests()
        setTests(updatedTests)

        // Check if the test is complete
        const newTest = updatedTests.find((t) => t.id === result.test_id)
        if (newTest) {
          setRunning(false)
          clearInterval(pollInterval)
          fetchData() // Refresh all data
        }
      }, 3000)

      // Timeout after 2 minutes
      setTimeout(() => {
        clearInterval(pollInterval)
        setRunning(false)
      }, 120000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run speed test')
      setRunning(false)
    }
  }

  if (error && tests.length === 0) {
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
          <h1 className="text-3xl font-bold">Internet Speed Test</h1>
          <p className="text-muted-foreground mt-1">
            Monitor your internet connection performance
          </p>
        </div>
        <Button onClick={handleRunTest} disabled={running || loading}>
          <Zap className={`w-4 h-4 mr-2 ${running ? 'animate-pulse' : ''}`} />
          {running ? 'Running Test...' : 'Run Speed Test'}
        </Button>
      </div>

      {/* Latest Test Results */}
      {latestTest && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="border-l-4 border-l-blue-500">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <Download className="w-4 h-4" />
                Download Speed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-blue-600">
                {latestTest.download_speed.toFixed(2)}
                <span className="text-lg ml-1">Mbps</span>
              </div>
              {latestTest.download_latency_iqm && (
                <p className="text-xs text-muted-foreground mt-2">
                  Latency: {latestTest.download_latency_iqm.toFixed(1)} ms
                </p>
              )}
            </CardContent>
          </Card>

          <Card className="border-l-4 border-l-green-500">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <Upload className="w-4 h-4" />
                Upload Speed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-green-600">
                {latestTest.upload_speed.toFixed(2)}
                <span className="text-lg ml-1">Mbps</span>
              </div>
              {latestTest.upload_latency_iqm && (
                <p className="text-xs text-muted-foreground mt-2">
                  Latency: {latestTest.upload_latency_iqm.toFixed(1)} ms
                </p>
              )}
            </CardContent>
          </Card>

          <Card className="border-l-4 border-l-yellow-500">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <Activity className="w-4 h-4" />
                Ping
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-yellow-600">
                {latestTest.ping.toFixed(2)}
                <span className="text-lg ml-1">ms</span>
              </div>
              <div className="flex gap-3 mt-2 text-xs text-muted-foreground">
                {latestTest.jitter !== null && (
                  <span>Jitter: {latestTest.jitter.toFixed(1)} ms</span>
                )}
                {latestTest.packet_loss !== null && (
                  <span>Loss: {latestTest.packet_loss.toFixed(1)}%</span>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Network Information */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {networkInfo && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Network Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">ISP</span>
                <span className="text-sm font-medium">{networkInfo.isp || '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">External IP</span>
                <span className="text-sm font-mono">
                  {networkInfo.external_ip || '—'}
                </span>
              </div>
              {networkInfo.location && (
                <>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Location</span>
                    <span className="text-sm">
                      {[
                        networkInfo.location.city,
                        networkInfo.location.region,
                        networkInfo.location.country,
                      ]
                        .filter(Boolean)
                        .join(', ') || '—'}
                    </span>
                  </div>
                  {networkInfo.location.timezone && (
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Timezone</span>
                      <span className="text-sm">{networkInfo.location.timezone}</span>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        )}

        {statistics && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg">Statistics</CardTitle>
              <div className="flex gap-1">
                {[7, 14, 21, 28].map((days) => (
                  <Button
                    key={days}
                    variant={statsPeriod === days ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setStatsPeriod(days)}
                  >
                    {days}d
                  </Button>
                ))}
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-xs text-muted-foreground">Avg Download</span>
                  <p className="text-sm font-semibold">
                    {statistics.avg_download.toFixed(2)} Mbps
                  </p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Avg Upload</span>
                  <p className="text-sm font-semibold">
                    {statistics.avg_upload.toFixed(2)} Mbps
                  </p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Avg Ping</span>
                  <p className="text-sm font-semibold">
                    {statistics.avg_ping.toFixed(2)} ms
                  </p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Total Tests</span>
                  <p className="text-sm font-semibold">{statistics.test_count}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Test History */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Test History</CardTitle>
        </CardHeader>
        <CardContent>
          {loading && tests.length === 0 ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          ) : tests.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-muted-foreground">No speed tests found</p>
              <Button onClick={handleRunTest} className="mt-4">
                Run your first test
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Download</TableHead>
                  <TableHead>Upload</TableHead>
                  <TableHead>Ping</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tests.map((test) => (
                  <TableRow key={test.id}>
                    <TableCell>
                      <div className="text-sm">{timeAgo(test.timestamp)}</div>
                      <div className="text-xs text-muted-foreground">
                        {new Date(test.timestamp).toLocaleString()}
                      </div>
                    </TableCell>
                    <TableCell className="font-semibold text-blue-600">
                      {test.download_speed.toFixed(2)} Mbps
                    </TableCell>
                    <TableCell className="font-semibold text-green-600">
                      {test.upload_speed.toFixed(2)} Mbps
                    </TableCell>
                    <TableCell className="font-semibold text-yellow-600">
                      {test.ping.toFixed(2)} ms
                    </TableCell>
                    <TableCell className="text-sm">
                      {test.server_name && (
                        <div>{test.server_name}</div>
                      )}
                      {test.server_location && (
                        <div className="text-xs text-muted-foreground">
                          {test.server_location}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          test.trigger_type === 'manual' ? 'default' : 'secondary'
                        }
                      >
                        {test.trigger_type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {test.result_url && (
                        <a
                          href={test.result_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center text-sm text-primary hover:underline"
                        >
                          Details
                          <ExternalLink className="w-3 h-3 ml-1" />
                        </a>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
