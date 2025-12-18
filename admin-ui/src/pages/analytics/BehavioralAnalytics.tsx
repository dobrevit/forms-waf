import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { behavioralApi } from '@/api/client'
import type { BehavioralStats, BehavioralBaseline, BehavioralFlowSummary } from '@/api/types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import {
  Activity,
  RefreshCw,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Clock,
  Shield,
  BarChart3,
  Loader2,
} from 'lucide-react'

type BucketType = 'hour' | 'day' | 'week' | 'month'

const bucketOptions: { value: BucketType; label: string; count: number }[] = [
  { value: 'hour', label: 'Last 24 Hours', count: 24 },
  { value: 'day', label: 'Last 30 Days', count: 30 },
  { value: 'week', label: 'Last 12 Weeks', count: 12 },
  { value: 'month', label: 'Last 12 Months', count: 12 },
]

function StatusBadge({ status }: { status: 'ready' | 'learning' | 'no_data' }) {
  const config = {
    ready: { icon: CheckCircle, label: 'Ready', className: 'bg-green-100 text-green-700' },
    learning: { icon: Clock, label: 'Learning', className: 'bg-yellow-100 text-yellow-700' },
    no_data: { icon: AlertTriangle, label: 'No Data', className: 'bg-gray-100 text-gray-600' },
  }
  const { icon: Icon, label, className } = config[status]
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${className}`}>
      <Icon className="h-3 w-3" />
      {label}
    </span>
  )
}

function StatCard({ title, value, subtitle, icon: Icon }: {
  title: string
  value: string | number
  subtitle?: string
  icon: React.ElementType
}) {
  return (
    <div className="bg-white rounded-lg border p-4">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-primary/10 rounded-lg">
          <Icon className="h-5 w-5 text-primary" />
        </div>
        <div>
          <p className="text-sm text-muted-foreground">{title}</p>
          <p className="text-2xl font-bold">{value}</p>
          {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
    </div>
  )
}

function StatsTable({ stats }: { stats: BehavioralStats[] }) {
  if (stats.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No stats data available for this period.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-muted/50">
          <tr>
            <th className="px-4 py-2 text-left font-medium">Time</th>
            <th className="px-4 py-2 text-right font-medium">Submissions</th>
            <th className="px-4 py-2 text-right font-medium">Allowed</th>
            <th className="px-4 py-2 text-right font-medium">Blocked</th>
            <th className="px-4 py-2 text-right font-medium">Monitored</th>
            <th className="px-4 py-2 text-right font-medium">Unique IPs</th>
            <th className="px-4 py-2 text-right font-medium">Avg Spam</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {stats.map((stat) => (
            <tr key={stat.bucket_id} className="hover:bg-muted/30">
              <td className="px-4 py-2">
                {new Date(stat.timestamp * 1000).toLocaleString()}
              </td>
              <td className="px-4 py-2 text-right font-mono">{stat.submissions}</td>
              <td className="px-4 py-2 text-right font-mono text-green-600">{stat.allowed}</td>
              <td className="px-4 py-2 text-right font-mono text-red-600">{stat.blocked}</td>
              <td className="px-4 py-2 text-right font-mono text-yellow-600">{stat.monitored}</td>
              <td className="px-4 py-2 text-right font-mono">{stat.unique_ips}</td>
              <td className="px-4 py-2 text-right font-mono">
                {stat.avg_spam_score?.toFixed(1) ?? '-'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function BaselineDisplay({ baseline }: { baseline: BehavioralBaseline | null }) {
  if (!baseline) {
    return (
      <div className="text-center py-4 text-muted-foreground">
        No baseline data available.
      </div>
    )
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      <div className="p-3 bg-muted/50 rounded-lg">
        <p className="text-xs text-muted-foreground">Hourly Average</p>
        <p className="text-lg font-bold">{baseline.hourly_avg_submissions?.toFixed(1) ?? '-'}</p>
        <p className="text-xs text-muted-foreground">
          &sigma; {baseline.hourly_std_dev_submissions?.toFixed(1) ?? '-'}
        </p>
      </div>
      <div className="p-3 bg-muted/50 rounded-lg">
        <p className="text-xs text-muted-foreground">Percentiles</p>
        <p className="text-sm">
          P50: <span className="font-medium">{baseline.hourly_p50_submissions?.toFixed(0) ?? '-'}</span>
          {' | '}
          P90: <span className="font-medium">{baseline.hourly_p90_submissions?.toFixed(0) ?? '-'}</span>
          {' | '}
          P99: <span className="font-medium">{baseline.hourly_p99_submissions?.toFixed(0) ?? '-'}</span>
        </p>
      </div>
      <div className="p-3 bg-muted/50 rounded-lg">
        <p className="text-xs text-muted-foreground">Learning Progress</p>
        <p className="text-sm">
          <span className="font-medium">{baseline.samples_collected ?? 0}</span>
          {' / '}
          <span className="text-muted-foreground">{baseline.min_samples_needed ?? 168}</span> samples
        </p>
        {baseline.last_updated && (
          <p className="text-xs text-muted-foreground mt-1">
            Updated: {new Date(baseline.last_updated).toLocaleString()}
          </p>
        )}
      </div>
    </div>
  )
}

function FlowDetails({ vhostId, flowName }: { vhostId: string; flowName: string }) {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [bucketType, setBucketType] = useState<BucketType>('hour')

  const selectedBucket = bucketOptions.find(b => b.value === bucketType) || bucketOptions[0]

  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ['behavioral-stats', vhostId, flowName, bucketType],
    queryFn: () => behavioralApi.getStats(vhostId, flowName, bucketType, selectedBucket.count),
    enabled: !!vhostId && !!flowName,
  })

  const { data: baselineData, isLoading: baselineLoading } = useQuery({
    queryKey: ['behavioral-baseline', vhostId, flowName],
    queryFn: () => behavioralApi.getBaseline(vhostId, flowName),
    enabled: !!vhostId && !!flowName,
  })

  const recalculateMutation = useMutation({
    mutationFn: () => behavioralApi.recalculateBaseline(vhostId, flowName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['behavioral-baseline', vhostId, flowName] })
      toast({ title: 'Baseline recalculation triggered' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to recalculate baseline',
        variant: 'destructive',
      })
    },
  })

  const stats = statsData?.stats || []
  const baseline = baselineData?.baseline
  const status = baselineData?.status || 'no_data'

  // Calculate summary stats
  const totalSubmissions = stats.reduce((sum, s) => sum + s.submissions, 0)
  const totalBlocked = stats.reduce((sum, s) => sum + s.blocked, 0)
  const totalAllowed = stats.reduce((sum, s) => sum + s.allowed, 0)
  const avgSpamScore = stats.length > 0
    ? stats.reduce((sum, s) => sum + (s.avg_spam_score || 0), 0) / stats.length
    : 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <StatusBadge status={status} />
          <Select value={bucketType} onValueChange={(v) => setBucketType(v as BucketType)}>
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {bucketOptions.map(opt => (
                <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => recalculateMutation.mutate()}
          disabled={recalculateMutation.isPending}
        >
          {recalculateMutation.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-2" />
          )}
          Recalculate Baseline
        </Button>
      </div>

      {/* Summary Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard
          title="Total Submissions"
          value={totalSubmissions.toLocaleString()}
          subtitle={selectedBucket.label}
          icon={Activity}
        />
        <StatCard
          title="Allowed"
          value={totalAllowed.toLocaleString()}
          subtitle={`${totalSubmissions ? ((totalAllowed / totalSubmissions) * 100).toFixed(1) : 0}%`}
          icon={CheckCircle}
        />
        <StatCard
          title="Blocked"
          value={totalBlocked.toLocaleString()}
          subtitle={`${totalSubmissions ? ((totalBlocked / totalSubmissions) * 100).toFixed(1) : 0}%`}
          icon={Shield}
        />
        <StatCard
          title="Avg Spam Score"
          value={avgSpamScore.toFixed(1)}
          icon={TrendingUp}
        />
      </div>

      {/* Baseline */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Baseline Data</CardTitle>
          <CardDescription>
            Statistical baseline used for anomaly detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          {baselineLoading ? (
            <div className="flex items-center justify-center py-4">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <BaselineDisplay baseline={baseline ?? null} />
          )}
        </CardContent>
      </Card>

      {/* Stats Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Historical Data</CardTitle>
          <CardDescription>
            Submission statistics by time bucket
          </CardDescription>
        </CardHeader>
        <CardContent>
          {statsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <StatsTable stats={stats} />
          )}
        </CardContent>
      </Card>
    </div>
  )
}

export default function BehavioralAnalytics() {
  const [selectedVhost, setSelectedVhost] = useState<string>('')
  const [selectedFlow, setSelectedFlow] = useState<string>('')

  // Fetch summary of all vhosts with behavioral tracking
  const { data: summaryData, isLoading: summaryLoading } = useQuery({
    queryKey: ['behavioral-summary'],
    queryFn: () => behavioralApi.getSummary(),
  })

  // Fetch flows for selected vhost (used for future enhancements)
  useQuery({
    queryKey: ['behavioral-flows', selectedVhost],
    queryFn: () => behavioralApi.getFlows(selectedVhost),
    enabled: !!selectedVhost,
  })

  // Ensure vhosts is always an array (Lua cjson encodes empty arrays as objects)
  const vhosts = Array.isArray(summaryData?.vhosts) ? summaryData.vhosts : []

  // When vhost changes, reset flow selection
  const handleVhostChange = (vhostId: string) => {
    setSelectedVhost(vhostId)
    setSelectedFlow('')
  }

  // Get selected vhost summary
  const selectedVhostSummary = vhosts.find(v => v.vhost_id === selectedVhost)

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Behavioral Analytics</h2>
        <p className="text-muted-foreground">
          Monitor submission patterns and anomaly detection baselines
        </p>
      </div>

      {/* Overview Cards */}
      {!selectedVhost && (
        <div className="grid gap-4 md:grid-cols-3">
          <StatCard
            title="Tracked Vhosts"
            value={summaryData?.total_tracked_vhosts ?? 0}
            icon={BarChart3}
          />
          <StatCard
            title="Total Flows"
            value={vhosts.reduce((sum, v) => sum + v.flows.length, 0)}
            icon={Activity}
          />
          <StatCard
            title="Ready Baselines"
            value={vhosts.reduce((sum, v) =>
              sum + v.flows.filter(f => f.baseline_status === 'ready').length, 0
            )}
            icon={CheckCircle}
          />
        </div>
      )}

      {/* Vhost Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Select Virtual Host
          </CardTitle>
          <CardDescription>
            Choose a virtual host to view its behavioral tracking data
          </CardDescription>
        </CardHeader>
        <CardContent>
          {summaryLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : vhosts.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No virtual hosts have behavioral tracking enabled.</p>
              <p className="text-sm mt-2">
                Enable behavioral tracking in a virtual host's configuration to start collecting data.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <Select value={selectedVhost} onValueChange={handleVhostChange}>
                <SelectTrigger className="w-full max-w-md">
                  <SelectValue placeholder="Select a virtual host..." />
                </SelectTrigger>
                <SelectContent>
                  {vhosts.map((vhost) => (
                    <SelectItem key={vhost.vhost_id} value={vhost.vhost_id}>
                      <div className="flex items-center gap-2">
                        <span>{vhost.vhost_id}</span>
                        <span className="text-muted-foreground">
                          ({vhost.flows.length} flow{vhost.flows.length !== 1 ? 's' : ''})
                        </span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              {/* Vhost Flows Grid */}
              {selectedVhostSummary && selectedVhostSummary.flows.length > 0 && (
                <div className="mt-6">
                  <h4 className="text-sm font-medium mb-3">Available Flows</h4>
                  <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                    {selectedVhostSummary.flows.map((flow: BehavioralFlowSummary) => (
                      <button
                        key={flow.name}
                        onClick={() => setSelectedFlow(flow.name)}
                        className={`text-left p-4 rounded-lg border transition-colors ${
                          selectedFlow === flow.name
                            ? 'border-primary bg-primary/5'
                            : 'border-border hover:border-primary/50'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium">{flow.name}</span>
                          <StatusBadge status={flow.baseline_status} />
                        </div>
                        {flow.last_hour && (
                          <div className="grid grid-cols-3 gap-2 text-xs text-muted-foreground">
                            <div>
                              <span className="block text-foreground font-medium">
                                {flow.last_hour.submissions}
                              </span>
                              submissions
                            </div>
                            <div>
                              <span className="block text-foreground font-medium">
                                {flow.last_hour.unique_ips}
                              </span>
                              unique IPs
                            </div>
                            <div>
                              <span className="block text-foreground font-medium">
                                {flow.last_hour.avg_spam_score?.toFixed(1) ?? '-'}
                              </span>
                              avg score
                            </div>
                          </div>
                        )}
                        {!flow.last_hour && (
                          <p className="text-xs text-muted-foreground">No data in last hour</p>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Flow Details */}
      {selectedVhost && selectedFlow && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Flow: {selectedFlow}
            </CardTitle>
            <CardDescription>
              Detailed analytics for {selectedVhost} / {selectedFlow}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FlowDetails vhostId={selectedVhost} flowName={selectedFlow} />
          </CardContent>
        </Card>
      )}
    </div>
  )
}
