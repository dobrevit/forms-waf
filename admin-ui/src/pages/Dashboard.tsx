import { useQuery } from '@tanstack/react-query'
import { statusApi, vhostsApi, endpointsApi, keywordsApi, metricsApi, configApi } from '@/api/client'
import type { MetricsSummary } from '@/api/client'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert'
import {
  Globe,
  Route,
  Ban,
  Flag,
  Shield,
  CheckCircle,
  XCircle,
  Activity,
  ShieldAlert,
  ShieldCheck,
  Eye,
  FileText,
  AlertTriangle,
  Bug
} from 'lucide-react'

interface StatCardProps {
  title: string
  value: string | number
  description?: string
  icon: React.ElementType
  trend?: 'up' | 'down' | 'neutral'
}

function StatCard({ title, value, description, icon: Icon }: StatCardProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </CardContent>
    </Card>
  )
}

export function Dashboard() {
  const { data: statusData, isLoading: statusLoading } = useQuery({
    queryKey: ['status'],
    queryFn: statusApi.get,
    refetchInterval: 30000,
  })

  const { data: vhostsData } = useQuery({
    queryKey: ['vhosts'],
    queryFn: vhostsApi.list,
  })

  const { data: endpointsData } = useQuery({
    queryKey: ['endpoints', 'all'],
    queryFn: () => endpointsApi.list(),
    staleTime: 0, // Always refetch on mount to ensure accurate counts
  })

  const { data: blockedKeywordsData } = useQuery({
    queryKey: ['keywords', 'blocked'],
    queryFn: keywordsApi.getBlocked,
  })

  const { data: flaggedKeywordsData } = useQuery({
    queryKey: ['keywords', 'flagged'],
    queryFn: keywordsApi.getFlagged,
  })

  const { data: metricsData } = useQuery({
    queryKey: ['metrics'],
    queryFn: metricsApi.get,
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const { data: thresholdsData } = useQuery({
    queryKey: ['config', 'thresholds'],
    queryFn: configApi.getThresholds,
  })

  const status = statusData as Record<string, unknown> | undefined
  const thresholds = (thresholdsData as { thresholds: Record<string, unknown> } | undefined)?.thresholds
  const debugEnabled = thresholds?.expose_waf_headers === true
  const rawVhosts = (vhostsData as { vhosts: unknown[] } | undefined)?.vhosts
  const rawEndpoints = (endpointsData as { endpoints: unknown[] } | undefined)?.endpoints
  const rawBlockedKeywords = (blockedKeywordsData as { keywords: string[] } | undefined)?.keywords
  const rawFlaggedKeywords = (flaggedKeywordsData as { keywords: string[] } | undefined)?.keywords

  // Ensure arrays (Lua cjson may encode empty arrays as objects)
  const vhosts = Array.isArray(rawVhosts) ? rawVhosts : []
  const endpoints = Array.isArray(rawEndpoints) ? rawEndpoints : []
  const blockedKeywords = Array.isArray(rawBlockedKeywords) ? rawBlockedKeywords : []
  const flaggedKeywords = Array.isArray(rawFlaggedKeywords) ? rawFlaggedKeywords : []

  const enabledVhosts = vhosts.filter((v: unknown) => (v as { enabled: boolean }).enabled).length
  const enabledEndpoints = endpoints.filter((e: unknown) => (e as { enabled: boolean }).enabled).length

  const metrics = metricsData as MetricsSummary | undefined

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">
          Overview of your WAF configuration and status
        </p>
      </div>

      {/* Status Banner */}
      <Card className={status?.redis_connected ? 'border-green-500' : 'border-red-500'}>
        <CardContent className="flex items-center gap-4 py-4">
          {statusLoading ? (
            <Activity className="h-5 w-5 animate-pulse" />
          ) : status?.redis_connected ? (
            <CheckCircle className="h-5 w-5 text-green-500" />
          ) : (
            <XCircle className="h-5 w-5 text-red-500" />
          )}
          <div>
            <p className="font-medium">
              {statusLoading
                ? 'Checking status...'
                : status?.redis_connected
                ? 'WAF is operational'
                : 'Redis connection issue'}
            </p>
            <p className="text-sm text-muted-foreground">
              {status?.redis_connected
                ? 'All systems running normally'
                : 'Please check Redis connectivity'}
            </p>
          </div>
          <Badge
            variant={status?.redis_connected ? 'success' : 'destructive'}
            className="ml-auto"
          >
            {status?.redis_connected ? 'Connected' : 'Disconnected'}
          </Badge>
        </CardContent>
      </Card>

      {/* Debug Mode Warning */}
      {debugEnabled && (
        <Alert variant="warning">
          <Bug className="h-5 w-5" />
          <AlertTitle>Debug Mode Enabled</AlertTitle>
          <AlertDescription>
            WAF debug headers are globally exposed to clients. This reveals internal WAF information and should only be enabled for debugging.{' '}
            <a href="/config/thresholds" className="underline font-medium hover:text-amber-900">
              Disable in Thresholds settings
            </a>
          </AlertDescription>
        </Alert>
      )}

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Virtual Hosts"
          value={vhosts.length}
          description={`${enabledVhosts} enabled`}
          icon={Globe}
        />
        <StatCard
          title="Endpoints"
          value={endpoints.length}
          description={`${enabledEndpoints} enabled`}
          icon={Route}
        />
        <StatCard
          title="Blocked Keywords"
          value={blockedKeywords.length}
          description="Immediate rejection"
          icon={Ban}
        />
        <StatCard
          title="Flagged Keywords"
          value={flaggedKeywords.length}
          description="Score-based filtering"
          icon={Flag}
        />
      </div>

      {/* Request Metrics */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Request Metrics
          </CardTitle>
          <CardDescription>
            Live request statistics (refreshes every 10s)
            {metrics?.global && (
              <span className="ml-2 text-xs">
                • Cluster: {metrics.global.instance_count ?? 0} instance{(metrics.global.instance_count ?? 0) !== 1 ? 's' : ''}
              </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6">
            <div className="flex flex-col items-center p-3 rounded-lg bg-muted/50">
              <FileText className="h-5 w-5 text-blue-500 mb-1" />
              {metrics?.global ? (
                <div className="flex items-center gap-2">
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold">{metrics?.total_requests || 0}</span>
                    <span className="text-[10px] text-muted-foreground">local</span>
                  </div>
                  <div className="h-8 w-px bg-border" />
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold">{(metrics.global.total_requests ?? 0).toLocaleString()}</span>
                    <span className="text-[10px] text-muted-foreground">global</span>
                  </div>
                </div>
              ) : (
                <span className="text-2xl font-bold">{metrics?.total_requests || 0}</span>
              )}
              <span className="text-xs text-muted-foreground mt-1">Total Requests</span>
            </div>
            <div className="flex flex-col items-center p-3 rounded-lg bg-muted/50">
              <ShieldAlert className="h-5 w-5 text-red-500 mb-1" />
              {metrics?.global ? (
                <div className="flex items-center gap-2">
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-red-600">{metrics?.blocked_requests || 0}</span>
                    <span className="text-[10px] text-muted-foreground">local</span>
                  </div>
                  <div className="h-8 w-px bg-border" />
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-red-600">{(metrics.global.blocked_requests ?? 0).toLocaleString()}</span>
                    <span className="text-[10px] text-muted-foreground">global</span>
                  </div>
                </div>
              ) : (
                <span className="text-2xl font-bold text-red-600">{metrics?.blocked_requests || 0}</span>
              )}
              <span className="text-xs text-muted-foreground mt-1">Blocked</span>
            </div>
            <div className="flex flex-col items-center p-3 rounded-lg bg-muted/50">
              <Eye className="h-5 w-5 text-yellow-500 mb-1" />
              {metrics?.global ? (
                <div className="flex items-center gap-2">
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-yellow-600">{metrics?.monitored_requests || 0}</span>
                    <span className="text-[10px] text-muted-foreground">local</span>
                  </div>
                  <div className="h-8 w-px bg-border" />
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-yellow-600">{(metrics.global.monitored_requests ?? 0).toLocaleString()}</span>
                    <span className="text-[10px] text-muted-foreground">global</span>
                  </div>
                </div>
              ) : (
                <span className="text-2xl font-bold text-yellow-600">{metrics?.monitored_requests || 0}</span>
              )}
              <span className="text-xs text-muted-foreground mt-1">Monitored</span>
            </div>
            <div className="flex flex-col items-center p-3 rounded-lg bg-muted/50">
              <ShieldCheck className="h-5 w-5 text-green-500 mb-1" />
              {metrics?.global ? (
                <div className="flex items-center gap-2">
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-green-600">{metrics?.allowed_requests || 0}</span>
                    <span className="text-[10px] text-muted-foreground">local</span>
                  </div>
                  <div className="h-8 w-px bg-border" />
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-green-600">{(metrics.global.allowed_requests ?? 0).toLocaleString()}</span>
                    <span className="text-[10px] text-muted-foreground">global</span>
                  </div>
                </div>
              ) : (
                <span className="text-2xl font-bold text-green-600">{metrics?.allowed_requests || 0}</span>
              )}
              <span className="text-xs text-muted-foreground mt-1">Allowed</span>
            </div>
            <div className="flex flex-col items-center p-3 rounded-lg bg-muted/50">
              <FileText className="h-5 w-5 text-purple-500 mb-1" />
              {metrics?.global ? (
                <div className="flex items-center gap-2">
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold">{metrics?.form_submissions || 0}</span>
                    <span className="text-[10px] text-muted-foreground">local</span>
                  </div>
                  <div className="h-8 w-px bg-border" />
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold">{(metrics.global.form_submissions ?? 0).toLocaleString()}</span>
                    <span className="text-[10px] text-muted-foreground">global</span>
                  </div>
                </div>
              ) : (
                <span className="text-2xl font-bold">{metrics?.form_submissions || 0}</span>
              )}
              <span className="text-xs text-muted-foreground mt-1">Form Submissions</span>
            </div>
            <div className="flex flex-col items-center p-3 rounded-lg bg-muted/50">
              <AlertTriangle className="h-5 w-5 text-orange-500 mb-1" />
              {metrics?.global ? (
                <div className="flex items-center gap-2">
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-orange-600">{metrics?.validation_errors || 0}</span>
                    <span className="text-[10px] text-muted-foreground">local</span>
                  </div>
                  <div className="h-8 w-px bg-border" />
                  <div className="flex flex-col items-center">
                    <span className="text-2xl font-bold text-orange-600">{(metrics.global.validation_errors ?? 0).toLocaleString()}</span>
                    <span className="text-[10px] text-muted-foreground">global</span>
                  </div>
                </div>
              ) : (
                <span className="text-2xl font-bold text-orange-600">{metrics?.validation_errors || 0}</span>
              )}
              <span className="text-xs text-muted-foreground mt-1">Validation Errors</span>
            </div>
          </div>

          {/* Block rate indicator */}
          {(metrics?.total_requests || 0) > 0 && (
            <div className="mt-4 pt-4 border-t">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Block Rate</span>
                <span className="font-medium">
                  {((((metrics?.blocked_requests || 0) + (metrics?.monitored_requests || 0)) / (metrics?.total_requests || 1)) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-red-500 transition-all"
                  style={{
                    width: `${((metrics?.blocked_requests || 0) / (metrics?.total_requests || 1)) * 100}%`
                  }}
                />
              </div>
              <div className="flex justify-between text-xs text-muted-foreground mt-1">
                <span>Blocked: {metrics?.blocked_requests || 0}</span>
                <span>Would Block: {metrics?.monitored_requests || 0}</span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Quick Info */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              WAF Configuration
            </CardTitle>
            <CardDescription>Current system configuration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Blocked Hashes</span>
              <span className="font-medium">{status?.blocked_hashes_count || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Allowed IPs</span>
              <span className="font-medium">{status?.whitelisted_ips_count || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Endpoints</span>
              <span className="font-medium">{status?.endpoints_count || endpoints.length}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Virtual Hosts</span>
              <span className="font-medium">{status?.vhosts_count || vhosts.length}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Virtual Hosts
            </CardTitle>
            <CardDescription>Configured hosts overview</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {vhosts.slice(0, 5).map((vhost: unknown) => {
                const v = vhost as { id: string; name: string; enabled: boolean; hostnames: unknown; waf?: { mode?: string } }
                const hostnames = Array.isArray(v.hostnames) ? v.hostnames : []
                const mode = v.waf?.mode || 'monitoring'
                return (
                  <div key={v.id} className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">{v.name || v.id}</p>
                      <p className="text-xs text-muted-foreground">
                        {hostnames.slice(0, 2).join(', ')}
                        {hostnames.length > 2 && ` +${hostnames.length - 2} more`}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <Badge variant="outline" className="text-xs">
                        {mode}
                      </Badge>
                      <Badge variant={v.enabled ? 'success' : 'secondary'}>
                        {v.enabled ? 'Active' : 'Disabled'}
                      </Badge>
                    </div>
                  </div>
                )
              })}
              {vhosts.length === 0 && (
                <p className="text-sm text-muted-foreground">No virtual hosts configured</p>
              )}
              {vhosts.length > 5 && (
                <p className="text-xs text-muted-foreground pt-2">
                  +{vhosts.length - 5} more virtual hosts
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
