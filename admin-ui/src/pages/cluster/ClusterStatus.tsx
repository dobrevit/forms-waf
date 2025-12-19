import { useQuery } from '@tanstack/react-query'
import { clusterApi } from '@/api/client'
import type { ClusterInstance } from '@/api/client'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert'
import {
  Server,
  Crown,
  Activity,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Cpu,
  RefreshCw,
} from 'lucide-react'
import { Button } from '@/components/ui/button'

function formatTimestamp(timestamp: number): string {
  if (!timestamp) return 'Never'
  const date = new Date(timestamp * 1000)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSecs = Math.floor(diffMs / 1000)
  const diffMins = Math.floor(diffSecs / 60)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSecs < 60) return `${diffSecs} second${diffSecs !== 1 ? 's' : ''} ago`
  if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
}

function getStatusBadgeVariant(status: string): 'success' | 'warning' | 'destructive' | 'secondary' {
  switch (status) {
    case 'active':
      return 'success'
    case 'drifted':
      return 'warning'
    case 'down':
      return 'destructive'
    default:
      return 'secondary'
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'active':
      return <CheckCircle className="h-4 w-4 text-green-500" />
    case 'drifted':
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    case 'down':
      return <XCircle className="h-4 w-4 text-red-500" />
    default:
      return <Activity className="h-4 w-4 text-gray-500" />
  }
}

export default function ClusterStatus() {
  const { data: statusData, isLoading: statusLoading, refetch: refetchStatus } = useQuery({
    queryKey: ['cluster', 'status'],
    queryFn: clusterApi.getStatus,
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const { data: instancesData, isLoading: instancesLoading, refetch: refetchInstances } = useQuery({
    queryKey: ['cluster', 'instances'],
    queryFn: clusterApi.getInstances,
    refetchInterval: 10000,
  })

  const { data: thisInstance } = useQuery({
    queryKey: ['cluster', 'this'],
    queryFn: clusterApi.getThis,
    refetchInterval: 10000,
  })

  const { data: configData } = useQuery({
    queryKey: ['cluster', 'config'],
    queryFn: clusterApi.getConfig,
  })

  const handleRefresh = () => {
    refetchStatus()
    refetchInstances()
  }

  const instances = instancesData?.instances || []
  const isLoading = statusLoading || instancesLoading

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Cluster Status</h2>
          <p className="text-muted-foreground">
            Monitor WAF instances, leader election, and cluster health
          </p>
        </div>
        <Button variant="outline" onClick={handleRefresh} disabled={isLoading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Cluster Health Banner */}
      <Card className={statusData?.cluster_healthy ? 'border-green-500' : 'border-red-500'}>
        <CardContent className="flex items-center gap-4 py-4">
          {isLoading ? (
            <Activity className="h-5 w-5 animate-pulse" />
          ) : statusData?.cluster_healthy ? (
            <CheckCircle className="h-5 w-5 text-green-500" />
          ) : (
            <XCircle className="h-5 w-5 text-red-500" />
          )}
          <div>
            <p className="font-medium">
              {isLoading
                ? 'Checking cluster status...'
                : statusData?.cluster_healthy
                ? 'Cluster is healthy'
                : 'Cluster health issues detected'}
            </p>
            <p className="text-sm text-muted-foreground">
              {statusData?.active_instances || 0} active instance(s) of {statusData?.instance_count || 0} total
            </p>
          </div>
          <Badge
            variant={statusData?.cluster_healthy ? 'success' : 'destructive'}
            className="ml-auto"
          >
            {statusData?.cluster_healthy ? 'Healthy' : 'Unhealthy'}
          </Badge>
        </CardContent>
      </Card>

      {/* This Instance Info */}
      {thisInstance && (
        <Alert variant="default">
          <Server className="h-5 w-5" />
          <AlertTitle className="flex items-center gap-2">
            This Instance: {thisInstance.instance_id}
            {thisInstance.is_leader && (
              <Badge variant="default" className="ml-2">
                <Crown className="h-3 w-3 mr-1" />
                Leader
              </Badge>
            )}
          </AlertTitle>
          <AlertDescription>
            Worker {thisInstance.worker_id} of {thisInstance.worker_count} workers
          </AlertDescription>
        </Alert>
      )}

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Instances</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statusData?.instance_count || 0}</div>
            <p className="text-xs text-muted-foreground">Registered in cluster</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Instances</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{statusData?.active_instances || 0}</div>
            <p className="text-xs text-muted-foreground">Responding normally</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Drifted Instances</CardTitle>
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{statusData?.drifted_instances || 0}</div>
            <p className="text-xs text-muted-foreground">Heartbeat delayed</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Current Leader</CardTitle>
            <Crown className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold truncate">
              {statusData?.leader?.instance_id || 'None'}
            </div>
            <p className="text-xs text-muted-foreground">
              {statusData?.leader?.since ? `Since ${formatTimestamp(statusData.leader.since)}` : 'No leader elected'}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Instances List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Registered Instances
          </CardTitle>
          <CardDescription>
            All WAF instances registered in the cluster
          </CardDescription>
        </CardHeader>
        <CardContent>
          {instances.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4 text-center">
              No instances registered yet. Instances will appear here after they start and register their heartbeat.
            </p>
          ) : (
            <div className="space-y-4">
              {instances.map((instance: ClusterInstance) => (
                <div
                  key={instance.instance_id}
                  className="flex items-center justify-between p-4 rounded-lg border bg-card"
                >
                  <div className="flex items-center gap-4">
                    {getStatusIcon(instance.status)}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{instance.instance_id}</span>
                        {instancesData?.current_leader === instance.instance_id && (
                          <Badge variant="default" className="text-xs">
                            <Crown className="h-3 w-3 mr-1" />
                            Leader
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Cpu className="h-3 w-3" />
                          {instance.worker_count} workers
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          Started {formatTimestamp(instance.started_at)}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right text-sm">
                      <p className="text-muted-foreground">Last heartbeat</p>
                      <p className="font-medium">{formatTimestamp(instance.last_heartbeat)}</p>
                    </div>
                    <Badge variant={getStatusBadgeVariant(instance.status)}>
                      {instance.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Configuration */}
      {configData && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Coordinator Configuration
            </CardTitle>
            <CardDescription>
              Instance coordination and leader election settings
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <div className="flex justify-between p-3 rounded-lg bg-muted/50">
                <span className="text-muted-foreground">Instance ID</span>
                <span className="font-mono font-medium">{configData.instance_id}</span>
              </div>
              <div className="flex justify-between p-3 rounded-lg bg-muted/50">
                <span className="text-muted-foreground">Heartbeat Interval</span>
                <span className="font-medium">{configData.heartbeat_interval}s</span>
              </div>
              <div className="flex justify-between p-3 rounded-lg bg-muted/50">
                <span className="text-muted-foreground">Heartbeat TTL</span>
                <span className="font-medium">{configData.heartbeat_ttl}s</span>
              </div>
              <div className="flex justify-between p-3 rounded-lg bg-muted/50">
                <span className="text-muted-foreground">Leader TTL</span>
                <span className="font-medium">{configData.leader_ttl}s</span>
              </div>
              <div className="flex justify-between p-3 rounded-lg bg-muted/50">
                <span className="text-muted-foreground">Drift Threshold</span>
                <span className="font-medium">{configData.drift_threshold}s</span>
              </div>
              <div className="flex justify-between p-3 rounded-lg bg-muted/50">
                <span className="text-muted-foreground">Stale Threshold</span>
                <span className="font-medium">{configData.stale_threshold}s</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
