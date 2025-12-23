import { useQuery } from '@tanstack/react-query'
import { attackSignaturesApi } from '@/api/client'
import type { AttackSignatureStats } from '@/api/types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { BarChart3, Clock, TrendingUp, Target, Loader2 } from 'lucide-react'

interface SignatureStatsPanelProps {
  signatureId: string
  signatureName?: string
  className?: string
}

// Format large numbers
function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toString()
}

// Format relative time
function formatRelativeTime(dateStr?: string): string {
  if (!dateStr) return 'Never'
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSecs = Math.floor(diffMs / 1000)
  const diffMins = Math.floor(diffSecs / 60)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffSecs < 60) return 'Just now'
  if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`
  if (diffDays < 30) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`
  return date.toLocaleDateString()
}

// Defense type labels for display
const DEFENSE_TYPE_LABELS: Record<string, string> = {
  fingerprint: 'User-Agent Patterns',
  keyword_filter: 'Keywords',
  rate_limiter: 'Rate Limits',
  ip_allowlist: 'IP Allowlist',
  ip_reputation: 'IP Reputation',
  geoip: 'GeoIP',
  timing_token: 'Timing Token',
  behavioral: 'Behavioral',
  honeypot: 'Honeypot',
  content_hash: 'Content Hash',
  expected_fields: 'Expected Fields',
  pattern_scan: 'Pattern Scan',
  disposable_email: 'Disposable Email',
  field_anomalies: 'Field Anomalies',
  header_consistency: 'Header Consistency',
}

export function SignatureStatsPanel({ signatureId, signatureName, className }: SignatureStatsPanelProps) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['attack-signature-stats', signatureId],
    queryFn: () => attackSignaturesApi.getStats(signatureId),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const stats: AttackSignatureStats | undefined = data?.stats

  if (isLoading) {
    return (
      <Card className={className}>
        <CardContent className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    )
  }

  if (error || !stats) {
    return (
      <Card className={className}>
        <CardContent className="py-6 text-center text-muted-foreground">
          Unable to load statistics
        </CardContent>
      </Card>
    )
  }

  const totalMatches = stats.total_matches || 0
  const matchesByType = stats.matches_by_type || {}
  const sortedTypes = Object.entries(matchesByType)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 6) // Top 6 types

  const maxMatches = sortedTypes.length > 0 ? sortedTypes[0][1] : 0

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5" />
          {signatureName ? `Statistics: ${signatureName}` : 'Signature Statistics'}
        </CardTitle>
        <CardDescription>
          Match statistics and performance metrics
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Summary Stats */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <TrendingUp className="h-4 w-4" />
              Total Matches
            </div>
            <div className="text-2xl font-bold">{formatNumber(totalMatches)}</div>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Clock className="h-4 w-4" />
              Last Match
            </div>
            <div className="text-lg font-medium">
              {formatRelativeTime(stats.last_match_at)}
            </div>
          </div>
        </div>

        {/* Matches by Type */}
        {sortedTypes.length > 0 && (
          <div className="space-y-3">
            <h4 className="text-sm font-medium flex items-center gap-2">
              <Target className="h-4 w-4" />
              Matches by Defense Type
            </h4>
            <div className="space-y-3">
              {sortedTypes.map(([type, count]) => {
                const percentage = maxMatches > 0 ? (count / maxMatches) * 100 : 0
                const totalPercentage = totalMatches > 0 ? (count / totalMatches) * 100 : 0
                return (
                  <div key={type} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">
                        {DEFENSE_TYPE_LABELS[type] || type}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-medium">{formatNumber(count)}</span>
                        <Badge variant="secondary" className="text-xs">
                          {totalPercentage.toFixed(0)}%
                        </Badge>
                      </div>
                    </div>
                    <Progress value={percentage} className="h-2" />
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {totalMatches === 0 && (
          <div className="text-center py-4 text-muted-foreground">
            <Target className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No matches recorded yet</p>
            <p className="text-sm">Stats will appear when this signature matches requests</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
