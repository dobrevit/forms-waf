import { useQuery } from '@tanstack/react-query'
import { attackSignaturesApi } from '@/api/client'
import { Card, CardContent } from '@/components/ui/card'
import { Loader2, Target, CheckCircle, XCircle, Shield, TrendingUp } from 'lucide-react'

interface SignatureStatsSummaryProps {
  className?: string
}

// Format large numbers
function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toString()
}

export function SignatureStatsSummary({ className }: SignatureStatsSummaryProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['attack-signatures-summary'],
    queryFn: () => attackSignaturesApi.getStatsSummary(),
    refetchInterval: 60000, // Refresh every minute
  })

  if (isLoading) {
    return (
      <Card className={className}>
        <CardContent className="py-4">
          <div className="flex items-center justify-center">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        </CardContent>
      </Card>
    )
  }

  const summary = data?.summary

  if (!summary) {
    return null
  }

  const stats = [
    {
      label: 'Total Signatures',
      value: summary.total_signatures,
      icon: Target,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
    },
    {
      label: 'Enabled',
      value: summary.enabled_count,
      icon: CheckCircle,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
    },
    {
      label: 'Disabled',
      value: summary.disabled_count,
      icon: XCircle,
      color: 'text-gray-600',
      bgColor: 'bg-gray-50',
    },
    {
      label: 'Built-in',
      value: summary.builtin_count,
      icon: Shield,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
    },
    {
      label: 'Total Matches',
      value: summary.total_matches || 0,
      icon: TrendingUp,
      color: 'text-amber-600',
      bgColor: 'bg-amber-50',
      format: true,
    },
  ]

  return (
    <Card className={className}>
      <CardContent className="py-4">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {stats.map((stat) => (
            <div key={stat.label} className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${stat.bgColor}`}>
                <stat.icon className={`h-5 w-5 ${stat.color}`} />
              </div>
              <div>
                <div className="text-2xl font-bold">
                  {stat.format ? formatNumber(stat.value) : stat.value}
                </div>
                <div className="text-xs text-muted-foreground">{stat.label}</div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
