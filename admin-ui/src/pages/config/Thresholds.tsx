import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { configApi } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { Save, Settings, Info } from 'lucide-react'

interface ThresholdConfig {
  spam_score_block: number
  spam_score_flag: number
  hash_count_block: number
  ip_rate_limit: number
  ip_daily_limit?: number
  hash_unique_ips_block?: number
}

export function Thresholds() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [values, setValues] = useState<ThresholdConfig>({
    spam_score_block: 80,
    spam_score_flag: 50,
    hash_count_block: 10,
    ip_rate_limit: 30,
    ip_daily_limit: 500,
    hash_unique_ips_block: 5,
  })

  const { data, isLoading } = useQuery({
    queryKey: ['config', 'thresholds'],
    queryFn: configApi.getThresholds,
  })

  useEffect(() => {
    const thresholds = (data as { thresholds: Record<string, number> } | undefined)?.thresholds
    if (thresholds) {
      setValues({
        spam_score_block: thresholds.spam_score_block || 80,
        spam_score_flag: thresholds.spam_score_flag || 50,
        hash_count_block: thresholds.hash_count_block || 10,
        ip_rate_limit: thresholds.ip_rate_limit || 30,
        ip_daily_limit: thresholds.ip_daily_limit || 500,
        hash_unique_ips_block: thresholds.hash_unique_ips_block || 5,
      })
    }
  }, [data])

  const saveMutation = useMutation({
    mutationFn: async (config: ThresholdConfig) => {
      const promises = Object.entries(config).map(([name, value]) =>
        configApi.setThreshold(name, value)
      )
      await Promise.all(promises)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config', 'thresholds'] })
      toast({ title: 'Thresholds saved' })
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to save thresholds',
        variant: 'destructive',
      })
    },
  })

  const handleSave = () => {
    saveMutation.mutate(values)
  }

  if (isLoading) {
    return <div>Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Thresholds</h2>
        <p className="text-muted-foreground">
          Configure global WAF thresholds and limits
        </p>
      </div>

      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="flex items-center gap-4 py-4">
          <Info className="h-5 w-5 text-blue-500" />
          <div>
            <p className="font-medium text-blue-800">Global Settings</p>
            <p className="text-sm text-blue-600">
              These thresholds apply globally but can be overridden per virtual host or endpoint.
            </p>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Settings className="h-5 w-5" />
              Spam Score Thresholds
            </CardTitle>
            <CardDescription>
              Configure when to flag or block based on spam score
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="spam_score_block">Block Threshold</Label>
              <Input
                id="spam_score_block"
                type="number"
                value={values.spam_score_block}
                onChange={(e) =>
                  setValues({ ...values, spam_score_block: parseInt(e.target.value) || 0 })
                }
              />
              <p className="text-xs text-muted-foreground">
                Submissions with score &gt;= this value are blocked
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="spam_score_flag">Flag Threshold</Label>
              <Input
                id="spam_score_flag"
                type="number"
                value={values.spam_score_flag}
                onChange={(e) =>
                  setValues({ ...values, spam_score_flag: parseInt(e.target.value) || 0 })
                }
              />
              <p className="text-xs text-muted-foreground">
                Submissions with score &gt;= this value are flagged for review
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Settings className="h-5 w-5" />
              Rate Limiting
            </CardTitle>
            <CardDescription>
              Configure IP-based rate limiting
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="ip_rate_limit">Requests per Minute</Label>
              <Input
                id="ip_rate_limit"
                type="number"
                value={values.ip_rate_limit}
                onChange={(e) =>
                  setValues({ ...values, ip_rate_limit: parseInt(e.target.value) || 0 })
                }
              />
              <p className="text-xs text-muted-foreground">
                Maximum form submissions per IP per minute
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="ip_daily_limit">Daily Limit</Label>
              <Input
                id="ip_daily_limit"
                type="number"
                value={values.ip_daily_limit}
                onChange={(e) =>
                  setValues({ ...values, ip_daily_limit: parseInt(e.target.value) || 0 })
                }
              />
              <p className="text-xs text-muted-foreground">
                Maximum form submissions per IP per day
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Settings className="h-5 w-5" />
              Content Hash Thresholds
            </CardTitle>
            <CardDescription>
              Configure duplicate content detection
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="hash_count_block">Hash Count Block</Label>
              <Input
                id="hash_count_block"
                type="number"
                value={values.hash_count_block}
                onChange={(e) =>
                  setValues({ ...values, hash_count_block: parseInt(e.target.value) || 0 })
                }
              />
              <p className="text-xs text-muted-foreground">
                Block if same content hash seen this many times
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="hash_unique_ips_block">Unique IPs Block</Label>
              <Input
                id="hash_unique_ips_block"
                type="number"
                value={values.hash_unique_ips_block}
                onChange={(e) =>
                  setValues({ ...values, hash_unique_ips_block: parseInt(e.target.value) || 0 })
                }
              />
              <p className="text-xs text-muted-foreground">
                Block if same hash from fewer than this many unique IPs
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saveMutation.isPending}>
          <Save className="mr-2 h-4 w-4" />
          {saveMutation.isPending ? 'Saving...' : 'Save Thresholds'}
        </Button>
      </div>
    </div>
  )
}
