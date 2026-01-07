import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { attackSignaturesApi } from '@/api/client'
import type { AttackSignatureTestResult } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import { Loader2, Play, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'

interface SignatureTestDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  signatureId: string
  signatureName: string
}

interface TestSample {
  user_agent?: string
  content?: string
  username?: string
  password?: string
}

export function SignatureTestDialog({
  open,
  onOpenChange,
  signatureId,
  signatureName,
}: SignatureTestDialogProps) {
  const [sample, setSample] = useState<TestSample>({
    user_agent: '',
    content: '',
    username: '',
    password: '',
  })
  const [result, setResult] = useState<AttackSignatureTestResult | null>(null)

  const testMutation = useMutation({
    mutationFn: () => attackSignaturesApi.test(signatureId, sample),
    onSuccess: (data) => {
      setResult(data.test)
    },
  })

  const handleTest = () => {
    setResult(null)
    testMutation.mutate()
  }

  const handleClose = () => {
    setResult(null)
    setSample({
      user_agent: '',
      content: '',
      username: '',
      password: '',
    })
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Play className="h-5 w-5" />
            Test Signature: {signatureName}
          </DialogTitle>
          <DialogDescription>
            Enter sample values to test this signature's patterns. The test will show which patterns match.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <Tabs defaultValue="fingerprint">
            <TabsList className="grid grid-cols-3 w-full">
              <TabsTrigger value="fingerprint">User Agent</TabsTrigger>
              <TabsTrigger value="content">Content</TabsTrigger>
              <TabsTrigger value="credentials">Credentials</TabsTrigger>
            </TabsList>

            <TabsContent value="fingerprint" className="space-y-4 mt-4">
              <div className="space-y-2">
                <Label htmlFor="user_agent">User-Agent String</Label>
                <Input
                  id="user_agent"
                  placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
                  value={sample.user_agent || ''}
                  onChange={(e) => setSample({ ...sample, user_agent: e.target.value })}
                />
                <p className="text-sm text-muted-foreground">
                  Test against blocked_user_agents and flagged_user_agents patterns
                </p>
              </div>
              <div className="flex gap-2 text-xs">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSample({ ...sample, user_agent: 'python-requests/2.28.0' })}
                >
                  Python Requests
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSample({ ...sample, user_agent: 'curl/7.68.0' })}
                >
                  curl
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSample({ ...sample, user_agent: 'WPScan v3.8.22' })}
                >
                  WPScan
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="content" className="space-y-4 mt-4">
              <div className="space-y-2">
                <Label htmlFor="content">Request Content/Body</Label>
                <Textarea
                  id="content"
                  placeholder="Enter form data, message content, etc..."
                  className="min-h-[120px]"
                  value={sample.content || ''}
                  onChange={(e) => setSample({ ...sample, content: e.target.value })}
                />
                <p className="text-sm text-muted-foreground">
                  Test against blocked_keywords, flagged_keywords, and pattern rules
                </p>
              </div>
            </TabsContent>

            <TabsContent value="credentials" className="space-y-4 mt-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    placeholder="admin, root, test..."
                    value={sample.username || ''}
                    onChange={(e) => setSample({ ...sample, username: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="password123..."
                    value={sample.password || ''}
                    onChange={(e) => setSample({ ...sample, password: e.target.value })}
                  />
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Test against blocked_usernames and blocked_passwords (credential stuffing detection)
              </p>
              <div className="flex gap-2 text-xs">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSample({ ...sample, username: 'admin' })}
                >
                  admin
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSample({ ...sample, password: 'password123' })}
                >
                  password123
                </Button>
              </div>
            </TabsContent>
          </Tabs>

          <div className="flex justify-end">
            <Button onClick={handleTest} disabled={testMutation.isPending}>
              {testMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Play className="h-4 w-4 mr-2" />
              )}
              Run Test
            </Button>
          </div>

          {/* Results */}
          {result && (
            <div className="border rounded-lg p-4 space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="font-medium">Test Results</h4>
                <div className="flex items-center gap-2">
                  {result.would_block ? (
                    <Badge variant="destructive" className="flex items-center gap-1">
                      <XCircle className="h-3 w-3" />
                      Would Block
                    </Badge>
                  ) : result.matches.length > 0 ? (
                    <Badge variant="outline" className="text-amber-600 border-amber-300 flex items-center gap-1">
                      <AlertTriangle className="h-3 w-3" />
                      Flagged (Score: {result.total_score})
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-green-600 border-green-300 flex items-center gap-1">
                      <CheckCircle className="h-3 w-3" />
                      No Match
                    </Badge>
                  )}
                </div>
              </div>

              {result.matches.length > 0 ? (
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    {result.matches.length} pattern{result.matches.length !== 1 ? 's' : ''} matched:
                  </p>
                  <div className="space-y-2">
                    {result.matches.map((match, index) => (
                      <div
                        key={index}
                        className={`p-3 rounded-lg text-sm ${
                          match.action === 'block'
                            ? 'bg-red-50 border border-red-200'
                            : 'bg-amber-50 border border-amber-200'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Badge
                              variant={match.action === 'block' ? 'destructive' : 'outline'}
                              className="text-xs"
                            >
                              {match.action}
                            </Badge>
                            <span className="font-medium">{match.type}</span>
                            <span className="text-muted-foreground">({match.pattern_type})</span>
                          </div>
                          {match.score && (
                            <span className="text-xs text-muted-foreground">+{match.score} score</span>
                          )}
                        </div>
                        <div className="font-mono text-xs mt-1">
                          Pattern: <code className="bg-white/50 px-1 rounded">{match.pattern}</code>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1 truncate">
                          Matched: {match.matched_value}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No patterns in this signature matched the provided sample data.
                </p>
              )}
            </div>
          )}

          {testMutation.isError && (
            <div className="border border-red-200 bg-red-50 rounded-lg p-4 text-sm text-red-800">
              Error testing signature: {(testMutation.error as Error).message}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
