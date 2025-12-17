import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { authProvidersApi, type AuthProviderPublic } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Shield, AlertCircle, KeyRound, ExternalLink, ArrowLeft } from 'lucide-react'

export function Login() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { login, isAuthenticated, checkAuth } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [providers, setProviders] = useState<AuthProviderPublic[]>([])
  const [localAuthEnabled, setLocalAuthEnabled] = useState(true)
  const [loadingProviders, setLoadingProviders] = useState(true)
  const [selectedLdapProvider, setSelectedLdapProvider] = useState<AuthProviderPublic | null>(null)

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/')
    }
  }, [isAuthenticated, navigate])

  // Check for error from SSO callback
  useEffect(() => {
    const errorParam = searchParams.get('error')
    if (errorParam) {
      setError(decodeURIComponent(errorParam))
    }
  }, [searchParams])

  // Fetch available providers
  useEffect(() => {
    const fetchProviders = async () => {
      try {
        const data = await authProvidersApi.listPublic()
        setProviders(data.providers || [])
        setLocalAuthEnabled(data.local_auth_enabled !== false)
      } catch {
        // If we can't fetch providers, assume local auth is available
        setLocalAuthEnabled(true)
      } finally {
        setLoadingProviders(false)
      }
    }

    fetchProviders()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (selectedLdapProvider) {
        // LDAP authentication
        await authProvidersApi.authenticateLdap(selectedLdapProvider.id, username, password)
        // Re-check auth to update context
        await checkAuth()
        navigate('/')
      } else {
        // Local authentication
        await login(username, password)
        navigate('/')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleSSOLogin = (provider: AuthProviderPublic) => {
    if (provider.type === 'ldap') {
      // LDAP requires username/password - show the form
      setSelectedLdapProvider(provider)
      setUsername('')
      setPassword('')
      setError('')
    } else {
      // OIDC/SAML - redirect to SSO initiation endpoint
      window.location.href = authProvidersApi.getSSOUrl(provider.type, provider.id)
    }
  }

  const handleBackToProviders = () => {
    setSelectedLdapProvider(null)
    setUsername('')
    setPassword('')
    setError('')
  }

  const getProviderIcon = (provider: AuthProviderPublic) => {
    // Return custom icon if defined, otherwise a default based on type
    if (provider.icon) {
      return <img src={provider.icon} alt="" className="h-5 w-5" />
    }

    // Default icons based on provider type
    switch (provider.type) {
      case 'oidc':
        return <KeyRound className="h-5 w-5" />
      case 'saml':
        return <Shield className="h-5 w-5" />
      case 'ldap':
        return <KeyRound className="h-5 w-5" />
      default:
        return <ExternalLink className="h-5 w-5" />
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/30">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary">
            <Shield className="h-6 w-6 text-primary-foreground" />
          </div>
          <CardTitle className="text-2xl">Forms WAF Admin</CardTitle>
          <CardDescription>
            {selectedLdapProvider
              ? `Sign in with ${selectedLdapProvider.name}`
              : 'Sign in to manage your WAF configuration'
            }
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {error && (
            <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* LDAP Provider Login Form */}
          {selectedLdapProvider && (
            <>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="gap-2 -ml-2"
                onClick={handleBackToProviders}
              >
                <ArrowLeft className="h-4 w-4" />
                Back to login options
              </Button>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="ldap-username">Username</Label>
                  <Input
                    id="ldap-username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Enter your LDAP username"
                    required
                    autoComplete="username"
                    autoFocus
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="ldap-password">Password</Label>
                  <Input
                    id="ldap-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    required
                    autoComplete="current-password"
                  />
                </div>
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? 'Signing in...' : `Sign in with ${selectedLdapProvider.name}`}
                </Button>
              </form>
            </>
          )}

          {/* SSO Providers */}
          {!selectedLdapProvider && !loadingProviders && providers.length > 0 && (
            <>
              <div className="space-y-3">
                {providers.map((provider) => (
                  <Button
                    key={provider.id}
                    type="button"
                    variant="outline"
                    className="w-full justify-start gap-3"
                    onClick={() => handleSSOLogin(provider)}
                  >
                    {getProviderIcon(provider)}
                    <span>Sign in with {provider.name}</span>
                  </Button>
                ))}
              </div>

              {localAuthEnabled && (
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <Separator className="w-full" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-card px-2 text-muted-foreground">
                      Or continue with
                    </span>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Local Auth Form */}
          {!selectedLdapProvider && localAuthEnabled && (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username"
                  required
                  autoComplete="username"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Signing in...' : 'Sign In'}
              </Button>
            </form>
          )}

          {/* No auth methods available */}
          {!loadingProviders && !localAuthEnabled && providers.length === 0 && (
            <div className="text-center text-sm text-muted-foreground">
              No authentication methods are configured.
              Please contact your administrator.
            </div>
          )}

          {/* Loading state */}
          {loadingProviders && (
            <div className="flex justify-center py-4">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
