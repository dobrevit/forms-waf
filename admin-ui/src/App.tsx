import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { AppLayout } from '@/components/layout/AppLayout'
import { Login } from '@/pages/Login'
import { Dashboard } from '@/pages/Dashboard'
import { VhostList } from '@/pages/vhosts/VhostList'
import { VhostForm } from '@/pages/vhosts/VhostForm'
import { EndpointList } from '@/pages/endpoints/EndpointList'
import { EndpointForm } from '@/pages/endpoints/EndpointForm'
import { BlockedKeywords } from '@/pages/keywords/BlockedKeywords'
import { FlaggedKeywords } from '@/pages/keywords/FlaggedKeywords'
import { Thresholds } from '@/pages/config/Thresholds'
import { RoutingConfig } from '@/pages/config/RoutingConfig'
import { IpAllowList } from '@/pages/config/IpAllowList'
import { CaptchaProviders } from '@/pages/captcha/CaptchaProviders'
import { CaptchaSettings } from '@/pages/captcha/CaptchaSettings'
import { WebhookSettings } from '@/pages/webhooks/WebhookSettings'
import { BulkOperations } from '@/pages/bulk/BulkOperations'
import TimingConfig from '@/pages/security/TimingConfig'
import GeoIPConfig from '@/pages/security/GeoIPConfig'
import ReputationConfig from '@/pages/security/ReputationConfig'
import { FingerprintProfiles } from '@/pages/security/FingerprintProfiles'
import DefenseProfiles from '@/pages/security/DefenseProfiles'
import DefenseProfileEditor from '@/pages/security/DefenseProfileEditor'
import AttackSignatures from '@/pages/security/AttackSignatures'
import AttackSignatureEditor from '@/pages/security/AttackSignatureEditor'
import BehavioralAnalytics from '@/pages/analytics/BehavioralAnalytics'
import ClusterStatus from '@/pages/cluster/ClusterStatus'
import { About } from '@/pages/About'
import { Users } from '@/pages/admin/Users'
import { AuthProviders } from '@/pages/admin/AuthProviders'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <AppLayout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/vhosts" element={<VhostList />} />
                <Route path="/vhosts/new" element={<VhostForm />} />
                <Route path="/vhosts/:id" element={<VhostForm />} />
                <Route path="/endpoints" element={<EndpointList />} />
                <Route path="/endpoints/new" element={<EndpointForm />} />
                <Route path="/endpoints/:id" element={<EndpointForm />} />
                <Route path="/keywords/blocked" element={<BlockedKeywords />} />
                <Route path="/keywords/flagged" element={<FlaggedKeywords />} />
                <Route path="/config/thresholds" element={<Thresholds />} />
                <Route path="/config/routing" element={<RoutingConfig />} />
                <Route path="/config/allowlist" element={<IpAllowList />} />
                <Route path="/captcha/providers" element={<CaptchaProviders />} />
                <Route path="/captcha/settings" element={<CaptchaSettings />} />
                <Route path="/operations/webhooks" element={<WebhookSettings />} />
                <Route path="/operations/bulk" element={<BulkOperations />} />
                <Route path="/security/timing" element={<TimingConfig />} />
                <Route path="/security/geoip" element={<GeoIPConfig />} />
                <Route path="/security/reputation" element={<ReputationConfig />} />
                <Route path="/security/fingerprint-profiles" element={<FingerprintProfiles />} />
                <Route path="/security/defense-profiles" element={<DefenseProfiles />} />
                <Route path="/security/defense-profiles/new" element={<DefenseProfileEditor />} />
                <Route path="/security/defense-profiles/:id" element={<DefenseProfileEditor />} />
                <Route path="/security/attack-signatures" element={<AttackSignatures />} />
                <Route path="/security/attack-signatures/:id" element={<AttackSignatureEditor />} />
                <Route path="/analytics/behavioral" element={<BehavioralAnalytics />} />
                <Route path="/cluster" element={<ClusterStatus />} />
                <Route path="/about" element={<About />} />
                <Route path="/admin/users" element={<Users />} />
                <Route path="/admin/providers" element={<AuthProviders />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </AppLayout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}
