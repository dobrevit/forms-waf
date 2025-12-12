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
import { IpWhitelist } from '@/pages/config/IpWhitelist'

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
                <Route path="/config/whitelist" element={<IpWhitelist />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </AppLayout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}
