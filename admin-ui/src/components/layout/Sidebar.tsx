import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import {
  LayoutDashboard,
  Globe,
  Route,
  Ban,
  Flag,
  Settings,
  Shield,
  Network,
  ArrowRightLeft,
  ShieldCheck,
  Cog,
  Bell,
  FileJson,
  Clock,
  MapPin,
  ShieldAlert,
  Info,
  Users,
  KeyRound,
  Activity,
  Server,
  Fingerprint,
  Workflow,
  Target,
  Archive,
} from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Virtual Hosts', href: '/vhosts', icon: Globe },
  { name: 'Endpoints', href: '/endpoints', icon: Route },
  {
    name: 'Keywords',
    children: [
      { name: 'Blocked', href: '/keywords/blocked', icon: Ban },
      { name: 'Flagged', href: '/keywords/flagged', icon: Flag },
    ],
  },
  {
    name: 'CAPTCHA',
    children: [
      { name: 'Providers', href: '/captcha/providers', icon: ShieldCheck },
      { name: 'Settings', href: '/captcha/settings', icon: Cog },
    ],
  },
  {
    name: 'Security',
    children: [
      { name: 'Form Timing', href: '/security/timing', icon: Clock },
      { name: 'Defense Profiles', href: '/security/defense-profiles', icon: Workflow },
      { name: 'Attack Signatures', href: '/security/attack-signatures', icon: Target },
      { name: 'Fingerprint Profiles', href: '/security/fingerprint-profiles', icon: Fingerprint },
      { name: 'GeoIP', href: '/security/geoip', icon: MapPin },
      { name: 'IP Reputation', href: '/security/reputation', icon: ShieldAlert },
    ],
  },
  {
    name: 'Analytics',
    children: [
      { name: 'Behavioral', href: '/analytics/behavioral', icon: Activity },
    ],
  },
  {
    name: 'Configuration',
    children: [
      { name: 'Thresholds', href: '/config/thresholds', icon: Settings },
      { name: 'Routing', href: '/config/routing', icon: ArrowRightLeft },
      { name: 'IP Allow List', href: '/config/allowlist', icon: Network },
    ],
  },
  {
    name: 'Operations',
    children: [
      { name: 'Webhooks', href: '/operations/webhooks', icon: Bell },
      { name: 'Bulk Import/Export', href: '/operations/bulk', icon: FileJson },
    ],
  },
  {
    name: 'Admin',
    children: [
      { name: 'User Management', href: '/admin/users', icon: Users },
      { name: 'Auth Providers', href: '/admin/providers', icon: KeyRound },
      { name: 'Backup & Restore', href: '/admin/backup', icon: Archive },
      { name: 'Cluster Status', href: '/cluster', icon: Server },
    ],
  },
  { name: 'About', href: '/about', icon: Info },
]

export function Sidebar() {
  return (
    <div className="flex h-full w-64 flex-col border-r bg-background">
      <div className="flex h-16 items-center border-b px-6">
        <Shield className="h-6 w-6 text-primary" />
        <span className="ml-2 text-lg font-semibold">Forms WAF</span>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navigation.map((item) =>
          item.children ? (
            <div key={item.name} className="space-y-1">
              <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {item.name}
              </div>
              {item.children.map((child) => (
                <NavLink
                  key={child.href}
                  to={child.href}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                    )
                  }
                >
                  <child.icon className="h-4 w-4" />
                  {child.name}
                </NavLink>
              ))}
            </div>
          ) : (
            <NavLink
              key={item.href}
              to={item.href}
              end={item.href === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.name}
            </NavLink>
          )
        )}
      </nav>
    </div>
  )
}
