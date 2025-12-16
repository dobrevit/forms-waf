import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Shield,
  Github,
  Bug,
  BookOpen,
  ExternalLink,
  Heart,
  Scale,
  Mail,
  Globe,
} from 'lucide-react'

const VERSION = '1.0.0'
const GITHUB_REPO = 'https://github.com/dobrevit/forms-waf'

interface LinkCardProps {
  title: string
  description: string
  href: string
  icon: React.ElementType
}

function LinkCard({ title, description, href, icon: Icon }: LinkCardProps) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="block"
    >
      <Card className="h-full transition-colors hover:bg-muted/50">
        <CardHeader className="flex flex-row items-center gap-4 pb-2">
          <div className="rounded-lg bg-primary/10 p-2">
            <Icon className="h-5 w-5 text-primary" />
          </div>
          <div className="flex-1">
            <CardTitle className="text-base flex items-center gap-2">
              {title}
              <ExternalLink className="h-3 w-3 text-muted-foreground" />
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{description}</p>
        </CardContent>
      </Card>
    </a>
  )
}

export function About() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">About Forms WAF</h2>
        <p className="text-muted-foreground">
          Web Application Firewall for form spam protection
        </p>
      </div>

      {/* Hero Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="rounded-xl bg-primary/10 p-4">
              <Shield className="h-12 w-12 text-primary" />
            </div>
            <div>
              <CardTitle className="text-2xl">Forms WAF</CardTitle>
              <CardDescription className="text-base">
                Intelligent form spam protection with machine learning-inspired scoring
              </CardDescription>
              <div className="mt-2 flex items-center gap-2">
                <Badge variant="secondary">v{VERSION}</Badge>
                <Badge variant="outline">MIT License</Badge>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">
            Forms WAF is an open-source web application firewall designed to protect web forms
            from spam, bots, and malicious submissions. It uses a multi-layered approach combining
            content analysis, behavioral detection, rate limiting, and threat intelligence to
            identify and block unwanted traffic while allowing legitimate users through.
          </p>
        </CardContent>
      </Card>

      {/* Quick Links */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Quick Links</h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <LinkCard
            title="GitHub Repository"
            description="View source code, star the project, and contribute"
            href={GITHUB_REPO}
            icon={Github}
          />
          <LinkCard
            title="Report an Issue"
            description="Found a bug? Let us know so we can fix it"
            href={`${GITHUB_REPO}/issues/new`}
            icon={Bug}
          />
          <LinkCard
            title="Documentation"
            description="Read the full documentation and guides"
            href={`${GITHUB_REPO}#readme`}
            icon={BookOpen}
          />
        </div>
      </div>

      {/* Features */}
      <Card>
        <CardHeader>
          <CardTitle>Key Features</CardTitle>
          <CardDescription>What makes Forms WAF powerful</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <h4 className="font-medium">Content Analysis</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Keyword blocking and flagging with scoring</li>
                <li>• Disposable email detection (250+ domains)</li>
                <li>• URL shortener and suspicious link detection</li>
                <li>• Honeypot field support</li>
              </ul>
            </div>
            <div className="space-y-3">
              <h4 className="font-medium">Behavioral Detection</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Form timing validation</li>
                <li>• Field anomaly detection</li>
                <li>• Submission fingerprinting</li>
                <li>• Duplicate content hashing</li>
              </ul>
            </div>
            <div className="space-y-3">
              <h4 className="font-medium">Threat Intelligence</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• GeoIP country/ASN restrictions</li>
                <li>• Datacenter/VPN detection</li>
                <li>• IP reputation management</li>
                <li>• Rate limiting per IP/endpoint</li>
              </ul>
            </div>
            <div className="space-y-3">
              <h4 className="font-medium">Bot Protection</h4>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• CAPTCHA integration (reCAPTCHA, hCaptcha, Turnstile)</li>
                <li>• Trust tokens for verified users</li>
                <li>• Configurable challenge triggers</li>
                <li>• Progressive security escalation</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* License & Credits */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Scale className="h-5 w-5" />
              License
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Forms WAF is released under the MIT License. You are free to use, modify,
              and distribute this software for any purpose.
            </p>
            <p className="text-sm font-medium">
              Copyright © 2025 Dobrev IT Ltd.
            </p>
            <Button variant="outline" size="sm" asChild>
              <a href={`${GITHUB_REPO}/blob/main/LICENSE`} target="_blank" rel="noopener noreferrer">
                View License
                <ExternalLink className="ml-2 h-3 w-3" />
              </a>
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Heart className="h-5 w-5 text-red-500" />
              Support the Project
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              If you find Forms WAF useful, consider supporting the project:
            </p>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Star the repository on GitHub</li>
              <li>• Report bugs and suggest features</li>
              <li>• Contribute code or documentation</li>
              <li>• Share with others who might benefit</li>
            </ul>
            <Button variant="outline" size="sm" asChild>
              <a href={GITHUB_REPO} target="_blank" rel="noopener noreferrer">
                <Github className="mr-2 h-4 w-4" />
                Star on GitHub
              </a>
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Tech Stack */}
      <Card>
        <CardHeader>
          <CardTitle>Technology Stack</CardTitle>
          <CardDescription>Built with modern, battle-tested technologies</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            <Badge variant="secondary">OpenResty / Nginx</Badge>
            <Badge variant="secondary">Lua</Badge>
            <Badge variant="secondary">HAProxy</Badge>
            <Badge variant="secondary">Redis</Badge>
            <Badge variant="secondary">React</Badge>
            <Badge variant="secondary">TypeScript</Badge>
            <Badge variant="secondary">Tailwind CSS</Badge>
            <Badge variant="secondary">Docker</Badge>
            <Badge variant="secondary">Kubernetes / Helm</Badge>
            <Badge variant="secondary">MaxMind GeoIP</Badge>
          </div>
        </CardContent>
      </Card>

      {/* Footer */}
      <div className="text-center text-sm text-muted-foreground py-4">
        <p>
          Made with <Heart className="inline h-4 w-4 text-red-500" /> by{' '}
          <a
            href="https://dobrev.it"
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-foreground hover:underline"
          >
            Dobrev IT Ltd.
          </a>
        </p>
      </div>
    </div>
  )
}
