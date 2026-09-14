import { Link } from 'react-router-dom';

function Feature({ title, desc }) {
  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <h3 className="text-sm font-medium mb-1.5">{title}</h3>
      <p className="text-sm text-muted leading-relaxed">{desc}</p>
    </div>
  );
}

export default function Landing() {
  return (
    <div className="min-h-screen bg-base">
      <header className="max-w-5xl mx-auto px-6 py-5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-safe" />
          <span className="font-mono text-sm tracking-wide">threatgate</span>
        </div>
        <Link
          to="/login"
          className="text-sm bg-brand hover:bg-brand/90 text-base font-medium rounded-md px-4 py-2 transition-colors"
        >
          Sign in
        </Link>
      </header>

      <main className="max-w-5xl mx-auto px-6 pt-20 pb-24">
        <div className="max-w-2xl">
          <span className="inline-block text-xs font-mono uppercase tracking-wide text-brand bg-brand/10 rounded px-2 py-1 mb-5">
            reverse-proxy WAF
          </span>
          <h1 className="text-4xl font-semibold leading-tight mb-4">
            Real-time protection against SQL injection, XSS, and brute-force attacks.
          </h1>
          <p className="text-muted text-base leading-relaxed mb-8">
            ThreatGate sits in front of your app as a reverse proxy, scores every request
            against a rules engine, and blocks the ones that cross the line — with a live
            dashboard so you can see exactly what's happening as it happens.
          </p>
          <div className="flex items-center gap-3">
            <Link
              to="/login"
              className="bg-brand hover:bg-brand/90 text-base font-medium rounded-md px-5 py-2.5 text-sm transition-colors"
            >
              Go to console
            </Link>
          </div>
        </div>

        <div className="grid sm:grid-cols-3 gap-4 mt-16">
          <Feature
            title="Detection engine"
            desc="Rules-as-data scoring for SQLi, XSS, and path traversal — tunable without a redeploy."
          />
          <Feature
            title="Live dashboard"
            desc="Every request decision streams in over Socket.io the moment it happens."
          />
          <Feature
            title="Role-based access"
            desc="JWT + bcrypt auth with admin vs. viewer roles enforced at the API, not just the UI."
          />
        </div>
      </main>
    </div>
  );
}
