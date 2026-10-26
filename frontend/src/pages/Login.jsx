import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login, error } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('admin@threatgate.dev');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    const ok = await login(email, password);
    setSubmitting(false);
    if (ok) navigate('/dashboard');
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-base px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2 mb-8 justify-center">
          <span className="h-2 w-2 rounded-full bg-safe" />
          <span className="font-mono text-sm text-muted tracking-wide">threatgate / console</span>
        </div>

        <div className="bg-surface border border-border rounded-lg p-8">
          <h1 className="text-xl font-semibold mb-1">Sign in</h1>
          <p className="text-sm text-muted mb-6">Access the live traffic console for your org.</p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm text-muted mb-1.5" htmlFor="email">
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-surface2 border border-border rounded-md px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-brand"
                placeholder="you@org.com"
              />
            </div>
            <div>
              <label className="block text-sm text-muted mb-1.5" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-surface2 border border-border rounded-md px-3 py-2 text-sm text-ink focus:outline-none focus:ring-2 focus:ring-brand"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="text-sm text-danger bg-danger/10 border border-danger/30 rounded-md px-3 py-2">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full bg-brand hover:bg-brand/90 disabled:opacity-60 text-base font-medium rounded-md py-2 text-sm transition-colors"
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>

        <p className="text-xs text-muted text-center mt-6 font-mono">
          demo: admin@threatgate.dev / Admin123! · viewer@threatgate.dev / Viewer123!
        </p>
      </div>
    </div>
  );
}
