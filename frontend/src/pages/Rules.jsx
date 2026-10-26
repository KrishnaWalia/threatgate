import { useEffect, useState, useCallback } from 'react';
import Sidebar from '../components/Sidebar';
import http from '../api/http';
import { useAuth } from '../context/AuthContext';

const CATEGORY_LABEL = { sqli: 'SQL Injection', xss: 'XSS', path_traversal: 'Path Traversal', other: 'Other' };
const CATEGORY_STYLE = {
  sqli: 'bg-danger/15 text-danger',
  xss: 'bg-warn/15 text-warn',
  path_traversal: 'bg-brand/15 text-brand',
  other: 'bg-surface2 text-muted',
};

export default function Rules() {
  const { isAdmin } = useAuth();
  const [rules, setRules] = useState([]);
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState(null);

  const load = useCallback(async () => {
    try {
      const { data } = await http.get('/api/dashboard/rules');
      setRules(data.rules);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Could not load rules.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Rules are data: flipping a switch here changes how the very next
  // proxied request is judged — no restart.
  async function patch(id, body) {
    setBusyId(id);
    try {
      const { data } = await http.patch(`/api/dashboard/rules/${id}`, body);
      setRules((prev) => prev.map((r) => (r.id === id ? data.rule : r)));
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Could not update rule.');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="flex min-h-screen bg-base">
      <Sidebar />
      <main className="flex-1 p-6 space-y-5 max-w-[1100px]">
        <div>
          <h1 className="text-lg font-semibold">Detection rules</h1>
          <p className="text-sm text-muted">
            The regex rules the WAF runs on every request. A request is blocked when its combined risk score reaches the threshold.
            {isAdmin ? ' Toggle a rule or change its weight — it applies instantly.' : ' Read-only for viewers.'}
          </p>
        </div>

        {error && (
          <div className="text-sm text-danger bg-danger/10 border border-danger/30 rounded-md px-3 py-2">{error}</div>
        )}

        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted uppercase tracking-wide font-mono border-b border-border">
                <th className="px-4 py-3 w-12">ID</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">What it catches</th>
                <th className="px-4 py-3">Pattern</th>
                <th className="px-4 py-3 w-20">Weight</th>
                <th className="px-4 py-3 w-20">Active</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rules.map((r) => (
                <tr key={r.id} className={r.is_active ? '' : 'opacity-50'}>
                  <td className="px-4 py-3 font-mono text-muted">{r.id}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[11px] font-mono uppercase tracking-wide px-1.5 py-0.5 rounded ${CATEGORY_STYLE[r.category]}`}>
                      {CATEGORY_LABEL[r.category] || r.category}
                    </span>
                  </td>
                  <td className="px-4 py-3">{r.description}</td>
                  <td className="px-4 py-3 font-mono text-xs text-muted max-w-[280px] truncate" title={r.pattern}>{r.pattern}</td>
                  <td className="px-4 py-3">
                    {isAdmin ? (
                      <input
                        type="number" min="1" max="100" defaultValue={r.weight} key={`${r.id}-${r.weight}`}
                        onBlur={(e) => {
                          const w = parseInt(e.target.value, 10);
                          if (w >= 1 && w <= 100 && w !== r.weight) patch(r.id, { weight: w });
                        }}
                        className="w-16 bg-base border border-border rounded px-2 py-1 font-mono text-xs"
                      />
                    ) : (
                      <span className="font-mono">{r.weight}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      disabled={!isAdmin || busyId === r.id}
                      onClick={() => patch(r.id, { is_active: !r.is_active })}
                      className={`text-xs font-mono px-2 py-1 rounded border ${
                        r.is_active ? 'border-safe/40 text-safe bg-safe/10' : 'border-border text-muted'
                      } disabled:cursor-not-allowed`}
                    >
                      {r.is_active ? 'on' : 'off'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
