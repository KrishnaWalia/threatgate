import { useEffect, useState, useCallback } from 'react';
import Sidebar from '../components/Sidebar';
import http from '../api/http';
import { getSocket } from '../api/socket';

function formatDate(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

export default function BlockedIps() {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState('');
  const [removingId, setRemovingId] = useState(null);

  const load = useCallback(async () => {
    try {
      const { data } = await http.get('/api/dashboard/blocked-ips');
      setRows(data.blockedIps);
      setError('');
    } catch (err) {
      // A viewer that somehow lands here would get a 403 from the
      // backend — this message reflects that the API is the real
      // gate, not just the sidebar link being hidden.
      setError(err.response?.data?.error || 'Could not load blocked IPs.');
    }
  }, []);

  useEffect(() => {
    load();
    const socket = getSocket();
    if (!socket) return;
    socket.on('blocked-ips:changed', load);
    return () => socket.off('blocked-ips:changed', load);
  }, [load]);

  async function handleUnblock(id) {
    setRemovingId(id);
    try {
      await http.delete(`/api/dashboard/blocked-ips/${id}`);
      setRows((prev) => prev.filter((r) => r.id !== id));
    } catch (err) {
      setError(err.response?.data?.error || 'Could not remove block.');
    } finally {
      setRemovingId(null);
    }
  }

  return (
    <div className="flex min-h-screen bg-base">
      <Sidebar />

      <main className="flex-1 p-6 space-y-5 max-w-[1000px]">
        <div>
          <h1 className="text-lg font-semibold">Blocked IPs</h1>
          <p className="text-sm text-muted">
            Admin-only. IPs auto-blocked by the brute-force/rate-limit logic, plus any manual blocks.
          </p>
        </div>

        {error && (
          <div className="text-sm text-danger bg-danger/10 border border-danger/30 rounded-md px-3 py-2">
            {error}
          </div>
        )}

        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted uppercase tracking-wide font-mono border-b border-border">
                <th className="px-4 py-3">IP address</th>
                <th className="px-4 py-3">Reason</th>
                <th className="px-4 py-3">Blocked at</th>
                <th className="px-4 py-3">Expires</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-muted">
                    No blocked IPs right now.
                  </td>
                </tr>
              )}
              {rows.map((row) => (
                <tr key={row.id}>
                  <td className="px-4 py-3 font-mono">{row.ip_address}</td>
                  <td className="px-4 py-3 text-muted">{row.reason || '—'}</td>
                  <td className="px-4 py-3 text-muted">{formatDate(row.blocked_at)}</td>
                  <td className="px-4 py-3 text-muted">
                    {row.expires_at ? formatDate(row.expires_at) : 'Permanent'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleUnblock(row.id)}
                      disabled={removingId === row.id}
                      className="text-xs font-mono text-brand hover:underline disabled:opacity-50"
                    >
                      {removingId === row.id ? 'removing…' : 'unblock'}
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
