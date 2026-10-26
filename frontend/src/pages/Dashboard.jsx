import { useEffect, useState, useCallback } from 'react';
import Sidebar from '../components/Sidebar';
import StatCard from '../components/StatCard';
import LiveFeed from '../components/LiveFeed';
import CategoryChart from '../components/CategoryChart';
import TimelineChart from '../components/TimelineChart';
import http from '../api/http';
import { getSocket } from '../api/socket';

const MAX_FEED_ROWS = 100;

export default function Dashboard() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loadError, setLoadError] = useState('');

  const loadInitial = useCallback(async () => {
    try {
      const [logsRes, statsRes] = await Promise.all([
        http.get('/api/dashboard/logs?limit=50'),
        http.get('/api/dashboard/stats'),
      ]);
      setLogs(logsRes.data.logs);
      setStats(statsRes.data);
      setLoadError('');
    } catch (err) {
      setLoadError('Could not reach the ThreatGate API. Is the backend running?');
    }
  }, []);

  // Initial REST load, then re-poll stats periodically since
  // aggregates (24h/1h buckets) are cheap to recompute but not
  // worth re-deriving on every single socket event.
  useEffect(() => {
    loadInitial();
    const statsPoll = setInterval(() => {
      http.get('/api/dashboard/stats').then((res) => setStats(res.data)).catch(() => {});
    }, 5000);
    return () => clearInterval(statsPoll);
  }, [loadInitial]);

  // Socket.io keeps the live feed pushing without polling: every
  // 'attack:new' event is prepended, capped at MAX_FEED_ROWS so the
  // DOM doesn't grow unbounded during a long demo.
  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    // A live event also changes the totals/charts, so refresh stats
    // shortly after (debounced: a burst of events = one request).
    let statsTimer = null;
    function handleNewLog(row) {
      setLogs((prev) => [row, ...prev].slice(0, MAX_FEED_ROWS));
      clearTimeout(statsTimer);
      statsTimer = setTimeout(() => {
        http.get('/api/dashboard/stats').then((res) => setStats(res.data)).catch(() => {});
      }, 700);
    }

    socket.on('attack:new', handleNewLog);
    socket.on('connect_error', () => setLoadError('Live feed disconnected — retrying…'));
    socket.on('connect', () => setLoadError(''));

    return () => {
      clearTimeout(statsTimer);
      socket.off('attack:new', handleNewLog);
      socket.off('connect_error');
      socket.off('connect');
    };
  }, []);

  return (
    <div className="flex min-h-screen bg-base">
      <Sidebar />

      <main className="flex-1 p-6 space-y-5 max-w-[1400px]">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">Live Feed</h1>
            <p className="text-sm text-muted">Real-time request decisions across your org.</p>
          </div>
        </div>

        {loadError && (
          <div className="text-sm text-warn bg-warn/10 border border-warn/30 rounded-md px-3 py-2">
            {loadError}
          </div>
        )}

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total requests" value={stats?.totalRequests ?? '—'} />
          <StatCard label="Blocked" value={stats?.totalBlocked ?? '—'} accent="text-danger" />
          <StatCard label="Allowed" value={stats?.totalAllowed ?? '—'} accent="text-safe" />
          <StatCard label="Active IP blocks" value={stats?.activeBlockedIps ?? '—'} accent="text-warn" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 h-64">
          <CategoryChart data={stats?.byCategory || []} />
          <TimelineChart data={stats?.timeline || []} />
        </div>

        <div className="h-[420px]">
          <LiveFeed logs={logs} />
        </div>
      </main>
    </div>
  );
}
