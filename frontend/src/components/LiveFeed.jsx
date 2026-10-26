const CATEGORY_LABEL = {
  sqli: 'SQL Injection',
  xss: 'XSS',
  path_traversal: 'Path Traversal',
  brute_force: 'Brute Force',
  none: 'Normal',
};

function Badge({ action }) {
  const isBlocked = action === 'blocked';
  return (
    <span
      className={`text-[11px] font-mono uppercase tracking-wide px-1.5 py-0.5 rounded ${
        isBlocked ? 'bg-danger/15 text-danger' : 'bg-safe/15 text-safe'
      }`}
    >
      {action}
    </span>
  );
}

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

export default function LiveFeed({ logs }) {
  return (
    <div className="bg-surface border border-border rounded-lg flex flex-col h-full">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h2 className="text-sm font-medium">Live request feed</h2>
        <span className="flex items-center gap-1.5 text-xs text-muted font-mono">
          <span className="h-1.5 w-1.5 rounded-full bg-safe animate-pulse" />
          streaming
        </span>
      </div>

      <div className="overflow-y-auto scroll-thin flex-1 divide-y divide-border">
        {logs.length === 0 && (
          <p className="text-sm text-muted px-4 py-6 text-center">
            No requests yet. They'll appear here the moment traffic comes through.
          </p>
        )}

        {logs.map((log) => (
          <div key={log.id} className="px-4 py-2.5 flex items-center gap-3 text-sm">
            <span className="text-muted font-mono text-xs w-20 shrink-0">{formatTime(log.created_at)}</span>
            <span className="font-mono text-xs text-muted w-14 shrink-0">{log.method}</span>
            <span className="font-mono truncate flex-1 text-ink/90">{log.path}</span>
            <span className="text-xs text-muted w-32 shrink-0 truncate">
              {CATEGORY_LABEL[log.category] || log.category}
            </span>
            <span className="text-xs font-mono w-10 shrink-0 text-right text-muted">{log.risk_score}</span>
            <Badge action={log.action} />
          </div>
        ))}
      </div>
    </div>
  );
}
