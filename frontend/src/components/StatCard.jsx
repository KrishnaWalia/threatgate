export default function StatCard({ label, value, accent = 'text-ink', hint }) {
  return (
    <div className="bg-surface border border-border rounded-lg px-4 py-3.5">
      <p className="text-xs text-muted uppercase tracking-wide font-mono">{label}</p>
      <p className={`text-2xl font-semibold mt-1.5 ${accent}`}>{value}</p>
      {hint && <p className="text-xs text-muted mt-1">{hint}</p>}
    </div>
  );
}
