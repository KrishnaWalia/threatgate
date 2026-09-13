import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts';

export default function TimelineChart({ data }) {
  return (
    <div className="bg-surface border border-border rounded-lg p-4 h-full flex flex-col">
      <h2 className="text-sm font-medium mb-3">Allowed vs. blocked (last hour)</h2>
      <div className="flex-1 min-h-[180px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ left: -12, right: 16 }}>
            <CartesianGrid stroke="#243244" vertical={false} />
            <XAxis dataKey="bucket" stroke="#8A97A6" fontSize={11} />
            <YAxis stroke="#8A97A6" fontSize={11} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#182230', border: '1px solid #243244', borderRadius: 8 }}
              labelStyle={{ color: '#E6EDF3' }}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Line type="monotone" dataKey="allowed" stroke="#3DDC97" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="blocked" stroke="#FF5D5D" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
