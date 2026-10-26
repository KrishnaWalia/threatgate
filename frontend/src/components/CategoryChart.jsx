import { BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const CATEGORY_LABEL = {
  sqli: 'SQLi',
  xss: 'XSS',
  path_traversal: 'Path Traversal',
  brute_force: 'Brute Force',
  none: 'Normal',
};

const CATEGORY_COLOR = {
  sqli: '#FF5D5D',
  xss: '#FFB454',
  path_traversal: '#4C9EEB',
  brute_force: '#C792EA',
  none: '#3DDC97',
};

export default function CategoryChart({ data }) {
  const chartData = data.map((d) => ({
    name: CATEGORY_LABEL[d.category] || d.category,
    count: Number(d.count),
    fill: CATEGORY_COLOR[d.category] || '#8A97A6',
  }));

  return (
    <div className="bg-surface border border-border rounded-lg p-4 h-full flex flex-col">
      <h2 className="text-sm font-medium mb-3">Attacks by category (24h)</h2>
      <div className="flex-1 min-h-[180px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 16 }}>
            <CartesianGrid stroke="#243244" horizontal={false} />
            <XAxis type="number" stroke="#8A97A6" fontSize={11} allowDecimals={false} />
            <YAxis type="category" dataKey="name" stroke="#8A97A6" fontSize={11} width={90} />
            <Tooltip
              contentStyle={{ background: '#182230', border: '1px solid #243244', borderRadius: 8 }}
              labelStyle={{ color: '#E6EDF3' }}
              cursor={{ fill: '#ffffff08' }}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={index} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
