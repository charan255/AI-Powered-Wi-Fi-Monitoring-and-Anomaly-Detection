import React from 'react';
import {
  AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts';

const PROTOCOL_COLORS = {
  TCP: '#06b6d4',
  UDP: '#8b5cf6',
  ICMP: '#f59e0b',
  ARP: '#10b981',
  DNS: '#3b82f6',
  Other: '#64748b'
};

export default function TrafficCharts({ throughputHistory, stats }) {
  const protocolData = stats?.protocol_distribution || [
    { name: 'TCP', value: 45 },
    { name: 'UDP', value: 30 },
    { name: 'DNS', value: 15 },
    { name: 'ARP', value: 10 }
  ];

  const topTalkers = stats?.top_talkers || [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Chart 1: Bandwidth Area Chart */}
      <div className="lg:col-span-2 bg-[#111827] border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="font-semibold text-sm text-slate-100">Live Traffic Throughput & Rates</h3>
            <p className="text-xs text-slate-400">Bandwidth velocity (KB/s) & packet arrival rate</p>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
            Rolling Window: 30s
          </span>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={throughputHistory} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorKbps" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
                </linearGradient>
                <linearGradient id="colorPkts" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#475569" fontSize={11} tickLine={false} />
              <YAxis stroke="#475569" fontSize={11} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
              <Area type="monotone" dataKey="kbytesPerSec" name="KB/s" stroke="#06b6d4" fillOpacity={1} fill="url(#colorKbps)" />
              <Area type="monotone" dataKey="pktsPerSec" name="Packets/s" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorPkts)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 2: Protocol Breakdown */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
        <div>
          <h3 className="font-semibold text-sm text-slate-100">Protocol Distribution</h3>
          <p className="text-xs text-slate-400">Proportion of network transport protocols</p>
        </div>

        <div className="h-52 w-full mt-2">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={protocolData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={4}
              >
                {protocolData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={PROTOCOL_COLORS[entry.name] || '#38bdf8'}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Legend pills */}
        <div className="flex flex-wrap gap-2 justify-center mt-2">
          {protocolData.map((item, idx) => (
            <div key={idx} className="flex items-center gap-1.5 text-xs text-slate-300">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: PROTOCOL_COLORS[item.name] || '#38bdf8' }}
              />
              <span>{item.name}:</span>
              <span className="font-mono font-medium text-slate-400">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
