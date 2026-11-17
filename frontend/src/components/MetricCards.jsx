import React from 'react';
import { Activity, ShieldAlert, Cpu, HardDriveDownload, Laptop } from 'lucide-react';

export default function MetricCards({ stats, alertCount, anomalyCount, deviceCount }) {
  const pktsPerSec = stats?.packets_per_sec || 0;
  const bytesPerSec = stats?.bytes_per_sec || 0;
  const kbps = Math.round((bytesPerSec * 8) / 1024);
  const totalPackets = stats?.total_packets || 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {/* Metric 1: Live Packet Velocity */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center gap-4">
        <div className="p-3 bg-cyan-950/60 border border-cyan-500/20 text-cyan-400 rounded-lg">
          <Activity className="w-5 h-5 animate-pulse" />
        </div>
        <div>
          <p className="text-xs font-medium text-slate-400">Packet Velocity</p>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold text-slate-100">{pktsPerSec}</span>
            <span className="text-xs text-slate-400">pkts/sec</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5">Total: {totalPackets.toLocaleString()}</p>
        </div>
      </div>

      {/* Metric 2: Live Network Throughput */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center gap-4">
        <div className="p-3 bg-blue-950/60 border border-blue-500/20 text-blue-400 rounded-lg">
          <HardDriveDownload className="w-5 h-5" />
        </div>
        <div>
          <p className="text-xs font-medium text-slate-400">Throughput</p>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold text-slate-100">{kbps}</span>
            <span className="text-xs text-slate-400">Kbps</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5">{Math.round(bytesPerSec / 1024)} KB/s</p>
        </div>
      </div>

      {/* Metric 3: ML Anomalies */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center gap-4">
        <div className="p-3 bg-purple-950/60 border border-purple-500/20 text-purple-400 rounded-lg">
          <Cpu className="w-5 h-5" />
        </div>
        <div>
          <p className="text-xs font-medium text-slate-400">ML Anomalies</p>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold text-purple-300">{anomalyCount}</span>
            <span className="text-xs text-slate-400">detected</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5">Isolation Forest</p>
        </div>
      </div>

      {/* Metric 4: Heuristic Alerts */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center gap-4">
        <div className={`p-3 rounded-lg border ${alertCount > 0 ? 'bg-red-950/60 border-red-500/30 text-red-400 animate-pulse' : 'bg-slate-900 border-slate-800 text-slate-400'}`}>
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <p className="text-xs font-medium text-slate-400">Security Alerts</p>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className={`text-xl font-bold ${alertCount > 0 ? 'text-red-400' : 'text-slate-100'}`}>
              {alertCount}
            </span>
            <span className="text-xs text-slate-400">threats</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5">Heuristics & Port Scans</p>
        </div>
      </div>

      {/* Metric 5: Active Devices */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center gap-4">
        <div className="p-3 bg-emerald-950/60 border border-emerald-500/20 text-emerald-400 rounded-lg">
          <Laptop className="w-5 h-5" />
        </div>
        <div>
          <p className="text-xs font-medium text-slate-400">Discovered Hosts</p>
          <div className="flex items-baseline gap-1.5 mt-0.5">
            <span className="text-xl font-bold text-emerald-300">{deviceCount}</span>
            <span className="text-xs text-slate-400">devices</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5">Wi-Fi Inventory</p>
        </div>
      </div>
    </div>
  );
}
