import React from 'react';
import { AlertTriangle, ShieldCheck, Cpu, Skull, Zap } from 'lucide-react';

export default function AnomalyAlerts({ alerts, anomalies }) {
  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-slate-700 text-slate-300 border-slate-600';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* 1. Rule-Based Security Alerts */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-red-950/60 border border-red-500/30 rounded-lg text-red-400">
              <Skull className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-slate-100">Security Alerts & Signatures</h3>
              <p className="text-xs text-slate-400">Heuristic detections (Port scans, spikes, rogue MACs)</p>
            </div>
          </div>
          <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
            {alerts.length} Events
          </span>
        </div>

        <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
          {alerts.length === 0 ? (
            <div className="text-center py-10 bg-slate-900/40 border border-dashed border-slate-800 rounded-lg">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
              <p className="text-xs text-slate-400 font-medium">No active security alerts</p>
              <p className="text-[11px] text-slate-500">Wi-Fi perimeter behavior normal</p>
            </div>
          ) : (
            alerts.map((al, idx) => (
              <div
                key={idx}
                className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-lg flex flex-col gap-2 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(al.severity)}`}>
                      {al.severity}
                    </span>
                    <span className="font-mono text-xs font-semibold text-slate-200">
                      {al.alert_type}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">
                    {al.timestamp ? new Date(al.timestamp).toLocaleTimeString() : ''}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{al.details}</p>

                <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-800/80">
                  <span>Source: <strong className="text-cyan-300">{al.source_ip}</strong></span>
                  <span>Target: <strong className="text-slate-200">{al.target_ip}</strong></span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 2. Unsupervised Machine Learning Anomalies (Isolation Forest) */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-purple-950/60 border border-purple-500/30 rounded-lg text-purple-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-slate-100">Isolation Forest ML Anomalies</h3>
              <p className="text-xs text-slate-400">Unsupervised statistical outlier analysis</p>
            </div>
          </div>
          <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-purple-300">
            {anomalies.length} Flagged
          </span>
        </div>

        <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
          {anomalies.length === 0 ? (
            <div className="text-center py-10 bg-slate-900/40 border border-dashed border-slate-800 rounded-lg">
              <Zap className="w-8 h-8 text-purple-400 mx-auto mb-2 opacity-80" />
              <p className="text-xs text-slate-400 font-medium">No ML anomalies isolated</p>
              <p className="text-[11px] text-slate-500">Multidimensional feature vectors match normal baseline</p>
            </div>
          ) : (
            anomalies.map((anom, idx) => (
              <div
                key={idx}
                className="p-3.5 bg-slate-900/80 border border-purple-900/30 rounded-lg flex flex-col gap-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                      SCORE: {anom.anomaly_score}
                    </span>
                    <span className="font-mono text-xs font-semibold text-cyan-300">
                      Target: {anom.ip_target}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">
                    {anom.timestamp ? new Date(anom.timestamp).toLocaleTimeString() : ''}
                  </span>
                </div>

                <p className="text-xs text-slate-300">{anom.explanation}</p>

                {anom.features && (
                  <div className="grid grid-cols-3 gap-2 text-[10px] font-mono bg-slate-950/80 p-2 rounded border border-slate-800">
                    <div>
                      <span className="text-slate-500 block">Rate:</span>
                      <span className="text-slate-200">{anom.features.packet_rate} pkts/s</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Dst Ports:</span>
                      <span className="text-slate-200">{anom.features.unique_dst_ports}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">SYN Ratio:</span>
                      <span className="text-slate-200">{Math.round(anom.features.syn_ratio * 100)}%</span>
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
