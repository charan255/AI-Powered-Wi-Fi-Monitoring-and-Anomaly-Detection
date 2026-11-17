import React from 'react';
import { Shield, Wifi, Activity, Database, Cpu } from 'lucide-react';

export default function Navbar({ systemStatus, wsStatus }) {
  const isMongoConnected = systemStatus?.database?.is_connected;
  const isCapturing = systemStatus?.capture?.is_running;
  const isSim = systemStatus?.capture?.simulation_mode;

  return (
    <header className="bg-[#0f172a] border-b border-slate-800 sticky top-0 z-50 px-6 py-3">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Title */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-950/80 border border-cyan-500/40 rounded-lg text-cyan-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-bold text-lg text-slate-100 tracking-tight flex items-center gap-2">
              PRICEPULSE / NetDefend AI
              <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                CSE Final Year
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              AI-Powered Wi-Fi Network Monitoring, Traffic Logging & Anomaly Detection
            </p>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="flex items-center flex-wrap gap-2 text-xs">
          {/* WebSocket Live Indicator */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700">
            <span className={`w-2 h-2 rounded-full ${wsStatus === 'connected' ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
            <span className="text-slate-300 font-medium">WS: {wsStatus}</span>
          </div>

          {/* Sniffer State */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700">
            <Wifi className={`w-3.5 h-3.5 ${isCapturing ? 'text-emerald-400' : 'text-slate-500'}`} />
            <span className="text-slate-300">
              {isCapturing ? (isSim ? 'Sniffer: Sim' : 'Sniffer: Live') : 'Sniffer: Stopped'}
            </span>
          </div>

          {/* Database State */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700">
            <Database className={`w-3.5 h-3.5 ${isMongoConnected ? 'text-emerald-400' : 'text-amber-400'}`} />
            <span className="text-slate-300">
              {isMongoConnected ? 'MongoDB: Online' : 'DB: In-Memory (Active)'}
            </span>
          </div>

          {/* ML Model State */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-300">Isolation Forest: Ready</span>
          </div>
        </div>
      </div>
    </header>
  );
}
