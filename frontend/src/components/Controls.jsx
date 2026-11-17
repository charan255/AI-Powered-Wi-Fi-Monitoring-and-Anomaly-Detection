import React, { useState } from 'react';
import { Play, Square, Sliders, Zap, RefreshCw, Radio } from 'lucide-react';
import {
  startCapture,
  stopCapture,
  toggleSimulationMode,
  triggerSimulationScenario,
  retrainMLModel
} from '../services/api';

export default function Controls({ systemStatus, onActionTriggered }) {
  const isRunning = systemStatus?.capture?.is_running;
  const isSim = systemStatus?.capture?.simulation_mode;
  const [injecting, setInjecting] = useState(false);
  const [retraining, setRetraining] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState('');

  const showFeedback = (msg) => {
    setFeedbackMsg(msg);
    setTimeout(() => setFeedbackMsg(''), 4000);
  };

  const handleStartStop = async () => {
    try {
      if (isRunning) {
        await stopCapture();
        showFeedback("Capture stopped.");
      } else {
        await startCapture();
        showFeedback("Capture started.");
      }
      if (onActionTriggered) onActionTriggered();
    } catch (e) {
      showFeedback(`Error: ${e.message}`);
    }
  };

  const handleToggleMode = async () => {
    try {
      await toggleSimulationMode(!isSim);
      showFeedback(`Switched to ${!isSim ? 'Simulation' : 'Live Sniff'} Mode.`);
      if (onActionTriggered) onActionTriggered();
    } catch (e) {
      showFeedback(`Error: ${e.message}`);
    }
  };

  const handleInjectScenario = async (scenario, label) => {
    setInjecting(true);
    try {
      const res = await triggerSimulationScenario(scenario);
      showFeedback(`Triggered test scenario: ${label} (${res.injected_packets} packets)`);
      if (onActionTriggered) onActionTriggered();
    } catch (e) {
      showFeedback(`Injection error: ${e.message}`);
    } finally {
      setInjecting(false);
    }
  };

  const handleRetrain = async () => {
    setRetraining(true);
    try {
      await retrainMLModel();
      showFeedback("Isolation Forest model successfully retrained!");
      if (onActionTriggered) onActionTriggered();
    } catch (e) {
      showFeedback(`Retrain error: ${e.message}`);
    } finally {
      setRetraining(false);
    }
  };

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left: Engine Controls */}
        <div className="flex items-center flex-wrap gap-3">
          <button
            onClick={handleStartStop}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
              isRunning
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 hover:bg-red-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
            }`}
          >
            {isRunning ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            {isRunning ? 'Stop Sniffer Engine' : 'Start Sniffer Engine'}
          </button>

          <button
            onClick={handleToggleMode}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-900 border border-slate-700 hover:border-slate-600 rounded-lg text-xs font-medium text-slate-200 transition-colors"
          >
            <Radio className={`w-3.5 h-3.5 ${isSim ? 'text-amber-400' : 'text-cyan-400'}`} />
            <span>Mode: <strong>{isSim ? 'Simulation / Demo' : 'Live NIC Sniffing'}</strong></span>
          </button>

          <button
            onClick={handleRetrain}
            disabled={retraining}
            className="flex items-center gap-2 px-3.5 py-2 bg-purple-950/40 border border-purple-500/30 hover:bg-purple-950/70 text-purple-300 rounded-lg text-xs font-medium transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${retraining ? 'animate-spin' : ''}`} />
            <span>{retraining ? 'Training Model...' : 'Retrain Isolation Forest'}</span>
          </button>
        </div>

        {/* Right: Defense Demonstration Injections (Viva & Presentation) */}
        <div className="flex items-center flex-wrap gap-2">
          <span className="text-xs text-slate-400 font-medium mr-1 flex items-center gap-1">
            <Zap className="w-3.5 h-3.5 text-amber-400" /> Test Attack Injections:
          </span>

          <button
            onClick={() => handleInjectScenario('port_scan', 'SYN Port Scan')}
            disabled={injecting}
            className="px-2.5 py-1.5 bg-red-950/40 hover:bg-red-900/60 border border-red-500/30 text-red-300 rounded text-xs transition-colors"
          >
            Port Scan (SYN)
          </button>

          <button
            onClick={() => handleInjectScenario('spike', 'Connection Surge')}
            disabled={injecting}
            className="px-2.5 py-1.5 bg-amber-950/40 hover:bg-amber-900/60 border border-amber-500/30 text-amber-300 rounded text-xs transition-colors"
          >
            Packet Flood
          </button>

          <button
            onClick={() => handleInjectScenario('bandwidth', 'Bandwidth Burst')}
            disabled={injecting}
            className="px-2.5 py-1.5 bg-blue-950/40 hover:bg-blue-900/60 border border-blue-500/30 text-blue-300 rounded text-xs transition-colors"
          >
            Bandwidth Burst
          </button>

          <button
            onClick={() => handleInjectScenario('unknown_device', 'Rogue Device')}
            disabled={injecting}
            className="px-2.5 py-1.5 bg-purple-950/40 hover:bg-purple-900/60 border border-purple-500/30 text-purple-300 rounded text-xs transition-colors"
          >
            Unknown MAC
          </button>
        </div>
      </div>

      {feedbackMsg && (
        <div className="mt-3 text-xs font-mono text-cyan-300 bg-cyan-950/40 border border-cyan-500/30 px-3 py-1.5 rounded-lg">
          {feedbackMsg}
        </div>
      )}
    </div>
  );
}
