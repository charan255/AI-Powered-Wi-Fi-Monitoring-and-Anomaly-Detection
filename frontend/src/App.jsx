import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import MetricCards from './components/MetricCards';
import TrafficCharts from './components/TrafficCharts';
import LiveTrafficTable from './components/LiveTrafficTable';
import AnomalyAlerts from './components/AnomalyAlerts';
import DeviceInventory from './components/DeviceInventory';
import Controls from './components/Controls';
import {
  fetchSystemStatus,
  fetchLiveTraffic,
  fetchTrafficStats,
  fetchAnomalies,
  fetchAlerts,
  fetchDevices
} from './services/api';
import { createWebSocketClient } from './services/websocket';

export default function App() {
  const [systemStatus, setSystemStatus] = useState(null);
  const [wsStatus, setWsStatus] = useState('connecting');
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [devices, setDevices] = useState([]);
  const [trafficStats, setTrafficStats] = useState(null);
  const [throughputHistory, setThroughputHistory] = useState([]);
  const [isPaused, setIsPaused] = useState(false);

  // Keep a ref to isPaused for the WebSocket callback
  const isPausedRef = useRef(isPaused);
  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  // Initial load
  const loadInitialData = async () => {
    try {
      const [statusRes, trafficRes, statsRes, anomRes, alertRes, devRes] = await Promise.all([
        fetchSystemStatus().catch(() => null),
        fetchLiveTraffic(100).catch(() => ({ packets: [] })),
        fetchTrafficStats().catch(() => null),
        fetchAnomalies(50).catch(() => ({ anomalies: [] })),
        fetchAlerts(50).catch(() => ({ alerts: [] })),
        fetchDevices().catch(() => ({ devices: [] }))
      ]);

      if (statusRes) setSystemStatus(statusRes);
      if (trafficRes?.packets) setPackets(trafficRes.packets);
      if (statsRes) setTrafficStats(statsRes);
      if (anomRes?.anomalies) setAnomalies(anomRes.anomalies);
      if (alertRes?.alerts) setAlerts(alertRes.alerts);
      if (devRes?.devices) setDevices(devRes.devices);
    } catch (err) {
      console.error("Error loading initial data", err);
    }
  };

  useEffect(() => {
    loadInitialData();

    // WebSocket subscription
    const wsClient = createWebSocketClient({
      onStatusChange: (status) => setWsStatus(status),
      onPacket: (newPacket) => {
        if (!isPausedRef.current) {
          setPackets((prev) => [newPacket, ...prev.slice(0, 199)]);
        }
      },
      onAlert: (newAlert) => {
        setAlerts((prev) => [newAlert, ...prev.slice(0, 99)]);
      },
      onAnomaly: (newAnomaly) => {
        setAnomalies((prev) => [newAnomaly, ...prev.slice(0, 99)]);
      },
      onRates: (rates) => {
        setSystemStatus((prev) => ({
          ...prev,
          capture: { ...(prev?.capture || {}), ...rates }
        }));

        // Append to rolling chart history
        const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const kbytes = Math.round((rates.bytes_per_sec || 0) / 1024);
        setThroughputHistory((prev) => {
          const updated = [...prev, { time: nowStr, kbytesPerSec: kbytes, pktsPerSec: rates.packets_per_sec || 0 }];
          return updated.slice(-25);
        });
      }
    });

    // Periodic polling for stats and devices (every 4 seconds)
    const statsInterval = setInterval(async () => {
      try {
        const [statsRes, devRes, statRes] = await Promise.all([
          fetchTrafficStats().catch(() => null),
          fetchDevices().catch(() => null),
          fetchSystemStatus().catch(() => null)
        ]);
        if (statsRes) setTrafficStats(statsRes);
        if (devRes?.devices) setDevices(devRes.devices);
        if (statRes) setSystemStatus(statRes);
      } catch (e) {
        // silent fail
      }
    }, 4000);

    return () => {
      wsClient.close();
      clearInterval(statsInterval);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0e17] text-slate-100 flex flex-col font-sans">
      <Navbar systemStatus={systemStatus} wsStatus={wsStatus} />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* Interactive Controls & Scenario Demonstrations */}
        <Controls
          systemStatus={systemStatus}
          onActionTriggered={loadInitialData}
        />

        {/* High-Level Metric Tiles */}
        <MetricCards
          stats={systemStatus?.capture}
          alertCount={alerts.length}
          anomalyCount={anomalies.length}
          deviceCount={devices.length}
        />

        {/* Visual Analytics (Bandwidth & Protocol Distribution) */}
        <TrafficCharts
          throughputHistory={throughputHistory}
          stats={trafficStats}
        />

        {/* Security Alerts (Heuristics) & Machine Learning (Isolation Forest) */}
        <AnomalyAlerts
          alerts={alerts}
          anomalies={anomalies}
        />

        {/* Live Dissected Packet Table */}
        <LiveTrafficTable
          packets={packets}
          isPaused={isPaused}
          setIsPaused={setIsPaused}
        />

        {/* Discovered Wi-Fi Hosts & Device Trust Inventory */}
        <DeviceInventory
          devices={devices}
          onDeviceUpdated={loadInitialData}
        />
      </main>

      {/* Defensive Footer Notice */}
      <footer className="border-t border-slate-900 bg-[#0d131f] py-4 text-center text-xs text-slate-500">
        <p>Defensive Wi-Fi Monitoring & Network Anomaly Detection System • CSE Final Year Project</p>
        <p className="text-[11px] text-slate-600 mt-0.5">Strictly Passive Observation & Threat Alerting • No Offensive Actions</p>
      </footer>
    </div>
  );
}
