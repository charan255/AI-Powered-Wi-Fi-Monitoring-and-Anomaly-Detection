const API_BASE = '/api';

export async function fetchSystemStatus() {
  const res = await fetch(`${API_BASE}/status`);
  if (!res.ok) throw new Error('Failed to fetch status');
  return res.json();
}

export async function fetchLiveTraffic(limit = 100, protocol = '', ip = '') {
  let url = `${API_BASE}/traffic/live?limit=${limit}`;
  if (protocol) url += `&protocol=${encodeURIComponent(protocol)}`;
  if (ip) url += `&ip=${encodeURIComponent(ip)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch traffic');
  return res.json();
}

export async function fetchTrafficStats() {
  const res = await fetch(`${API_BASE}/traffic/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchAnomalies(limit = 50) {
  const res = await fetch(`${API_BASE}/anomalies?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch anomalies');
  return res.json();
}

export async function fetchAlerts(limit = 50) {
  const res = await fetch(`${API_BASE}/alerts?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function fetchDevices() {
  const res = await fetch(`${API_BASE}/devices`);
  if (!res.ok) throw new Error('Failed to fetch devices');
  return res.json();
}

export async function toggleDeviceTrust(mac, isTrusted) {
  const res = await fetch(`${API_BASE}/devices/${encodeURIComponent(mac)}/trust`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ is_trusted: isTrusted })
  });
  if (!res.ok) throw new Error('Failed to update device trust');
  return res.json();
}

export async function startCapture() {
  const res = await fetch(`${API_BASE}/capture/start`, { method: 'POST' });
  return res.json();
}

export async function stopCapture() {
  const res = await fetch(`${API_BASE}/capture/stop`, { method: 'POST' });
  return res.json();
}

export async function toggleSimulationMode(enabled) {
  const res = await fetch(`${API_BASE}/capture/mode?simulation=${enabled}`, { method: 'POST' });
  return res.json();
}

export async function triggerSimulationScenario(scenario) {
  const res = await fetch(`${API_BASE}/simulate/${scenario}`, { method: 'POST' });
  return res.json();
}

export async function retrainMLModel() {
  const res = await fetch(`${API_BASE}/ml/retrain`, { method: 'POST' });
  return res.json();
}
