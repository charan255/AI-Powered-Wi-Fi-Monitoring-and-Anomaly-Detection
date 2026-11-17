export function createWebSocketClient({ onPacket, onAlert, onAnomaly, onRates, onStatusChange }) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/live`;
  let socket = null;
  let reconnectTimer = null;
  let isIntentionallyClosed = false;

  function connect() {
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      if (onStatusChange) onStatusChange('connected');
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'packet') {
          if (onPacket) onPacket(payload.data);
          if (onRates && payload.rates) onRates(payload.rates);
        } else if (payload.type === 'alert') {
          if (onAlert) onAlert(payload.data);
        } else if (payload.type === 'anomaly') {
          if (onAnomaly) onAnomaly(payload.data);
        }
      } catch (err) {
        console.error("WS Parse error", err);
      }
    };

    socket.onclose = () => {
      if (onStatusChange) onStatusChange('disconnected');
      if (!isIntentionallyClosed) {
        reconnectTimer = setTimeout(connect, 3000);
      }
    };

    socket.onerror = (err) => {
      console.warn("WebSocket error:", err);
      socket.close();
    };
  }

  connect();

  // Ping interval
  const pingInterval = setInterval(() => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send('ping');
    }
  }, 10000);

  return {
    close: () => {
      isIntentionallyClosed = true;
      clearInterval(pingInterval);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (socket) socket.close();
    }
  };
}
