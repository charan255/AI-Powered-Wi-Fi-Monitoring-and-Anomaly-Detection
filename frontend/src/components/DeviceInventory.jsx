import React from 'react';
import { Laptop, CheckCircle2, AlertCircle, Shield } from 'lucide-react';
import { toggleDeviceTrust } from '../services/api';

export default function DeviceInventory({ devices, onDeviceUpdated }) {
  const handleToggleTrust = async (mac, currentTrust) => {
    try {
      await toggleDeviceTrust(mac, !currentTrust);
      if (onDeviceUpdated) onDeviceUpdated();
    } catch (e) {
      console.error("Failed to toggle trust", e);
    }
  };

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-emerald-950/60 border border-emerald-500/30 rounded-lg text-emerald-400">
            <Laptop className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-semibold text-sm text-slate-100">Discovered Wi-Fi Host Inventory</h3>
            <p className="text-xs text-slate-400">Active endpoints discovered via Layer 2/3 traffic monitoring</p>
          </div>
        </div>
        <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
          {devices.length} Endpoints
        </span>
      </div>

      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#0f172a] text-slate-400 uppercase tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3">IP Address</th>
              <th className="py-2.5 px-3">MAC Address</th>
              <th className="py-2.5 px-3">Vendor / Host</th>
              <th className="py-2.5 px-3">Total Packets</th>
              <th className="py-2.5 px-3">Volume</th>
              <th className="py-2.5 px-3">Last Seen</th>
              <th className="py-2.5 px-3 text-right">Trust Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-[#0d131f]">
            {devices.length === 0 ? (
              <tr>
                <td colSpan="8" className="text-center py-6 text-slate-500">
                  Scanning for active hosts...
                </td>
              </tr>
            ) : (
              devices.map((dev, idx) => {
                const isTrusted = dev.is_trusted;
                const kb = Math.round((dev.bytes_transferred || 0) / 1024);
                const lastSeenStr = dev.last_seen
                  ? new Date(dev.last_seen).toLocaleTimeString()
                  : 'Just now';

                return (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2 px-3">
                      {isTrusted ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/30">
                          <CheckCircle2 className="w-3 h-3" /> Trusted
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/30">
                          <AlertCircle className="w-3 h-3" /> Untrusted
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-cyan-300 font-semibold">{dev.ip_address}</td>
                    <td className="py-2 px-3 text-slate-400">{dev.mac_address}</td>
                    <td className="py-2 px-3 text-slate-300">{dev.vendor || 'Unknown Host'}</td>
                    <td className="py-2 px-3 text-slate-300">{(dev.packet_count || 1).toLocaleString()}</td>
                    <td className="py-2 px-3 text-slate-400">{kb} KB</td>
                    <td className="py-2 px-3 text-slate-400">{lastSeenStr}</td>
                    <td className="py-2 px-3 text-right">
                      <button
                        onClick={() => handleToggleTrust(dev.mac_address, isTrusted)}
                        className={`text-[11px] px-2.5 py-1 rounded border transition-colors ${
                          isTrusted
                            ? 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                            : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20'
                        }`}
                      >
                        {isTrusted ? 'Revoke Trust' : 'Mark Trusted'}
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
