import React, { useState } from 'react';
import { Pause, Play, Filter, Search, Terminal, Info } from 'lucide-react';

export default function LiveTrafficTable({ packets, isPaused, setIsPaused }) {
  const [filterProto, setFilterProto] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPacket, setSelectedPacket] = useState(null);

  const filteredPackets = packets.filter(pkt => {
    if (filterProto !== 'ALL' && pkt.protocol !== filterProto) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchSrc = pkt.src_ip?.toLowerCase().includes(q);
      const matchDst = pkt.dst_ip?.toLowerCase().includes(q);
      const matchService = pkt.service?.toLowerCase().includes(q);
      if (!matchSrc && !matchDst && !matchService) return false;
    }
    return true;
  });

  const getProtoBadge = (proto) => {
    switch (proto) {
      case 'TCP':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      case 'UDP':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'ICMP':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'ARP':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      default:
        return 'bg-slate-700/50 text-slate-300 border-slate-600';
    }
  };

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-cyan-400" />
          <div>
            <h3 className="font-semibold text-sm text-slate-100">Live Traffic Dissection Stream</h3>
            <p className="text-xs text-slate-400">Real-time Layer 2–4 metadata extraction</p>
          </div>
        </div>

        {/* Filter and Pause Controls */}
        <div className="flex items-center flex-wrap gap-2 text-xs">
          {/* Search bar */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-400" />
            <input
              type="text"
              placeholder="Search IP / Service..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Protocol Filter */}
          <select
            value={filterProto}
            onChange={(e) => setFilterProto(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-slate-200 py-1 px-2.5 rounded-lg focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="ARP">ARP</option>
          </select>

          {/* Pause / Resume button */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-lg border font-medium transition-colors ${
              isPaused
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/20'
                : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>
        </div>
      </div>

      {/* Packet Table */}
      <div className="overflow-x-auto max-h-80 border border-slate-800 rounded-lg">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#0f172a] text-slate-400 uppercase tracking-wider sticky top-0 z-10 border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Proto</th>
              <th className="py-2.5 px-3">Source</th>
              <th className="py-2.5 px-3">Destination</th>
              <th className="py-2.5 px-3">Port (S/D)</th>
              <th className="py-2.5 px-3">Service</th>
              <th className="py-2.5 px-3">Size</th>
              <th className="py-2.5 px-3">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-[#0d131f]">
            {filteredPackets.length === 0 ? (
              <tr>
                <td colSpan="8" className="text-center py-8 text-slate-500">
                  Awaiting traffic packets...
                </td>
              </tr>
            ) : (
              filteredPackets.slice(0, 100).map((pkt, idx) => {
                const timeStr = pkt.timestamp
                  ? new Date(pkt.timestamp).toLocaleTimeString()
                  : '--:--:--';

                return (
                  <tr
                    key={idx}
                    onClick={() => setSelectedPacket(pkt)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{timeStr}</td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded border text-[11px] font-semibold ${getProtoBadge(pkt.protocol)}`}>
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-cyan-300 font-medium whitespace-nowrap">{pkt.src_ip}</td>
                    <td className="py-2 px-3 text-slate-300 whitespace-nowrap">{pkt.dst_ip}</td>
                    <td className="py-2 px-3 text-slate-400">
                      {pkt.src_port && pkt.dst_port ? `${pkt.src_port} → ${pkt.dst_port}` : '—'}
                    </td>
                    <td className="py-2 px-3 text-slate-300">
                      <span className="text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-200">
                        {pkt.service || '—'}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400">{pkt.packet_size} B</td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{pkt.info || '—'}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Packet Inspection Modal / Drawer */}
      {selectedPacket && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-cyan-500/30 rounded-xl max-w-xl w-full p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Info className="w-5 h-5 text-cyan-400" />
                <h4 className="font-semibold text-slate-100 text-sm">Dissected Packet Inspection</h4>
              </div>
              <button
                onClick={() => setSelectedPacket(null)}
                className="text-slate-400 hover:text-slate-100 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5">Source IP / MAC</span>
                <span className="text-cyan-300 font-semibold">{selectedPacket.src_ip}</span>
                <span className="text-slate-400 block text-[11px]">{selectedPacket.src_mac}</span>
              </div>
              <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5">Destination IP / MAC</span>
                <span className="text-slate-200 font-semibold">{selectedPacket.dst_ip}</span>
                <span className="text-slate-400 block text-[11px]">{selectedPacket.dst_mac}</span>
              </div>
              <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5">Protocol & Service</span>
                <span className="text-purple-300 font-semibold">{selectedPacket.protocol}</span>
                <span className="text-slate-400 block text-[11px]">Service: {selectedPacket.service}</span>
              </div>
              <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5">Ports & Size</span>
                <span className="text-slate-200">
                  {selectedPacket.src_port ? `${selectedPacket.src_port} → ${selectedPacket.dst_port}` : 'None'}
                </span>
                <span className="text-slate-400 block text-[11px]">{selectedPacket.packet_size} Bytes (TTL: {selectedPacket.ttl || 'N/A'})</span>
              </div>
            </div>

            {selectedPacket.tcp_flags && selectedPacket.tcp_flags.length > 0 && (
              <div className="mt-3 p-2.5 bg-slate-900 rounded-lg border border-slate-800 text-xs font-mono">
                <span className="text-slate-500 block mb-1">Active TCP Flags:</span>
                <div className="flex gap-1.5 flex-wrap">
                  {selectedPacket.tcp_flags.map((f, i) => (
                    <span key={i} className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30 text-xs">
                      {f}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setSelectedPacket(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
