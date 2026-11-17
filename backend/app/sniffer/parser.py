from datetime import datetime, timezone
from typing import Dict, Any, Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS

COMMON_SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    123: "NTP",
    67: "DHCP-Server",
    68: "DHCP-Client",
    1883: "MQTT",
    8080: "HTTP-Proxy",
    3306: "MySQL",
    27017: "MongoDB"
}

def extract_tcp_flags(flags_val) -> list[str]:
    """Parse Scapy TCP flags into list of flag names."""
    flag_names = []
    # Flags: F=FIN, S=SYN, R=RST, P=PSH, A=ACK, U=URG, E=ECE, C=CWR
    flags_str = str(flags_val)
    if "S" in flags_str:
        flag_names.append("SYN")
    if "A" in flags_str:
        flag_names.append("ACK")
    if "F" in flags_str:
        flag_names.append("FIN")
    if "R" in flags_str:
        flag_names.append("RST")
    if "P" in flags_str:
        flag_names.append("PSH")
    if "U" in flags_str:
        flag_names.append("URG")
    return flag_names

def parse_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Dissect a raw Scapy packet into defensive network metadata.
    Extracts Layer 2, Layer 3, and Layer 4 header fields.
    """
    try:
        timestamp = datetime.now(timezone.utc)
        packet_size = len(packet)
        
        src_mac = packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "00:00:00:00:00:00"
        
        # Handle ARP (Layer 2.5)
        if packet.haslayer(ARP):
            arp = packet[ARP]
            return {
                "timestamp": timestamp,
                "src_ip": arp.psrc,
                "dst_ip": arp.pdst,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "protocol": "ARP",
                "src_port": None,
                "dst_port": None,
                "packet_size": packet_size,
                "tcp_flags": [],
                "service": "ARP",
                "ttl": None,
                "info": f"ARP {'Request' if arp.op == 1 else 'Reply'}"
            }
        
        # Handle IPv4 (Layer 3)
        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.ttl
            protocol_name = "IP"
            src_port = None
            dst_port = None
            tcp_flags = []
            service = "Unknown"
            info = ""

            if packet.haslayer(TCP):
                protocol_name = "TCP"
                tcp = packet[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                tcp_flags = extract_tcp_flags(tcp.flags)
                service = COMMON_SERVICES.get(dst_port) or COMMON_SERVICES.get(src_port) or "TCP"
                info = f"Flags: [{', '.join(tcp_flags)}] Seq={tcp.seq}"
                
            elif packet.haslayer(UDP):
                protocol_name = "UDP"
                udp = packet[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
                service = COMMON_SERVICES.get(dst_port) or COMMON_SERVICES.get(src_port) or "UDP"
                
                if packet.haslayer(DNS):
                    service = "DNS"
                    dns = packet[DNS]
                    info = "DNS Query" if dns.qr == 0 else "DNS Response"
                else:
                    info = f"Len={udp.len}"
                    
            elif packet.haslayer(ICMP):
                protocol_name = "ICMP"
                icmp = packet[ICMP]
                service = "ICMP"
                info = f"Type={icmp.type} Code={icmp.code}"
            else:
                protocol_name = f"Proto-{ip.proto}"
                
            return {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "protocol": protocol_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_size": packet_size,
                "tcp_flags": tcp_flags,
                "service": service,
                "ttl": ttl,
                "info": info
            }
            
        return None
    except Exception:
        return None
