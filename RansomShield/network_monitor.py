"""
Network monitoring system for Ransomware Detection & Mitigation Framework.
Monitors network traffic for suspicious activities related to ransomware.
"""

import os
import threading
import time
import logging
import socket
import json
import ipaddress
from datetime import datetime
from collections import defaultdict, Counter

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Network monitoring will be limited.")

# Get logger
logger = logging.getLogger(__name__)

# Global variables
db_instance = None
alert_system = None
monitoring_active = False
monitoring_thread = None
malicious_domains_list = set()
malicious_ips_list = set()
malicious_ports = {
    20: "FTP Data", 
    21: "FTP Control",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    4899: "Radmin",
    6666: "IRC",
    8080: "HTTP Alternate"
}

# Thresholds for detection
CONNECTION_RATE_THRESHOLD = 100  # Connections per minute
DNS_QUERY_RATE_THRESHOLD = 50  # DNS queries per minute
PORT_SCAN_THRESHOLD = 15  # Different ports in quick succession
ENCRYPTION_EXTENSION_PATTERNS = [
    ".crypt", ".crypto", ".locked", ".encrypted", ".enc", ".crypted",
    ".vault", ".ryk", ".ransom", ".wcry", ".wncry", ".locky", ".zepto",
    ".cerber", ".osiris", ".aesir", ".sage", ".cryptolocker", ".cryptodef",
    ".crypz", ".cryp1", ".kimcilware", ".rokku", ".lock"
]

# Stats
stats = {
    'monitored_packets': 0,
    'suspicious_connections': 0,
    'malicious_domain_blocks': 0,
    'malicious_ip_blocks': 0,
    'ransomware_patterns_detected': 0,
    'dns_queries': 0,
}

# Connection tracking
connection_history = defaultdict(list)  # {source_ip: [(timestamp, dest_ip, dest_port), ...]}
dns_query_history = defaultdict(list)  # {source_ip: [(timestamp, domain), ...]}


def initialize(database_instance, alert_system_instance=None):
    """Initialize the network monitoring system."""
    global db_instance, alert_system, malicious_domains_list, malicious_ips_list
    
    db_instance = database_instance
    alert_system = alert_system_instance
    
    # Load malicious domains/IPs from files if available
    try:
        malicious_domains_file = os.path.join('data', 'malicious_domains.txt')
        if os.path.exists(malicious_domains_file):
            with open(malicious_domains_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        malicious_domains_list.add(line)
            logger.info(f"Loaded {len(malicious_domains_list)} malicious domains")
    except Exception as e:
        logger.error(f"Error loading malicious domains: {str(e)}")
    
    try:
        malicious_ips_file = os.path.join('data', 'malicious_ips.txt')
        if os.path.exists(malicious_ips_file):
            with open(malicious_ips_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            # Validate as IP address
                            ipaddress.ip_address(line)
                            malicious_ips_list.add(line)
                        except ValueError:
                            # Skip invalid IP addresses
                            continue
            logger.info(f"Loaded {len(malicious_ips_list)} malicious IPs")
    except Exception as e:
        logger.error(f"Error loading malicious IPs: {str(e)}")
    
    # Create data directory if it doesn't exist
    os.makedirs(os.path.join('data'), exist_ok=True)
    
    logger.info("Network monitoring system initialized")
    
    return True


def start_monitoring(user_id=None):
    """Start network traffic monitoring."""
    global monitoring_active, monitoring_thread
    
    if monitoring_active:
        logger.info("Network monitoring already active")
        return True
    
    monitoring_active = True
    
    # Start monitoring thread
    monitoring_thread = threading.Thread(target=_monitoring_worker, args=(user_id,), daemon=True)
    monitoring_thread.start()
    
    if db_instance:
        db_instance.add_log("Network monitoring started", "INFO", user_id)
    
    logger.info("Network monitoring started")
    
    return True


def stop_monitoring(user_id=None):
    """Stop network traffic monitoring."""
    global monitoring_active
    
    if not monitoring_active:
        logger.info("Network monitoring already inactive")
        return True
    
    monitoring_active = False
    
    if db_instance:
        db_instance.add_log("Network monitoring stopped", "INFO", user_id)
    
    logger.info("Network monitoring stopped")
    
    return True


def _monitoring_worker(user_id=None):
    """Worker thread for network monitoring."""
    try:
        if SCAPY_AVAILABLE:
            # Start packet capture in a separate thread
            capture_thread = threading.Thread(target=_capture_packets, daemon=True)
            capture_thread.start()
            
            # Use this thread for analysis to not block packet capture
            while monitoring_active:
                try:
                    # Analyze connections for suspicious patterns
                    _analyze_connections(user_id)
                    _analyze_dns_queries(user_id)
                    
                    # Sleep to avoid high CPU usage
                    time.sleep(10)
                except Exception as e:
                    logger.error(f"Error in connection analysis: {str(e)}")
        else:
            # Fallback to polling network connections when scapy not available
            while monitoring_active:
                try:
                    _poll_network_connections(user_id)
                    time.sleep(30)  # Poll less frequently to reduce overhead
                except Exception as e:
                    logger.error(f"Error polling network connections: {str(e)}")
    except Exception as e:
        logger.error(f"Error in network monitoring worker: {str(e)}")
        if db_instance:
            db_instance.add_log(f"Network monitoring error: {str(e)}", "ERROR", user_id)
        monitoring_active = False


def _capture_packets():
    """Capture network packets using scapy."""
    try:
        # Start packet capture
        if monitoring_active:
            # Define packet handler
            def packet_handler(packet):
                if not monitoring_active:
                    return
                
                try:
                    global stats
                    stats['monitored_packets'] += 1
                    
                    # Process IP packets
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        
                        # Check against known malicious IPs
                        if src_ip in malicious_ips_list or dst_ip in malicious_ips_list:
                            malicious_ip = src_ip if src_ip in malicious_ips_list else dst_ip
                            _handle_malicious_ip(src_ip, dst_ip, malicious_ip)
                        
                        # Track connections
                        if TCP in packet:
                            dst_port = packet[TCP].dport
                            _track_connection(src_ip, dst_ip, dst_port)
                        elif UDP in packet:
                            dst_port = packet[UDP].dport
                            _track_connection(src_ip, dst_ip, dst_port)
                        
                        # Track DNS queries
                        if DNS in packet and packet.haslayer(DNSQR):
                            domain = packet[DNSQR].qname.decode('utf-8')
                            domain = domain.rstrip('.')  # Remove trailing dot
                            _track_dns_query(src_ip, domain)
                            
                            # Check against known malicious domains
                            if domain in malicious_domains_list:
                                _handle_malicious_domain(src_ip, domain)
                except Exception as e:
                    logger.error(f"Error processing packet: {str(e)}")
            
            # Start sniffing in a non-blocking way
            sniff(prn=packet_handler, store=0, filter="ip", timeout=60)
            
            # If we reach here, sniffing has stopped, check if monitoring still active
            if monitoring_active:
                # Restart capture
                time.sleep(1)
                _capture_packets()
    except Exception as e:
        logger.error(f"Error in packet capture: {str(e)}")


def _poll_network_connections(user_id=None):
    """Fallback method to poll network connections when scapy not available."""
    try:
        # Get a list of established connections
        active_connections = []
        
        # Try to use netstat-like functionality
        try:
            import psutil
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    if conn.laddr and conn.raddr:
                        active_connections.append({
                            'src_ip': conn.laddr.ip,
                            'src_port': conn.laddr.port,
                            'dst_ip': conn.raddr.ip,
                            'dst_port': conn.raddr.port
                        })
        except (ImportError, AttributeError):
            # Fallback to socket connections
            import socket
            # This is a limited approach as it only checks for our own connections
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            
            # Check common ports on localhost
            for port in [80, 443, 445, 3389]:
                try:
                    result = s.connect_ex(('127.0.0.1', port))
                    if result == 0:  # Port is open
                        active_connections.append({
                            'src_ip': '127.0.0.1',
                            'src_port': 0,
                            'dst_ip': '127.0.0.1',
                            'dst_port': port
                        })
                except:
                    pass
            s.close()
        
        # Analyze the connections
        for conn in active_connections:
            # Track connection
            _track_connection(conn['src_ip'], conn['dst_ip'], conn['dst_port'])
            
            # Check against known malicious IPs
            if conn['dst_ip'] in malicious_ips_list:
                _handle_malicious_ip(conn['src_ip'], conn['dst_ip'], conn['dst_ip'])
    
    except Exception as e:
        logger.error(f"Error polling network connections: {str(e)}")


def _track_connection(src_ip, dst_ip, dst_port):
    """Track a network connection."""
    connection_history[src_ip].append((datetime.now(), dst_ip, dst_port))
    
    # Clean up old connections (older than 10 minutes)
    ten_minutes_ago = datetime.now() - datetime.timedelta(minutes=10)
    connection_history[src_ip] = [c for c in connection_history[src_ip] if c[0] > ten_minutes_ago]


def _track_dns_query(src_ip, domain):
    """Track a DNS query."""
    global stats
    stats['dns_queries'] += 1
    dns_query_history[src_ip].append((datetime.now(), domain))
    
    # Clean up old queries (older than 10 minutes)
    ten_minutes_ago = datetime.now() - datetime.timedelta(minutes=10)
    dns_query_history[src_ip] = [q for q in dns_query_history[src_ip] if q[0] > ten_minutes_ago]


def _analyze_connections(user_id=None):
    """Analyze connection history for suspicious patterns."""
    for src_ip, connections in connection_history.items():
        # Check connection rate
        one_minute_ago = datetime.now() - datetime.timedelta(minutes=1)
        recent_connections = [c for c in connections if c[0] > one_minute_ago]
        
        if len(recent_connections) > CONNECTION_RATE_THRESHOLD:
            _handle_high_connection_rate(src_ip, len(recent_connections), user_id)
        
        # Check for port scanning
        unique_ports = set(conn[2] for conn in recent_connections)
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            _handle_port_scanning(src_ip, unique_ports, user_id)
        
        # Check for connections to suspicious ports
        suspicious_ports_used = [port for port in unique_ports if port in malicious_ports]
        if suspicious_ports_used:
            _handle_suspicious_ports(src_ip, suspicious_ports_used, user_id)


def _analyze_dns_queries(user_id=None):
    """Analyze DNS queries for suspicious patterns."""
    for src_ip, queries in dns_query_history.items():
        # Check query rate
        one_minute_ago = datetime.now() - datetime.timedelta(minutes=1)
        recent_queries = [q for q in queries if q[0] > one_minute_ago]
        
        if len(recent_queries) > DNS_QUERY_RATE_THRESHOLD:
            _handle_high_dns_query_rate(src_ip, len(recent_queries), user_id)
        
        # Check for domain generation algorithm (DGA) patterns
        domains = [q[1] for q in recent_queries]
        if len(domains) > 10:  # Need a minimum sample size
            domain_lengths = [len(d) for d in domains]
            avg_length = sum(domain_lengths) / len(domain_lengths)
            
            # Check for random-looking domain patterns
            if avg_length > 15:  # Long average domain length
                # Count character frequencies
                all_chars = ''.join(domains)
                char_counts = Counter(all_chars)
                entropy = sum(-count/len(all_chars) * (count/len(all_chars)) for count in char_counts.values())
                
                # High entropy suggests randomness
                if entropy > 3.5:
                    _handle_dga_pattern(src_ip, domains, user_id)
        
        # Check for DNS lookups of known encryption extensions
        for query in recent_queries:
            domain = query[1]
            for ext in ENCRYPTION_EXTENSION_PATTERNS:
                if domain.endswith(ext):
                    _handle_suspicious_extension(src_ip, domain, ext, user_id)


def _handle_malicious_ip(src_ip, dst_ip, malicious_ip):
    """Handle detection of connection to/from a known malicious IP."""
    global stats
    stats['malicious_ip_blocks'] += 1
    
    logger.warning(f"Detected connection with malicious IP: {malicious_ip}")
    
    if alert_system:
        message = f"Connection detected with known malicious IP: {malicious_ip}"
        alert_system.send_alert(
            message=message,
            severity="HIGH",
            process_name="Network Monitor"
        )


def _handle_malicious_domain(src_ip, domain):
    """Handle detection of DNS query for a known malicious domain."""
    global stats
    stats['malicious_domain_blocks'] += 1
    
    logger.warning(f"Detected DNS query for malicious domain: {domain} from {src_ip}")
    
    if alert_system:
        message = f"DNS query detected for known malicious domain: {domain}"
        alert_system.send_alert(
            message=message,
            severity="HIGH",
            process_name="Network Monitor"
        )


def _handle_high_connection_rate(src_ip, connection_count, user_id=None):
    """Handle detection of unusually high connection rate."""
    global stats
    stats['suspicious_connections'] += 1
    
    logger.warning(f"High connection rate detected from {src_ip}: {connection_count} connections in the last minute")
    
    if db_instance:
        db_instance.add_log(f"High connection rate detected from {src_ip}: {connection_count} connections/min", "WARNING", user_id)
    
    if alert_system:
        message = f"Suspicious network activity: High connection rate detected from {src_ip} ({connection_count} connections/min)"
        alert_system.send_alert(
            message=message,
            severity="MEDIUM",
            process_name="Network Monitor"
        )


def _handle_port_scanning(src_ip, ports, user_id=None):
    """Handle detection of port scanning behavior."""
    global stats
    stats['suspicious_connections'] += 1
    
    port_list = ", ".join(str(p) for p in sorted(ports)[:10])
    if len(ports) > 10:
        port_list += f" and {len(ports) - 10} more"
    
    logger.warning(f"Possible port scanning from {src_ip}. Ports: {port_list}")
    
    if db_instance:
        db_instance.add_log(f"Possible port scanning from {src_ip}. Accessed {len(ports)} different ports", "WARNING", user_id)
    
    if alert_system:
        message = f"Suspicious network activity: Possible port scanning from {src_ip} ({len(ports)} different ports)"
        alert_system.send_alert(
            message=message,
            severity="MEDIUM",
            process_name="Network Monitor"
        )


def _handle_suspicious_ports(src_ip, ports, user_id=None):
    """Handle detection of connections to suspicious ports."""
    global stats
    stats['suspicious_connections'] += 1
    
    port_services = [f"{port} ({malicious_ports[port]})" for port in ports]
    port_list = ", ".join(port_services)
    
    logger.warning(f"Connection to suspicious ports from {src_ip}: {port_list}")
    
    if db_instance:
        db_instance.add_log(f"Connection to suspicious ports from {src_ip}: {port_list}", "WARNING", user_id)
    
    if alert_system:
        message = f"Suspicious network activity: Connection to potentially malicious ports from {src_ip}: {port_list}"
        alert_system.send_alert(
            message=message,
            severity="MEDIUM",
            process_name="Network Monitor"
        )


def _handle_high_dns_query_rate(src_ip, query_count, user_id=None):
    """Handle detection of unusually high DNS query rate."""
    global stats
    stats['suspicious_connections'] += 1
    
    logger.warning(f"High DNS query rate detected from {src_ip}: {query_count} queries in the last minute")
    
    if db_instance:
        db_instance.add_log(f"High DNS query rate detected from {src_ip}: {query_count} queries/min", "WARNING", user_id)
    
    if alert_system:
        message = f"Suspicious network activity: High DNS query rate from {src_ip} ({query_count} queries/min)"
        alert_system.send_alert(
            message=message,
            severity="MEDIUM",
            process_name="Network Monitor"
        )


def _handle_dga_pattern(src_ip, domains, user_id=None):
    """Handle detection of likely domain generation algorithm (DGA) pattern."""
    global stats
    stats['ransomware_patterns_detected'] += 1
    
    domain_examples = ", ".join(domains[:5])
    if len(domains) > 5:
        domain_examples += f" and {len(domains) - 5} more"
    
    logger.warning(f"Possible DGA pattern detected from {src_ip}. Sample domains: {domain_examples}")
    
    if db_instance:
        db_instance.add_log(f"Possible domain generation algorithm (DGA) detected from {src_ip}", "WARNING", user_id)
    
    if alert_system:
        message = f"Ransomware activity: Possible domain generation algorithm (DGA) detected from {src_ip}. This may indicate command and control communication."
        alert_system.send_alert(
            message=message,
            severity="HIGH",
            process_name="Network Monitor"
        )


def _handle_suspicious_extension(src_ip, domain, extension, user_id=None):
    """Handle detection of DNS query containing known ransomware extension."""
    global stats
    stats['ransomware_patterns_detected'] += 1
    
    logger.warning(f"DNS query for domain with ransomware extension detected: {domain} from {src_ip}")
    
    if db_instance:
        db_instance.add_log(f"DNS query for domain with ransomware extension ({extension}) detected from {src_ip}", "WARNING", user_id)
    
    if alert_system:
        message = f"Ransomware activity: DNS query for domain with known ransomware extension ({extension}) detected from {src_ip}"
        alert_system.send_alert(
            message=message,
            severity="HIGH",
            process_name="Network Monitor"
        )


def add_malicious_domain(domain, user_id=None):
    """Add a domain to the malicious domains list."""
    global malicious_domains_list
    
    malicious_domains_list.add(domain)
    
    # Save to file
    try:
        malicious_domains_file = os.path.join('data', 'malicious_domains.txt')
        with open(malicious_domains_file, 'a') as f:
            f.write(f"{domain}\n")
        
        logger.info(f"Added domain to malicious list: {domain}")
        
        if db_instance:
            db_instance.add_log(f"Added domain to malicious list: {domain}", "INFO", user_id)
        
        return True
    except Exception as e:
        logger.error(f"Error adding malicious domain: {str(e)}")
        return False


def add_malicious_ip(ip_address, user_id=None):
    """Add an IP address to the malicious IPs list."""
    global malicious_ips_list
    
    try:
        # Validate IP address
        ipaddress.ip_address(ip_address)
        
        malicious_ips_list.add(ip_address)
        
        # Save to file
        malicious_ips_file = os.path.join('data', 'malicious_ips.txt')
        with open(malicious_ips_file, 'a') as f:
            f.write(f"{ip_address}\n")
        
        logger.info(f"Added IP to malicious list: {ip_address}")
        
        if db_instance:
            db_instance.add_log(f"Added IP to malicious list: {ip_address}", "INFO", user_id)
        
        return True
    except ValueError:
        logger.error(f"Invalid IP address: {ip_address}")
        return False
    except Exception as e:
        logger.error(f"Error adding malicious IP: {str(e)}")
        return False


def get_monitoring_status():
    """Get the status of the network monitoring."""
    return {
        'active': monitoring_active,
        'scapy_available': SCAPY_AVAILABLE,
        'stats': stats,
        'malicious_domains_count': len(malicious_domains_list),
        'malicious_ips_count': len(malicious_ips_list)
    }


def get_network_stats():
    """Get network monitoring statistics."""
    return stats