"""
DETECTION RULE: Port Scan Detection
MITRE ATT&CK: T1046 - Network Service Scanning
Tactic: Discovery

Detects when a single IP attempts connections to many 
different ports in a short time period.
"""

from datetime import datetime, timedelta
from collections import defaultdict


def detect(logs):
    """
    Detect port scanning activity.
    
    Logic: If one IP hits 10+ different ports within 
    60 seconds, flag as port scan.
    """
    
    PORT_THRESHOLD = 10   # Minimum different ports to trigger
    WINDOW_SECONDS = 60   # Time window
    
    alerts = []
    
    # Group connection attempts by source IP
    connections_by_ip = defaultdict(list)
    
    for log in logs:
        if log.get('action') in ['CONNECTION_ATTEMPT', 'BLOCKED', 'DROP']:
            ip = log.get('source_ip')
            port = log.get('destination_port')
            timestamp = log.get('timestamp')
            
            if ip and port and timestamp:
                if isinstance(timestamp, str):
                    try:
                        ts = datetime.fromisoformat(timestamp)
                    except ValueError:
                        continue
                else:
                    ts = timestamp
                    
                connections_by_ip[ip].append({
                    'timestamp': ts,
                    'port': port,
                    'raw_log': log.get('raw_log', '')
                })
    
    # Check each IP for port scan pattern
    for ip, connections in connections_by_ip.items():
        connections.sort(key=lambda x: x['timestamp'])
        
        for i in range(len(connections)):
            window_start = connections[i]['timestamp']
            window_end = window_start + timedelta(seconds=WINDOW_SECONDS)
            
            # Get connections within window
            window_conns = [
                c for c in connections
                if window_start <= c['timestamp'] <= window_end
            ]
            
            # Count unique ports
            unique_ports = set(c['port'] for c in window_conns)
            
            if len(unique_ports) >= PORT_THRESHOLD:
                ports_list = sorted(unique_ports)
                evidence_logs = [c['raw_log'] for c in window_conns[:15]]
                
                alert = {
                    'title': f'Port Scan Detected from {ip}',
                    'description': (
                        f'IP {ip} attempted connections to {len(unique_ports)} '
                        f'different ports within {WINDOW_SECONDS} seconds. '
                        f'Scanned ports include: {ports_list[:15]}. '
                        f'This behavior is consistent with network reconnaissance.'
                    ),
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'rule_name': 'Port Scan Detection',
                    'mitre_tactic': 'Discovery',
                    'mitre_technique': 'T1046 - Network Service Scanning',
                    'evidence': '\n'.join(evidence_logs),
                    'timestamp': window_start.isoformat(),
                }
                
                alerts.append(alert)
                break
    
    return alerts