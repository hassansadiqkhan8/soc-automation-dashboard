"""
DETECTION RULE: Data Exfiltration Detection
MITRE ATT&CK: T1048 - Exfiltration Over Alternative Protocol
Tactic: Exfiltration

Detects unusually large outbound data transfers.
"""


def detect(logs):
    """
    Detect potential data exfiltration.
    
    Logic: Flag outbound transfers larger than 10MB 
    to external IPs.
    """
    
    SIZE_THRESHOLD = 10000000  # 10 MB in bytes
    
    INTERNAL_RANGES = ['192.168.', '10.0.', '172.16.']
    
    alerts = []
    
    for log in logs:
        bytes_sent = log.get('bytes_sent', 0)
        
        if bytes_sent and bytes_sent > SIZE_THRESHOLD:
            dest_ip = log.get('destination_ip', '')
            source_ip = log.get('source_ip', '')
            
            # Check if destination is external
            is_external = not any(
                dest_ip.startswith(prefix)
                for prefix in INTERNAL_RANGES
            )
            
            if is_external:
                mb_sent = round(bytes_sent / 1000000, 2)
                
                alert = {
                    'title': f'Possible Data Exfiltration to {dest_ip}',
                    'description': (
                        f'Large outbound data transfer detected. '
                        f'{mb_sent} MB sent from {source_ip} to '
                        f'external IP {dest_ip}. '
                        f'This could indicate data exfiltration or '
                        f'unauthorized data transfer.'
                    ),
                    'severity': 'CRITICAL',
                    'source_ip': source_ip,
                    'rule_name': 'Data Exfiltration Detection',
                    'mitre_tactic': 'Exfiltration',
                    'mitre_technique': 'T1048 - Exfiltration Over Alternative Protocol',
                    'evidence': log.get('raw_log', ''),
                    'timestamp': log.get('timestamp', ''),
                }
                
                alerts.append(alert)
    
    return alerts