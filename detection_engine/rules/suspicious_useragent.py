"""
DETECTION RULE: Suspicious User Agent Detection
MITRE ATT&CK: T1595 - Active Scanning
Tactic: Reconnaissance

Detects requests from known malicious/scanning tools.
"""


def detect(logs):
    """
    Detect suspicious user agents in web logs.
    
    Logic: Check if User-Agent string matches known 
    security scanning tools.
    """
    
    SUSPICIOUS_AGENTS = [
        'sqlmap',
        'nikto',
        'dirbuster',
        'nmap',
        'masscan',
        'gobuster',
        'burpsuite',
        'hydra',
        'metasploit',
        'wpscan',
        'acunetix',
        'nessus',
        'openvas',
    ]
    
    alerts = []
    detected_agents = set()
    
    for log in logs:
        action = log.get('action', '').lower()
        raw_log = log.get('raw_log', '').lower()
        
        text_to_check = f"{action} {raw_log}"
        
        for agent in SUSPICIOUS_AGENTS:
            if agent in text_to_check and agent not in detected_agents:
                detected_agents.add(agent)
                
                alert = {
                    'title': f'Suspicious Tool Detected: {agent.upper()}',
                    'description': (
                        f'A request was detected using the security scanning '
                        f'tool "{agent}". This tool is commonly used for '
                        f'reconnaissance and vulnerability scanning. '
                        f'Source IP: {log.get("source_ip", "Unknown")}'
                    ),
                    'severity': 'MEDIUM',
                    'source_ip': log.get('source_ip', ''),
                    'rule_name': 'Suspicious User Agent Detection',
                    'mitre_tactic': 'Reconnaissance',
                    'mitre_technique': 'T1595 - Active Scanning',
                    'evidence': log.get('raw_log', ''),
                    'timestamp': log.get('timestamp', ''),
                }
                
                alerts.append(alert)
    
    return alerts