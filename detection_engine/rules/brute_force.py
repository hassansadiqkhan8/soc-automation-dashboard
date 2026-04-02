"""
DETECTION RULE: Brute Force Attack
MITRE ATT&CK: T1110 - Brute Force
Tactic: Credential Access

Detects multiple failed login attempts from the same IP
within a short time window.
"""

from datetime import datetime, timedelta
from collections import defaultdict


def detect(logs):
    """
    Detect brute force attacks.
    
    Logic: If the same IP has 5+ failed logins within 
    a 5-minute window, flag it as a brute force attack.
    
    Args:
        logs: list of log dictionaries
        
    Returns:
        list of alert dictionaries
    """
    
    THRESHOLD = 5        # Number of failed attempts to trigger alert
    WINDOW_MINUTES = 5   # Time window in minutes
    
    alerts = []
    
    # Group failed login attempts by source IP
    failed_by_ip = defaultdict(list)
    
    for log in logs:
        if log.get('action') == 'LOGIN_FAILED':
            ip = log.get('source_ip')
            timestamp = log.get('timestamp')
            
            if ip and timestamp:
                # Parse timestamp string to datetime object
                if isinstance(timestamp, str):
                    try:
                        ts = datetime.fromisoformat(timestamp)
                    except ValueError:
                        continue
                else:
                    ts = timestamp
                    
                failed_by_ip[ip].append({
                    'timestamp': ts,
                    'raw_log': log.get('raw_log', '')
                })
    
    # Check each IP for brute force pattern
    for ip, attempts in failed_by_ip.items():
        # Sort by timestamp
        attempts.sort(key=lambda x: x['timestamp'])
        
        # Sliding window check
        for i in range(len(attempts)):
            window_start = attempts[i]['timestamp']
            window_end = window_start + timedelta(minutes=WINDOW_MINUTES)
            
            # Count attempts within window
            window_attempts = [
                a for a in attempts
                if window_start <= a['timestamp'] <= window_end
            ]
            
            if len(window_attempts) >= THRESHOLD:
                # Collect evidence
                evidence_logs = [a['raw_log'] for a in window_attempts[:10]]
                
                alert = {
                    'title': f'Brute Force Attack Detected from {ip}',
                    'description': (
                        f'Detected {len(window_attempts)} failed login attempts '
                        f'from IP {ip} within {WINDOW_MINUTES} minutes. '
                        f'This indicates a possible brute force attack attempting '
                        f'to guess credentials.'
                    ),
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'rule_name': 'Brute Force Detection',
                    'mitre_tactic': 'Credential Access',
                    'mitre_technique': 'T1110 - Brute Force',
                    'evidence': '\n'.join(evidence_logs),
                    'timestamp': window_start.isoformat(),
                }
                
                alerts.append(alert)
                break  # One alert per IP is enough
    
    return alerts