"""
DETECTION RULE: SQL Injection Attempt
MITRE ATT&CK: T1190 - Exploit Public-Facing Application
Tactic: Initial Access

Detects SQL injection patterns in web server logs.
"""

import re


def detect(logs):
    """
    Detect SQL injection attempts in web request logs.
    
    Logic: Check if any web request contains known 
    SQL injection patterns/payloads.
    """
    
    # Common SQL injection patterns (case-insensitive)
    SQLI_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",          # Basic SQL meta-characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # Modified equals
        r"\w*((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # OR pattern
        r"((\%27)|(\'))union",                        # UNION keyword
        r"union.*select",                             # UNION SELECT
        r"select.*from",                              # SELECT FROM
        r"drop\s+table",                              # DROP TABLE
        r"insert\s+into",                             # INSERT INTO
        r"delete\s+from",                             # DELETE FROM
        r"or\s+1\s*=\s*1",                           # OR 1=1
        r"or\s+'1'\s*=\s*'1'",                       # OR '1'='1'
        r"'\s*or\s+'",                                # ' OR '
        r";\s*(drop|delete|insert|update|create)",   # Stacked queries
        r"union\s+select\s+null",                     # UNION SELECT NULL
    ]
    
    alerts = []
    detected_ips = set()  # Avoid duplicate alerts per IP
    
    for log in logs:
        if log.get('source_type') != 'webserver':
            continue
            
        action = log.get('action', '')
        raw_log = log.get('raw_log', '')
        source_ip = log.get('source_ip', '')
        
        # Check action and raw log against all patterns
        text_to_check = f"{action} {raw_log}".lower()
        
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                if source_ip not in detected_ips:
                    detected_ips.add(source_ip)
                    
                    alert = {
                        'title': f'SQL Injection Attempt from {source_ip}',
                        'description': (
                            f'Detected SQL injection payload in web request from '
                            f'IP {source_ip}. The request contained patterns '
                            f'matching known SQLi attack signatures. '
                            f'Matched pattern: {pattern}'
                        ),
                        'severity': 'CRITICAL',
                        'source_ip': source_ip,
                        'rule_name': 'SQL Injection Detection',
                        'mitre_tactic': 'Initial Access',
                        'mitre_technique': 'T1190 - Exploit Public-Facing Application',
                        'evidence': raw_log,
                        'timestamp': log.get('timestamp', ''),
                    }
                    
                    alerts.append(alert)
                break  # One pattern match is enough per log
    
    return alerts