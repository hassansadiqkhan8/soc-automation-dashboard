"""
Generate realistic sample security logs for testing
our detection engine.
"""

import json
import random
from datetime import datetime, timedelta


def generate_logs():
    logs = []
    
    base_time = datetime.now() - timedelta(hours=24)
    
    # Normal IPs (legitimate users)
    normal_ips = [
        '192.168.1.10', '192.168.1.15', '192.168.1.20',
        '192.168.1.25', '10.0.0.5', '10.0.0.12',
    ]
    
    # Attacker IPs
    attacker_ips = [
        '45.33.32.156', '185.220.101.44', '23.129.64.100',
    ]
    
    # ============================================
    # 1. NORMAL WEB TRAFFIC (legitimate requests)
    # ============================================
    normal_pages = [
        '/index.html', '/about', '/contact', '/products',
        '/login', '/dashboard', '/api/users', '/images/logo.png',
    ]
    
    for i in range(200):
        timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
        ip = random.choice(normal_ips)
        page = random.choice(normal_pages)
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'source_type': 'webserver',
            'source_ip': ip,
            'destination_ip': '192.168.1.100',
            'destination_port': 80,
            'action': f'GET {page}',
            'status_code': 200,
            'raw_log': f'{ip} - - [{timestamp}] "GET {page} HTTP/1.1" 200 1234'
        })
    
    # ============================================
    # 2. BRUTE FORCE ATTACK (many failed logins)
    # ============================================
    attacker_ip = '45.33.32.156'
    brute_force_start = base_time + timedelta(hours=3)
    
    # 25 failed login attempts in 5 minutes from same IP
    for i in range(25):
        timestamp = brute_force_start + timedelta(seconds=random.randint(0, 300))
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'source_type': 'ssh',
            'source_ip': attacker_ip,
            'destination_ip': '192.168.1.100',
            'destination_port': 22,
            'action': 'LOGIN_FAILED',
            'status_code': 401,
            'raw_log': f'{timestamp} sshd[1234]: Failed password for admin from {attacker_ip} port 22 ssh2'
        })
    
    # Attacker eventually succeeds (suspicious!)
    logs.append({
        'timestamp': (brute_force_start + timedelta(minutes=6)).isoformat(),
        'source_type': 'ssh',
        'source_ip': attacker_ip,
        'destination_ip': '192.168.1.100',
        'destination_port': 22,
        'action': 'LOGIN_SUCCESS',
        'status_code': 200,
        'raw_log': f'{brute_force_start} sshd[1234]: Accepted password for admin from {attacker_ip} port 22 ssh2'
    })
    
    # Normal successful logins for comparison
    for i in range(10):
        timestamp = base_time + timedelta(hours=random.randint(0, 24))
        ip = random.choice(normal_ips)
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'source_type': 'ssh',
            'source_ip': ip,
            'destination_ip': '192.168.1.100',
            'destination_port': 22,
            'action': 'LOGIN_SUCCESS',
            'status_code': 200,
            'raw_log': f'{timestamp} sshd[5678]: Accepted password for user from {ip} port 22 ssh2'
        })
    
    # ============================================
    # 3. SQL INJECTION ATTEMPTS
    # ============================================
    sqli_payloads = [
        "GET /products?id=1' OR '1'='1",
        "GET /login?user=admin'--",
        "GET /search?q=' UNION SELECT username,password FROM users--",
        "GET /products?id=1; DROP TABLE users--",
        "POST /login username=admin' OR 1=1--&password=anything",
        "GET /api/users?id=1' UNION SELECT NULL,NULL,NULL--",
    ]
    
    sqli_attacker = '185.220.101.44'
    sqli_start = base_time + timedelta(hours=8)
    
    for i, payload in enumerate(sqli_payloads):
        timestamp = sqli_start + timedelta(minutes=i * 2)
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'source_type': 'webserver',
            'source_ip': sqli_attacker,
            'destination_ip': '192.168.1.100',
            'destination_port': 80,
            'action': payload,
            'status_code': 500,
            'raw_log': f'{sqli_attacker} - - [{timestamp}] "{payload} HTTP/1.1" 500 0'
        })
    
    # ============================================
    # 4. PORT SCAN (hitting many ports quickly)
    # ============================================
    scanner_ip = '23.129.64.100'
    scan_start = base_time + timedelta(hours=14)
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1723, 3306, 3389,
        5432, 5900, 8080, 8443, 8888, 9090, 27017,
    ]
    
    for port in common_ports:
        timestamp = scan_start + timedelta(seconds=random.randint(0, 30))
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'source_type': 'firewall',
            'source_ip': scanner_ip,
            'destination_ip': '192.168.1.100',
            'destination_port': port,
            'action': 'CONNECTION_ATTEMPT',
            'status_code': 0,
            'raw_log': f'{timestamp} FIREWALL: SRC={scanner_ip} DST=192.168.1.100 PROTO=TCP DPT={port} ACTION=DROP'
        })
    
    # ============================================
    # 5. SUSPICIOUS USER AGENT (scanning tools)
    # ============================================
    sus_agents = [
        'sqlmap/1.5 (http://sqlmap.org)',
        'nikto/2.1.6',
        'dirbuster/1.0',
        'Nmap Scripting Engine',
    ]
    
    for agent in sus_agents:
        timestamp = base_time + timedelta(hours=random.randint(5, 20))
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'source_type': 'webserver',
            'source_ip': sqli_attacker,
            'destination_ip': '192.168.1.100',
            'destination_port': 80,
            'action': f'GET / [User-Agent: {agent}]',
            'status_code': 200,
            'raw_log': f'{sqli_attacker} - - [{timestamp}] "GET / HTTP/1.1" 200 1234 "-" "{agent}"'
        })
    
    # ============================================
    # 6. DATA EXFILTRATION (large outbound transfer)
    # ============================================
    exfil_start = base_time + timedelta(hours=18)
    
    # Normal traffic has small response sizes
    # Exfiltration has huge response sizes
    for i in range(5):
        timestamp = exfil_start + timedelta(minutes=i * 5)
        
        logs.append({
            'timestamp': timestamp.isoformat(),
            'source_type': 'firewall',
            'source_ip': '192.168.1.100',  # Internal server sending data OUT
            'destination_ip': '103.45.67.89',  # External unknown IP
            'destination_port': 443,
            'action': 'LARGE_OUTBOUND_TRANSFER',
            'bytes_sent': random.randint(50000000, 100000000),  # 50-100 MB
            'raw_log': f'{timestamp} FIREWALL: SRC=192.168.1.100 DST=103.45.67.89 PROTO=TCP DPT=443 BYTES={random.randint(50000000, 100000000)}'
        })
    
    # Sort all logs by timestamp
    logs.sort(key=lambda x: x['timestamp'])
    
    return logs


if __name__ == '__main__':
    logs = generate_logs()
    
    # Save to JSON file
    with open('sample_logs/security_logs.json', 'w') as f:
        json.dump(logs, f, indent=2)
    
    print(f"Generated {len(logs)} log entries")
    print(f"Saved to sample_logs/security_logs.json")
    
    # Print summary
    from collections import Counter
    types = Counter(log['source_type'] for log in logs)
    print(f"\nLog breakdown:")
    for log_type, count in types.items():
        print(f"  {log_type}: {count}")