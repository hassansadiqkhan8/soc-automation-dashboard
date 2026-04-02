"""
Main Detection Engine
Loads all rules and runs them against log data.
"""

import json
import os
from datetime import datetime

from detection_engine.rules import (
    brute_force,
    sqli_detection,
    port_scan,
    exfiltration,
    suspicious_useragent,
)


class DetectionEngine:
    """
    Core detection engine that runs all security rules
    against ingested log data.
    """
    
    def __init__(self):
        # Register all detection rules
        self.rules = [
            {
                'name': 'Brute Force Detection',
                'module': brute_force,
                'description': 'Detects multiple failed login attempts',
            },
            {
                'name': 'SQL Injection Detection',
                'module': sqli_detection,
                'description': 'Detects SQL injection patterns in web requests',
            },
            {
                'name': 'Port Scan Detection',
                'module': port_scan,
                'description': 'Detects network port scanning activity',
            },
            {
                'name': 'Data Exfiltration Detection',
                'module': exfiltration,
                'description': 'Detects large unusual outbound data transfers',
            },
            {
                'name': 'Suspicious User Agent',
                'module': suspicious_useragent,
                'description': 'Detects known malicious scanning tools',
            },
        ]
    
    def load_logs(self, filepath):
        """Load logs from a JSON file."""
        with open(filepath, 'r') as f:
            logs = json.load(f)
        print(f"[+] Loaded {len(logs)} log entries from {filepath}")
        return logs
    
    def run_all_rules(self, logs):
        """Run all detection rules against the logs."""
        all_alerts = []
        
        print("\n" + "=" * 50)
        print("  RUNNING DETECTION ENGINE")
        print("=" * 50)
        
        for rule in self.rules:
            rule_name = rule['name']
            module = rule['module']
            
            print(f"\n[*] Running: {rule_name}...")
            
            try:
                alerts = module.detect(logs)
                
                if alerts:
                    print(f"  [!] FOUND {len(alerts)} alert(s)!")
                    for alert in alerts:
                        print(f"      → [{alert['severity']}] {alert['title']}")
                else:
                    print(f"  [✓] No threats detected")
                
                all_alerts.extend(alerts)
                
            except Exception as e:
                print(f"  [ERROR] Rule failed: {str(e)}")
        
        print("\n" + "=" * 50)
        print(f"  SCAN COMPLETE: {len(all_alerts)} total alerts")
        print("=" * 50)
        
        return all_alerts
    
    def get_summary(self, alerts):
        """Generate a summary of all alerts."""
        summary = {
            'total_alerts': len(alerts),
            'by_severity': {},
            'by_rule': {},
            'by_mitre': {},
            'unique_attackers': set(),
        }
        
        for alert in alerts:
            # Count by severity
            sev = alert['severity']
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1
            
            # Count by rule
            rule = alert['rule_name']
            summary['by_rule'][rule] = summary['by_rule'].get(rule, 0) + 1
            
            # Count by MITRE technique
            technique = alert.get('mitre_technique', 'Unknown')
            summary['by_mitre'][technique] = summary['by_mitre'].get(technique, 0) + 1
            
            # Track unique attacker IPs
            if alert.get('source_ip'):
                summary['unique_attackers'].add(alert['source_ip'])
        
        summary['unique_attackers'] = list(summary['unique_attackers'])
        
        return summary


# Quick test - run this file directly
if __name__ == '__main__':
    engine = DetectionEngine()
    
    # Load sample logs
    log_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'sample_logs',
        'security_logs.json'
    )
    
    logs = engine.load_logs(log_file)
    alerts = engine.run_all_rules(logs)
    summary = engine.get_summary(alerts)
    
    print("\n\n📊 SUMMARY:")
    print(f"Total Alerts: {summary['total_alerts']}")
    print(f"\nBy Severity:")
    for sev, count in summary['by_severity'].items():
        print(f"  {sev}: {count}")
    print(f"\nBy Rule:")
    for rule, count in summary['by_rule'].items():
        print(f"  {rule}: {count}")
    print(f"\nUnique Attacker IPs: {summary['unique_attackers']}")