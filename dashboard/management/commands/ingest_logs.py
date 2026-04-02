"""
Django management command to ingest logs, run detection engine, 
and send alert notifications.

Usage: python manage.py ingest_logs
       python manage.py ingest_logs --notify
"""

import json
import os
from django.core.management.base import BaseCommand
from django.conf import settings
from dashboard.models import LogEntry, Alert, DetectionRule
from detection_engine.engine import DetectionEngine
from detection_engine.alerter import EmailAlerter, ConsoleAlerter


class Command(BaseCommand):
    help = 'Ingest sample logs, run detection engine, and optionally send notifications'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--notify',
            action='store_true',
            help='Send alert notifications (email if configured, otherwise console)',
        )
    
    def handle(self, *args, **options):
        self.stdout.write("\n🔄 Starting log ingestion...\n")
        
        # Clear old data
        LogEntry.objects.all().delete()
        Alert.objects.all().delete()
        self.stdout.write("  Cleared old data")
        
        # Load logs from JSON file
        log_file = os.path.join(
            settings.BASE_DIR, 'sample_logs', 'security_logs.json'
        )
        
        with open(log_file, 'r') as f:
            logs = json.load(f)
        
        self.stdout.write(f"  Loaded {len(logs)} log entries")
        
        # Save logs to database
        log_objects = []
        for log in logs:
            log_objects.append(LogEntry(
                timestamp=log.get('timestamp'),
                source_type=log.get('source_type', 'custom'),
                source_ip=log.get('source_ip'),
                destination_ip=log.get('destination_ip'),
                destination_port=log.get('destination_port'),
                action=log.get('action', ''),
                raw_log=log.get('raw_log', ''),
            ))
        
        LogEntry.objects.bulk_create(log_objects)
        self.stdout.write(f"  ✅ Saved {len(log_objects)} logs to database")
        
        # Run detection engine
        engine = DetectionEngine()
        alerts = engine.run_all_rules(logs)
        
        # Save alerts to database
        alert_objects = []
        for alert in alerts:
            alert_objects.append(Alert(
                title=alert['title'],
                description=alert['description'],
                severity=alert['severity'],
                source_ip=alert.get('source_ip'),
                rule_name=alert['rule_name'],
                mitre_tactic=alert.get('mitre_tactic', ''),
                mitre_technique=alert.get('mitre_technique', ''),
                evidence=alert.get('evidence', ''),
                timestamp=alert.get('timestamp'),
            ))
        
        Alert.objects.bulk_create(alert_objects)
        self.stdout.write(
            self.style.SUCCESS(
                f"\n  ✅ Generated {len(alert_objects)} security alerts!"
            )
        )
        
        # Create/update detection rules in database
        DetectionRule.objects.all().delete()
        for rule in engine.rules:
            DetectionRule.objects.create(
                name=rule['name'],
                description=rule['description'],
                severity='HIGH',
                is_active=True,
            )
        
        # Send notifications if --notify flag is used
        if options['notify']:
            self.stdout.write("\n📧 Sending notifications...")
            
            # Check if email is configured
            email_enabled = getattr(settings, 'ENABLE_EMAIL_ALERTS', False)
            email_severities = getattr(
                settings, 'ALERT_EMAIL_SEVERITIES', ['CRITICAL', 'HIGH']
            )
            
            if email_enabled:
                config = settings.SOC_EMAIL_CONFIG
                alerter = EmailAlerter(
                    smtp_server=config['SMTP_SERVER'],
                    smtp_port=config['SMTP_PORT'],
                    username=config['USERNAME'],
                    password=config['PASSWORD'],
                    recipient=config['RECIPIENT'],
                )
            else:
                self.stdout.write(
                    "  Email not configured. Using console notifications."
                )
                self.stdout.write(
                    "  (Set ENABLE_EMAIL_ALERTS=True in settings.py to enable email)\n"
                )
                alerter = ConsoleAlerter()
            
            # Send individual alerts for critical/high
            important_alerts = [
                a for a in alerts if a['severity'] in email_severities
            ]
            
            for alert in important_alerts:
                alerter.send_alert(alert)
            
            # Send summary
            alerter.send_summary(alerts)
        
        self.stdout.write(
            self.style.SUCCESS("\n🎉 Ingestion complete!\n")
        )