"""
Alert Notification System
Sends email notifications when critical/high alerts are detected.
Can be extended to support Slack, Telegram, etc.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


class EmailAlerter:
    """Send email notifications for security alerts."""
    
    def __init__(self, smtp_server, smtp_port, username, password, recipient):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipient = recipient
    
    def send_alert(self, alert):
        """Send a single alert via email."""
        
        subject = f"[{alert['severity']}] SOC Alert: {alert['title']}"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #0a0e17; color: #e2e8f0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1a2232; border-radius: 10px; padding: 25px; border: 1px solid #2d3748;">
                
                <h2 style="color: #06b6d4; margin-top: 0;">🛡️ SOC Dashboard Alert</h2>
                
                <div style="background-color: #0a0e17; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; color: #94a3b8; width: 120px;">Severity:</td>
                            <td style="padding: 8px 0;">
                                <span style="background-color: {'#ef4444' if alert['severity'] == 'CRITICAL' else '#f97316'}20; 
                                             color: {'#ef4444' if alert['severity'] == 'CRITICAL' else '#f97316'}; 
                                             padding: 3px 10px; border-radius: 20px; font-size: 12px;">
                                    {alert['severity']}
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #94a3b8;">Alert:</td>
                            <td style="padding: 8px 0; font-weight: bold;">{alert['title']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #94a3b8;">Source IP:</td>
                            <td style="padding: 8px 0; font-family: monospace; color: #ef4444;">
                                {alert.get('source_ip', 'N/A')}
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #94a3b8;">Rule:</td>
                            <td style="padding: 8px 0;">{alert['rule_name']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #94a3b8;">MITRE Technique:</td>
                            <td style="padding: 8px 0;">
                                <span style="background-color: #06b6d420; color: #06b6d4; 
                                             padding: 2px 8px; border-radius: 4px; font-family: monospace;">
                                    {alert.get('mitre_technique', 'N/A')}
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #94a3b8;">Time:</td>
                            <td style="padding: 8px 0;">{alert.get('timestamp', 'N/A')}</td>
                        </tr>
                    </table>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <h3 style="color: #94a3b8; font-size: 14px; margin-bottom: 8px;">DESCRIPTION</h3>
                    <p style="line-height: 1.6;">{alert['description']}</p>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <h3 style="color: #94a3b8; font-size: 14px; margin-bottom: 8px;">EVIDENCE</h3>
                    <div style="background-color: #0d1117; border: 1px solid #2d3748; border-radius: 6px; 
                                padding: 12px; font-family: monospace; font-size: 12px; color: #22c55e;
                                white-space: pre-wrap; word-break: break-all;">
{alert.get('evidence', 'No evidence collected')}</div>
                </div>
                
                <hr style="border: none; border-top: 1px solid #2d3748; margin: 20px 0;">
                
                <p style="color: #64748b; font-size: 12px; text-align: center;">
                    SOC Automation Dashboard — Automated Alert Notification<br>
                    Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.username
        msg['To'] = self.recipient
        
        # Plain text fallback
        plain_text = f"""
SOC DASHBOARD ALERT
====================
Severity: {alert['severity']}
Title: {alert['title']}
Source IP: {alert.get('source_ip', 'N/A')}
Rule: {alert['rule_name']}
MITRE: {alert.get('mitre_technique', 'N/A')}
Time: {alert.get('timestamp', 'N/A')}

Description:
{alert['description']}

Evidence:
{alert.get('evidence', 'No evidence collected')}
        """
        
        msg.attach(MIMEText(plain_text, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            print(f"  [✉] Email sent for: {alert['title']}")
            return True
            
        except Exception as e:
            print(f"  [✗] Email failed: {str(e)}")
            return False
    
    def send_summary(self, alerts):
        """Send a summary email of all alerts from a scan."""
        
        if not alerts:
            return
        
        critical = [a for a in alerts if a['severity'] == 'CRITICAL']
        high = [a for a in alerts if a['severity'] == 'HIGH']
        medium = [a for a in alerts if a['severity'] == 'MEDIUM']
        
        subject = f"SOC Alert Summary: {len(alerts)} alerts detected ({len(critical)} critical)"
        
        alert_rows = ""
        for alert in alerts:
            color = {
                'CRITICAL': '#ef4444',
                'HIGH': '#f97316',
                'MEDIUM': '#eab308',
                'LOW': '#22c55e'
            }.get(alert['severity'], '#3b82f6')
            
            alert_rows += f"""
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #2d3748;">
                    <span style="color: {color}; font-weight: bold;">{alert['severity']}</span>
                </td>
                <td style="padding: 8px; border-bottom: 1px solid #2d3748;">{alert['title']}</td>
                <td style="padding: 8px; border-bottom: 1px solid #2d3748; font-family: monospace; color: #06b6d4;">
                    {alert.get('source_ip', 'N/A')}
                </td>
            </tr>
            """
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #0a0e17; color: #e2e8f0; padding: 20px;">
            <div style="max-width: 700px; margin: 0 auto; background-color: #1a2232; border-radius: 10px; padding: 25px; border: 1px solid #2d3748;">
                
                <h2 style="color: #06b6d4; margin-top: 0;">🛡️ SOC Dashboard — Scan Summary</h2>
                
                <div style="display: flex; gap: 15px; margin-bottom: 20px;">
                    <div style="background: #ef444420; border: 1px solid #ef444450; border-radius: 8px; padding: 15px; text-align: center; flex: 1;">
                        <div style="font-size: 28px; font-weight: bold; color: #ef4444;">{len(critical)}</div>
                        <div style="font-size: 12px; color: #94a3b8;">CRITICAL</div>
                    </div>
                    <div style="background: #f9731620; border: 1px solid #f9731650; border-radius: 8px; padding: 15px; text-align: center; flex: 1;">
                        <div style="font-size: 28px; font-weight: bold; color: #f97316;">{len(high)}</div>
                        <div style="font-size: 12px; color: #94a3b8;">HIGH</div>
                    </div>
                    <div style="background: #eab30820; border: 1px solid #eab30850; border-radius: 8px; padding: 15px; text-align: center; flex: 1;">
                        <div style="font-size: 28px; font-weight: bold; color: #eab308;">{len(medium)}</div>
                        <div style="font-size: 12px; color: #94a3b8;">MEDIUM</div>
                    </div>
                </div>
                
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="border-bottom: 2px solid #2d3748;">
                            <th style="padding: 10px 8px; text-align: left; color: #94a3b8; font-size: 12px;">SEVERITY</th>
                            <th style="padding: 10px 8px; text-align: left; color: #94a3b8; font-size: 12px;">ALERT</th>
                            <th style="padding: 10px 8px; text-align: left; color: #94a3b8; font-size: 12px;">SOURCE IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alert_rows}
                    </tbody>
                </table>
                
                <hr style="border: none; border-top: 1px solid #2d3748; margin: 20px 0;">
                
                <p style="color: #64748b; font-size: 12px; text-align: center;">
                    SOC Automation Dashboard — Automated Summary<br>
                    Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.username
        msg['To'] = self.recipient
        msg.attach(MIMEText(html_body, 'html'))
        
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            print(f"\n  [✉] Summary email sent to {self.recipient}")
            return True
            
        except Exception as e:
            print(f"\n  [✗] Summary email failed: {str(e)}")
            return False


class ConsoleAlerter:
    """
    Fallback alerter that prints to console.
    Use this when email is not configured.
    """
    
    def send_alert(self, alert):
        print(f"\n{'='*50}")
        print(f"  🚨 ALERT NOTIFICATION")
        print(f"{'='*50}")
        print(f"  Severity:  {alert['severity']}")
        print(f"  Title:     {alert['title']}")
        print(f"  Source IP:  {alert.get('source_ip', 'N/A')}")
        print(f"  Rule:      {alert['rule_name']}")
        print(f"  MITRE:     {alert.get('mitre_technique', 'N/A')}")
        print(f"{'='*50}\n")
        return True
    
    def send_summary(self, alerts):
        print(f"\n{'='*50}")
        print(f"  📊 ALERT SUMMARY")
        print(f"{'='*50}")
        print(f"  Total:    {len(alerts)}")
        critical = len([a for a in alerts if a['severity'] == 'CRITICAL'])
        high = len([a for a in alerts if a['severity'] == 'HIGH'])
        medium = len([a for a in alerts if a['severity'] == 'MEDIUM'])
        print(f"  Critical: {critical}")
        print(f"  High:     {high}")
        print(f"  Medium:   {medium}")
        print(f"{'='*50}\n")
        return True