import json
from datetime import timedelta

from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.db.models import Count, Q
from django.http import JsonResponse

from .models import LogEntry, Alert, DetectionRule


def dashboard_home(request):
    """Main dashboard - overview of security status"""
    
    # Get alert counts by severity
    total_alerts = Alert.objects.count()
    critical_count = Alert.objects.filter(severity='CRITICAL').count()
    high_count = Alert.objects.filter(severity='HIGH').count()
    medium_count = Alert.objects.filter(severity='MEDIUM').count()
    low_count = Alert.objects.filter(severity='LOW').count()
    
    # Get alert counts by status
    new_count = Alert.objects.filter(status='NEW').count()
    investigating_count = Alert.objects.filter(status='INVESTIGATING').count()
    resolved_count = Alert.objects.filter(status='RESOLVED').count()
    
    # Get total log entries
    total_logs = LogEntry.objects.count()
    
    # Get unique attacker IPs
    attacker_ips = Alert.objects.values_list(
        'source_ip', flat=True
    ).distinct()
    unique_attackers = len([ip for ip in attacker_ips if ip])
    
    # Get recent alerts (latest 10)
    recent_alerts = Alert.objects.all()[:10]
    
    # Get alerts grouped by rule name for pie chart
    alerts_by_rule = list(
        Alert.objects.values('rule_name')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Get alerts grouped by severity for pie chart
    alerts_by_severity = list(
        Alert.objects.values('severity')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Get logs grouped by source type
    logs_by_type = list(
        LogEntry.objects.values('source_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Get top attacker IPs
    top_attackers = list(
        Alert.objects.values('source_ip')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    
    # Get MITRE ATT&CK technique breakdown
    mitre_breakdown = list(
        Alert.objects.exclude(mitre_technique='')
        .values('mitre_technique', 'mitre_tactic')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Active detection rules
    active_rules = DetectionRule.objects.filter(is_active=True)
    
    context = {
        # Summary cards
        'total_alerts': total_alerts,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'new_count': new_count,
        'investigating_count': investigating_count,
        'resolved_count': resolved_count,
        'total_logs': total_logs,
        'unique_attackers': unique_attackers,
        
        # Tables and lists
        'recent_alerts': recent_alerts,
        'top_attackers': top_attackers,
        'active_rules': active_rules,
        'mitre_breakdown': mitre_breakdown,
        
        # Chart data (convert to JSON for JavaScript)
        'alerts_by_rule_json': json.dumps(alerts_by_rule),
        'alerts_by_severity_json': json.dumps(alerts_by_severity),
        'logs_by_type_json': json.dumps(logs_by_type),
    }
    
    return render(request, 'dashboard/home.html', context)


def alert_list(request):
    """List all alerts with filtering"""
    
    # Get filter parameters from URL
    severity = request.GET.get('severity', '')
    status = request.GET.get('status', '')
    rule = request.GET.get('rule', '')
    search = request.GET.get('search', '')
    
    alerts = Alert.objects.all()
    
    # Apply filters
    if severity:
        alerts = alerts.filter(severity=severity)
    if status:
        alerts = alerts.filter(status=status)
    if rule:
        alerts = alerts.filter(rule_name=rule)
    if search:
        alerts = alerts.filter(
            Q(title__icontains=search) |
            Q(description__icontains=search) |
            Q(source_ip__icontains=search)
        )
    
    # Get unique values for filter dropdowns
    all_rules = Alert.objects.values_list(
        'rule_name', flat=True
    ).distinct()
    
    context = {
        'alerts': alerts,
        'all_rules': all_rules,
        'current_severity': severity,
        'current_status': status,
        'current_rule': rule,
        'current_search': search,
    }
    
    return render(request, 'dashboard/alert_list.html', context)


def alert_detail(request, alert_id):
    """Detailed view of a single alert"""
    
    alert = get_object_or_404(Alert, id=alert_id)
    
    # Get related alerts (same source IP or same rule)
    related_alerts = Alert.objects.filter(
        Q(source_ip=alert.source_ip) | Q(rule_name=alert.rule_name)
    ).exclude(id=alert.id)[:5]
    
    # Get related logs (same source IP)
    related_logs = []
    if alert.source_ip:
        related_logs = LogEntry.objects.filter(
            source_ip=alert.source_ip
        )[:20]
    
    context = {
        'alert': alert,
        'related_alerts': related_alerts,
        'related_logs': related_logs,
    }
    
    return render(request, 'dashboard/alert_detail.html', context)


def update_alert_status(request, alert_id):
    """Update alert status (AJAX endpoint)"""
    
    if request.method == 'POST':
        alert = get_object_or_404(Alert, id=alert_id)
        new_status = request.POST.get('status', '')
        
        if new_status in ['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE']:
            alert.status = new_status
            alert.save()
            return JsonResponse({
                'success': True,
                'new_status': new_status
            })
    
    return JsonResponse({'success': False})


def log_viewer(request):
    """View and search through raw logs"""
    
    source_type = request.GET.get('source', '')
    search = request.GET.get('search', '')
    ip_filter = request.GET.get('ip', '')
    
    logs = LogEntry.objects.all()
    
    if source_type:
        logs = logs.filter(source_type=source_type)
    if search:
        logs = logs.filter(
            Q(raw_log__icontains=search) |
            Q(action__icontains=search)
        )
    if ip_filter:
        logs = logs.filter(
            Q(source_ip__icontains=ip_filter) |
            Q(destination_ip__icontains=ip_filter)
        )
    
    # Only show latest 200 logs to keep page fast
    logs = logs[:200]
    
    context = {
        'logs': logs,
        'current_source': source_type,
        'current_search': search,
        'current_ip': ip_filter,
    }
    
    return render(request, 'dashboard/log_viewer.html', context)


def analytics(request):
    """Analytics and charts page"""
    
    # Alerts by severity
    alerts_by_severity = list(
        Alert.objects.values('severity')
        .annotate(count=Count('id'))
    )
    
    # Alerts by rule
    alerts_by_rule = list(
        Alert.objects.values('rule_name')
        .annotate(count=Count('id'))
    )
    
    # Alerts by MITRE tactic
    alerts_by_tactic = list(
        Alert.objects.exclude(mitre_tactic='')
        .values('mitre_tactic')
        .annotate(count=Count('id'))
    )
    
    # Logs by source type
    logs_by_source = list(
        LogEntry.objects.values('source_type')
        .annotate(count=Count('id'))
    )
    
    # Top 10 source IPs in logs
    top_source_ips = list(
        LogEntry.objects.values('source_ip')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    
    # Top targeted ports
    top_ports = list(
        LogEntry.objects.exclude(destination_port__isnull=True)
        .values('destination_port')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    
    context = {
        'alerts_by_severity_json': json.dumps(alerts_by_severity),
        'alerts_by_rule_json': json.dumps(alerts_by_rule),
        'alerts_by_tactic_json': json.dumps(alerts_by_tactic),
        'logs_by_source_json': json.dumps(logs_by_source),
        'top_source_ips_json': json.dumps(top_source_ips),
        'top_ports_json': json.dumps(top_ports),
    }
    
    return render(request, 'dashboard/analytics.html', context)