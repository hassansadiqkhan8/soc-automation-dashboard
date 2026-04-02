from django.contrib import admin
from .models import LogEntry, Alert, DetectionRule

@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'source_type', 'source_ip', 'action']
    list_filter = ['source_type', 'timestamp']
    search_fields = ['source_ip', 'action', 'raw_log']


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'status', 'source_ip', 'rule_name', 'timestamp']
    list_filter = ['severity', 'status', 'rule_name']
    search_fields = ['title', 'source_ip', 'description']


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'severity', 'mitre_technique', 'is_active']
    list_filter = ['severity', 'is_active']