from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_home, name='home'),
    path('alerts/', views.alert_list, name='alert_list'),
    path('alerts/<int:alert_id>/', views.alert_detail, name='alert_detail'),
    path('alerts/<int:alert_id>/update-status/', views.update_alert_status, name='update_alert_status'),
    path('logs/', views.log_viewer, name='log_viewer'),
    path('analytics/', views.analytics, name='analytics'),
]