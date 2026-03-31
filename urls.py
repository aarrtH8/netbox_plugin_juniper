from django.urls import path
from . import views


app_name = 'plugin_juniper'

urlpatterns = [
    path('', views.FirewallListView.as_view(), name='firewall_list'),
    path('scan/<int:device_id>/', views.FirewallScanView.as_view(), name='firewall_scan'),
    path('push/<int:device_id>/', views.FirewallPushView.as_view(), name='firewall_push'),
]