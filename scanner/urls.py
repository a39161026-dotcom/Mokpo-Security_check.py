from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('register/', views.register, name='register'),
    path('scan/<int:pk>/', views.scan_detail, name='scan_detail'),
    path('scan/<int:pk>/report/', views.scan_report_pdf, name='scan_report_pdf'),
    path('export/', views.export_scan_logs_csv, name='export_scan_logs_csv'),
    path('clear/', views.clear_scan_logs, name='clear_scan_logs'),
]
