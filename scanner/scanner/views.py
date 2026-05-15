"""
scanner/views.py
담당: 김성환 | 로그 조회 페이지 로직 처리
"""

from django.shortcuts import render
from .models import ScanLog

# ──────────────────────────────────────────────
# 공개 뷰 함수 (urls.py에서 연결)
# ──────────────────────────────────────────────
def log_dashboard(request):
    """
    [웹 페이지] 모든 스캔 로그를 최신순으로 화면에 전달
    """
    logs = ScanLog.objects.all()
    
    return render(request, 'scanner/dashboard.html', {'logs': logs})
