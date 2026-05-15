"""
scanner/models.py
담당: 김성환 | 스캔 기록 DB 저장 모델 정의
"""

from django.db import models

# ──────────────────────────────────────────────
# 모델 정의
# ──────────────────────────────────────────────
class ScanLog(models.Model):
    """
    [DB 모델] 보안 검사 및 파일 이동 결과 기록
    """
    # 1. 파일 정보
    file_name = models.CharField(max_length=255, verbose_name="파일명")
    file_hash = models.CharField(max_length=64, verbose_name="SHA-256 해시")
    
    # 2. 보안 검사 결과 (성헌 파트 연동)
    status_choices = [
        ('clean', '✅ 안전'),
        ('suspicious', '⚠️ 의심'),
        ('malicious', '🚨 악성'),
        ('error', '❌ 오류'),
    ]
    status = models.CharField(
        max_length=20, 
        choices=status_choices, 
        default='clean',
        verbose_name="보안 상태"
    )
    detections = models.IntegerField(default=0, verbose_name="탐지 수")
    total_engines = models.IntegerField(default=0, verbose_name="전체 엔진 수")

    # 3. 처리 결과 (지민 파트 연동)
    is_compressed = models.BooleanField(default=False, verbose_name="압축 여부")
    saved_path = models.CharField(max_length=512, verbose_name="최종 저장 경로")
    
    # 4. 시간 기록
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="스캔 일시")

    class Meta:
        ordering = ['-created_at'] # 최신순 정렬
        verbose_name = "스캔 기록"
        verbose_name_plural = "스캔 기록 목록"

    def __str__(self):
        return f"[{self.status}] {self.file_name}"
