from django.db import models

class ScanLog(models.Model):
    STATUS_CHOICES = [
        ('clean', '✅ 안전'),
        ('malicious', '🚨 악성'),
        ('suspicious', '⚠️ 의심'),
        ('unknown', '❓ 미등록'),
    ]

    session_id = models.CharField(max_length=100, blank=True, null=True)
    file_name = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    detections = models.IntegerField(default=0)
    total_engines = models.IntegerField(default=0)
    is_compressed = models.BooleanField(default=False)
    saved_path = models.CharField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # ── AI 사전 위험도 예측용 필드 (VT 응답 오기 전에 채워짐) ──
    file_size = models.IntegerField(default=0, help_text="바이트 단위")
    file_extension = models.CharField(max_length=20, blank=True, default="")
    entropy = models.FloatField(null=True, blank=True, help_text="0~8, 높을수록 암호화/난독화 의심")
    risk_score = models.FloatField(null=True, blank=True, help_text="0~100, 사전 예측 위험도")

    # ── 상세페이지(엔진별 결과)용 필드 ──
    sha256 = models.CharField(max_length=64, blank=True, default="")
    engine_results = models.JSONField(default=list, blank=True, help_text="악성/의심으로 판정한 엔진 목록")

    def __str__(self):
        return f"{self.file_name} - {self.status}"