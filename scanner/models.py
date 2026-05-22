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

    def __str__(self):
        return f"{self.file_name} - {self.status}"