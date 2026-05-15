from django.db import models

class ScanLog(models.Model):
    filename = models.CharField(max_length=255)
    status = models.CharField(max_length=50)
    detections = models.IntegerField(default=0)
    total = models.IntegerField(default=0)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.filename} - {self.status}"