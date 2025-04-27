from django.db import models
from django.contrib.auth.models import User

class SoftwarePackage(models.Model):
    OPERATING_SYSTEM_CHOICES = [
        ('WINDOWS', 'Windows'),
        ('MAC', 'MacOS'),
    ]
    
    version = models.CharField(max_length=50)
    operating_system = models.CharField(
        max_length=10,
        choices=OPERATING_SYSTEM_CHOICES,
        default='WINDOWS'
    )
    file = models.FileField(upload_to='software_packages/')
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Version {self.version} ({self.operating_system})"

    class Meta:
        ordering = ['-uploaded_at']
        unique_together = ['version', 'operating_system']

    def save(self, *args, **kwargs):
        # Deactivate all other packages of the same OS when a new one is uploaded
        if self.is_active:
            SoftwarePackage.objects.filter(
                operating_system=self.operating_system
            ).exclude(pk=self.pk).update(is_active=False)
        super().save(*args, **kwargs)
