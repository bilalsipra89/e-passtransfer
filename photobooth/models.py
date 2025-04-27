from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import random
import string
import hashlib
import uuid


class PhotoboothUser(models.Model):
    SALUTATION_CHOICES = [              #Mr, Mrs
        ('Herr', 'Herr'),
        ('Frau', 'Frau'),
        ('Divers', 'Divers'),
        ('Keine Anrede', 'Keine Anrede'),
    ]
    
    USER_TYPE_CHOICES = [
        ('owner', 'Owner'),
        ('manager', 'Manager'),
        ('employee', 'Employee'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20)
    phone_2 = models.CharField(max_length=20, blank=True, null=True)
    salutation = models.CharField(max_length=12, choices=SALUTATION_CHOICES, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    legal_form = models.CharField(max_length=100, blank=True, null=True)
    website = models.CharField(max_length=255, blank=True, null=True)
    license_hash = models.CharField(max_length=255, unique=True, null=True, blank=True)
    email_verified = models.BooleanField(default=False)
    email_otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='owner')
    employer = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='employees')
    owner_code = models.CharField(max_length=8, unique=True, null=True, blank=True)
    mac_address = models.CharField(max_length=17, blank=True, null=True)
    licensed = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username

    def is_manager(self):
        return self.user_type == 'manager'
        
    def is_owner(self):
        return self.user_type == 'owner'
        
    def can_invite_employees(self):
        return self.user_type in ['owner', 'manager']
        
    def can_have_license(self):
        return self.user_type in ['owner', 'manager']

    def generate_otp(self):
        # Generate 6 digit OTP
        otp = ''.join(random.choices(string.digits, k=6))
        self.email_otp = otp
        # Set OTP expiry to 10 minutes from now
        self.otp_expiry = timezone.now() + timezone.timedelta(minutes=2)
        self.save()
        return otp

    def generate_owner_code(self):
        # Generate 8 character alphanumeric owner code
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        self.owner_code = code
        self.save()
        return code

    def generate_license_hash(self):
        # Generate 256 character license hash
        license_hash = hashlib.sha256(f"{self.user.username}-{uuid.uuid4()}".encode()).hexdigest()
        self.license_hash = license_hash
        self.save()
        return license_hash


class UserTimestamp(models.Model):
    user = models.ForeignKey(PhotoboothUser, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(default=timezone.now)
    software_version = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.user.user.username} - {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']

class ShopAddress(models.Model):
    photobooth_user = models.ForeignKey(PhotoboothUser, on_delete=models.CASCADE, related_name='addresses')
    name = models.CharField(max_length=255)
    address = models.TextField()
    shop_phone = models.CharField(max_length=20, blank=True, null=True)
    zipcode = models.CharField(max_length=10)
    city = models.CharField(max_length=100)
    latitude = models.DecimalField(max_digits=10, decimal_places=8, blank=False, null=False, default=0.0)
    longitude = models.DecimalField(max_digits=10, decimal_places=8, blank=False, null=False, default=0.0)
    website = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.city}"

    class Meta:
        verbose_name_plural = "Shop Addresses"
