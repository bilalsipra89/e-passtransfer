from rest_framework import serializers
from django.contrib.auth.models import User
from .models import PhotoboothUser, UserTimestamp, ShopAddress
from admin_portal.models import SoftwarePackage
import hashlib
import uuid
from django.utils import timezone
import re

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
        }
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            # Check if the user has a PhotoboothUser profile and if the email is not verified
            user = User.objects.get(email=value)
            try:
                photobooth_user = PhotoboothUser.objects.get(user=user)
                if not photobooth_user.email_verified:
                    raise serializers.ValidationError({"email": "Please verify your email."})
                if photobooth_user.email_verified:
                    raise serializers.ValidationError({"email": "An account with this email already exists."})
            except PhotoboothUser.DoesNotExist:
                raise serializers.ValidationError("photobooth user does not exist")
        return value

class PhotoboothUserRegistrationSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    owner_code = serializers.CharField(max_length=8, required=False, write_only=True)
    
    class Meta:
        model = PhotoboothUser
        fields = ('user', 'phone', 'phone_2', 'salutation', 'date_of_birth', 
                 'company_name', 'legal_form', 'website', 'license_hash', 'user_type', 'owner_code')
        read_only_fields = ('license_hash',)

    def validate_user_type(self, value):
        if value in ['employee', 'manager'] and not self.initial_data.get('owner_code'):
            raise serializers.ValidationError(f"Owner code is required for {value} accounts.")
        if value == 'owner' and self.initial_data.get('owner_code'):
            raise serializers.ValidationError("Owner code is not allowed for owner accounts.")
        return value
    
    def validate_owner_code(self, value):
        if self.initial_data.get('user_type') in ['employee', 'manager'] and len(value) != 8:
            raise serializers.ValidationError("Owner code must be 8 characters long.")

        if self.initial_data.get('user_type') in ['employee', 'manager'] and not PhotoboothUser.objects.filter(owner_code=value).exists():
            raise serializers.ValidationError("Owner code doesnt match any owner")
        return value
    
    def create(self, validated_data):
        user_data = validated_data.pop('user')
        owner_code = validated_data.pop('owner_code', None)
        user_type = validated_data.get('user_type', 'owner')

        # Generate a unique license hash for owners and managers
        license_hash = None
        if user_type in ['owner', 'manager']:
            print("generating license hash")
            unique_string = f"{user_data['username']}-{uuid.uuid4()}"
            license_hash = hashlib.sha256(unique_string.encode()).hexdigest()
        
        # Find employer if this is an employee or manager
        employer = None
        if user_type in ['employee', 'manager'] and owner_code:
            try:
                employer = PhotoboothUser.objects.get(owner_code=owner_code)
            except PhotoboothUser.DoesNotExist:
                raise serializers.ValidationError({"owner_code": "Invalid owner code."})

        user = User.objects.create_user(
            username=user_data['username'],
            email=user_data['email'],
            password=user_data['password'],
            first_name=user_data.get('first_name', ''),
            last_name=user_data.get('last_name', '')
        )
        photobooth_user = PhotoboothUser.objects.create(
            user=user,
            license_hash=license_hash,
            user_type=user_type,
            employer=employer,
            **{k: v for k, v in validated_data.items() if k != 'user_type'}
        )
        
        # Generate owner_code for owners and managers   
        if user_type in ['owner', 'manager']:
            photobooth_user.generate_owner_code()
            
        return photobooth_user

class InviteEmployeeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

class InviteUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=[('employee', 'Employee'), ('manager', 'Manager')])
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

class PhotoboothUserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    software_version = serializers.CharField()
    operating_system = serializers.ChoiceField(
        choices=SoftwarePackage.OPERATING_SYSTEM_CHOICES
    )
    mac_address = serializers.CharField(max_length=17)
    #mac address is required
    extra_kwargs = {
        'mac_address': {'required': True},
        'software_version': {'required': True},
        'operating_system': {'required': True}, 
    }
    
    def validate_mac_address(self, value):
        #check if mac address is valid
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', value):
            raise serializers.ValidationError("Invalid MAC address.")
        return value
    
    def validate(self, data):
        # Get the active software package for the specified OS
        active_package = SoftwarePackage.objects.filter(
            is_active=True,
            operating_system=data['operating_system']
        ).first()
        
        if not active_package:
            raise serializers.ValidationError(
                f"No active software package found for {data['operating_system']}"
            )
        
        if data['software_version'] != active_package.version:
            raise serializers.ValidationError(
                f"Invalid software version. Current active version for {data['operating_system']} is {active_package.version}"
            )
        
        return data

class PhotoboothUserProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    email = serializers.EmailField(source='user.email', read_only=True)
    license_hash = serializers.SerializerMethodField()
    employer_details = serializers.SerializerMethodField(read_only=True)
    user_role = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = PhotoboothUser
        fields = ('first_name', 'last_name', 'email', 'phone', 'phone_2', 'salutation', 
                  'date_of_birth', 'company_name', 'legal_form', 'website', 'user_type', 
                  'license_hash', 'employer_details', 'owner_code', 'user_role', 'licensed')
        read_only_fields = ('user_type', 'owner_code', 'licensed')

    def get_license_hash(self, obj):
        # Return license hash for owners and managers
        if obj.can_have_license():
            return obj.license_hash
        return None
    
    def get_employer_details(self, obj):
        # Return employer information for employees and managers
        if obj.user_type in ['employee', 'manager'] and obj.employer:
            return {
                'owner_name': f"{obj.employer.user.first_name} {obj.employer.user.last_name}",
                'owner_email': obj.employer.user.email,
                'company_name': obj.employer.company_name
            }
        return None
    
    def get_user_role(self, obj):
        if obj.user_type == 'manager':
            return 'Manager'
        elif obj.user_type == 'employee':
            return 'Mitarbeiter'
        else:
            return 'Inhaber'

    def update(self, instance, validated_data):
        # Handle the nested user data separately
        user_data = validated_data.pop('user', {})
        user = instance.user
        
        # Update User model fields
        if 'first_name' in user_data:
            user.first_name = user_data['first_name']
        if 'last_name' in user_data:
            user.last_name = user_data['last_name']
        user.save()
        
        # Update PhotoboothUser model fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        return instance

class UserTimestampSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTimestamp
        fields = ('timestamp',)
        read_only_fields = ('timestamp',)

class LicenseVerificationSerializer(serializers.Serializer):
    license_hash = serializers.CharField()
    operating_system = serializers.ChoiceField(
        choices=SoftwarePackage.OPERATING_SYSTEM_CHOICES
    )

    def validate_license_hash(self, value):
        if not PhotoboothUser.objects.filter(license_hash=value).exists():
            raise serializers.ValidationError("Invalid license hash.")
        return value

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ShopAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShopAddress
        fields = ('id', 'name', 'address', 'shop_phone', 'zipcode', 'city', 'latitude', 'longitude', 'website', 'created_at')
        read_only_fields = ('created_at',)
        #latitude and longitude are required
        extra_kwargs = {
            'latitude': {'required': True},
            'longitude': {'required': True},
            'website': {'required': False},
        }
    
    def validate_latitude(self, value):
        if not (-90 <= value <= 90):
            raise serializers.ValidationError("Latitude must be between -90 and 90.")
        return value
    
    def validate_longitude(self, value):    
        if not (-180 <= value <= 180):
            raise serializers.ValidationError("Longitude must be between -180 and 180.")
        return value

class UsernameCheckSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    
    def validate_username(self, value):
        # Check if the username already exists
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        return value 

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Check if a user with this email exists
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user is registered with this email address.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    reset_code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(min_length=8, write_only=True)
    
    def validate(self, data):
        email = data.get('email')
        reset_code = data.get('reset_code')
        
        try:
            user = User.objects.get(email=email)
            photobooth_user = PhotoboothUser.objects.get(user=user)
            
            # Check if reset code is valid and not expired
            if not photobooth_user.email_otp or photobooth_user.email_otp != reset_code:
                raise serializers.ValidationError({"reset_code": "Invalid reset code."})
            
            if not photobooth_user.otp_expiry or photobooth_user.otp_expiry < timezone.now():
                raise serializers.ValidationError({"reset_code": "Reset code has expired."})
                
        except (User.DoesNotExist, PhotoboothUser.DoesNotExist):
            raise serializers.ValidationError({"email": "User not found."})
            
        return data 

class LocationQuerySerializer(serializers.Serializer):
    latitude = serializers.FloatField(
        required=True,
        min_value=-90.0,
        max_value=90.0,
        error_messages={
            'min_value': 'Latitude must be between -90 and 90 degrees.',
            'max_value': 'Latitude must be between -90 and 90 degrees.',
        }
    )
    longitude = serializers.FloatField(
        required=True,
        min_value=-180.0,
        max_value=180.0,
        error_messages={
            'min_value': 'Longitude must be between -180 and 180 degrees.',
            'max_value': 'Longitude must be between -180 and 180 degrees.',
        }
    )
    radius = serializers.FloatField(
        default=5.0,
        min_value=0.0,
        error_messages={
            'min_value': 'Radius must be a positive number.',
        }
    ) 

class MacOTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)
    mac_address = serializers.CharField(max_length=17)
    
    def validate(self, data):
        email = data.get('email')
        otp = data.get('otp')
        
        try:
            user = User.objects.get(email=email)
            photobooth_user = PhotoboothUser.objects.get(user=user)
            
            # Check if OTP is valid and not expired
            if not photobooth_user.email_otp or photobooth_user.email_otp != otp:
                raise serializers.ValidationError({"otp": "Invalid OTP."})
            
            if not photobooth_user.otp_expiry or photobooth_user.otp_expiry < timezone.now():
                raise serializers.ValidationError({"otp": "OTP has expired."})
                
        except (User.DoesNotExist, PhotoboothUser.DoesNotExist):
            raise serializers.ValidationError({"email": "User not found."})
            
        return data 

class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate_current_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value
    
    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value
        
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class DownloadURLSerializer(serializers.Serializer):
    operating_system = serializers.ChoiceField(
        choices=SoftwarePackage.OPERATING_SYSTEM_CHOICES
    )

class WebLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        email = data.get('email')
        
        # Find the user by email
        try:
            user = User.objects.get(email=email)
            # Validate that the user has a PhotoboothUser profile
            try:
                photobooth_user = PhotoboothUser.objects.get(user=user)
                # Check if email is verified
                if not photobooth_user.email_verified:
                    raise serializers.ValidationError({"email": "Please verify your email before logging in."})
            except PhotoboothUser.DoesNotExist:
                raise serializers.ValidationError({"email": "User is not registered as a photobooth user."})
        except User.DoesNotExist:
            # Don't reveal if the email exists for security reasons
            pass
            
        return data 