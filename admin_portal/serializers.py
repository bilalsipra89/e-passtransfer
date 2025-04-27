from rest_framework import serializers
from django.contrib.auth.models import User
from .models import SoftwarePackage
from packaging import version as pkg_version
import re

class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'password', 'email')
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email'],
            is_staff=True
        )
        return user

class AdminLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

class SoftwarePackageSerializer(serializers.ModelSerializer):
    uploaded_at = serializers.DateTimeField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = SoftwarePackage
        fields = ('version', 'operating_system', 'file', 'uploaded_at', 'is_active')
        read_only_fields = ('uploaded_at', 'is_active')

    def validate_version(self, value):
        # Check if the version follows semantic versioning pattern (X.Y.Z)
        pattern = r'^\d+\.\d+\.\d+$'
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Version must be in semantic format (X.Y.Z) where X, Y, and Z are numbers"
            )

        # Access the entire data dictionary
        data = self.initial_data
        operating_system = data.get('operating_system')

        # Check if version already exists for this operating system
        if SoftwarePackage.objects.filter(
            version=value,
            operating_system=operating_system
        ).exists():
            raise serializers.ValidationError(
                f"Version {value} already exists for {operating_system}"
            )
        
        # Get the latest version for this operating system
        latest_package = SoftwarePackage.objects.filter(
            operating_system=operating_system
        ).order_by('-uploaded_at').first()

        if latest_package:
            try:
                if pkg_version.parse(value) <= pkg_version.parse(latest_package.version):
                    raise serializers.ValidationError(
                        f"New version must be higher than the current version ({latest_package.version}) for {operating_system}"
                    )
            except pkg_version.InvalidVersion:
                raise serializers.ValidationError(
                    "Invalid version format. Please use semantic versioning (e.g., 1.0.0)"
                )
        
        return value 