from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import SoftwarePackage
from .serializers import (
    AdminUserSerializer,
    AdminLoginSerializer,
    SoftwarePackageSerializer
)
from django.contrib.auth.models import User

# Create your views here.

@api_view(['POST'])
@permission_classes([AllowAny])
def login_admin(request):
    serializer = AdminLoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = authenticate(username=username, password=password)
        if user and user.is_staff:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh)
            }, status=status.HTTP_200_OK)
        return Response({
            'error': 'Invalid credentials or not an admin user'
        }, status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def upload_package(request):
    serializer = SoftwarePackageSerializer(data=request.data)
    if serializer.is_valid():
        # Save the new package as active
        package = serializer.save(
            uploaded_by=request.user,
            is_active=True
        )
        return Response({
            'message': 'Software package uploaded successfully'
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_admin_user(request):
    # Check if requesting user is superuser
    if not request.user.is_superuser:
        return Response({
            'error': 'Only superusers can create admin accounts'
        }, status=status.HTTP_403_FORBIDDEN)
    
    serializer = AdminUserSerializer(data=request.data)
    if serializer.is_valid():
        # Create user with admin privileges
        user = User.objects.create_user(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password'],
            email=serializer.validated_data.get('email', ''),
            is_staff=True  # This gives admin site access
        )
        
        return Response({
            'message': 'Admin user created successfully',
            'username': user.username
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
