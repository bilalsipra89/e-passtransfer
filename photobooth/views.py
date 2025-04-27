from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import PhotoboothUser, UserTimestamp, ShopAddress, User
from admin_portal.models import SoftwarePackage
from .serializers import (
    PhotoboothUserRegistrationSerializer,
    PhotoboothUserLoginSerializer,
    UserTimestampSerializer,
    LicenseVerificationSerializer,
    OTPVerificationSerializer,
    ResendOTPSerializer,
    ShopAddressSerializer,
    UsernameCheckSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    LocationQuerySerializer,
    PhotoboothUserProfileSerializer,
    InviteUserSerializer,
    MacOTPVerificationSerializer,
    WebLoginSerializer,
    PasswordChangeSerializer,
    DownloadURLSerializer
)
from django.template.loader import render_to_string
from django.utils import timezone
import hashlib
import uuid
from .email_utils import send_email
import boto3
from rest_framework.views import APIView
from django.contrib.auth.hashers import make_password
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .eid_token_utils import get_access_token
from django.conf import settings
from django.core.mail import send_mail
from rest_framework import serializers


# Create your views here.

@api_view(['GET'])
@permission_classes([AllowAny])
def signature(request):
    #get operating system from request body
    operating_system = request.data.get('operating_system')
    if operating_system == 'MAC':
        return Response({
        'Signature': 'DIQXRpPuY44b3HrFYOu5ETgMLKrCVWsHvosJ+UspcE6uca56ptIsw0SQZjjmw27x9nVvHF0Qp9orNFIC8l0vohUbnV7qeFM4ZGFfTyiyozpYf8JOgT/VMeSLf0erpmRaNd+2BDgkM6CUSMLvQn388+NyS0asMEJ05NrhP4pk+O2mejGC56JlUyahxTo7/xq6xWJWYy3PfO+Zrfz7ShBSdJmHrAp0d/9IIvtwQJlJZZnXgMI0nbZmLdFsF3QAj58BCi1O5qOcCuF38C1floU/8Ky2mp0KHcQ+Cw70d7QOZMjww3l7WBWKpcC32fEH7wYr07LpQE0EvhgGhsz97OwRXg=='
    }, status=status.HTTP_200_OK)

    elif operating_system == 'WINDOWS':
        return Response({
        'Signature': 'kODfAcsD8+8HoxamNwE1Df0PP9it9wyX3oTDLnamUXINqWtWvzw4TPZXzKYFNVRw+AfKQ9OS4k+Xh8vdqgknQvx/fy7UzjH8oVw4nhLmXR6G0gW6LWA1KCsK6jzjY0eBj3YyyWxcsiMx6Sz27mZAKXztqnwagT+HK++YrSHvyo0BtpyLcOtww7FABj0WceHlILJQU/DGRyN85HpdKLBJT//6rVYGxGilxK59RxAXnLSjIikQXwNuK0OOwaPDEVDjskg/nrmNckEIg5E9ruywP0fBVVF6u5+cewUA6Az2BlMeeAlquPuzFR8p+0Jaimvn80sW5k1UGJ0ZV5RfekQ+EA=='
    }, status=status.HTTP_200_OK)

    else:
        return Response({
            'error': 'Invalid operating system'
        }, status=status.HTTP_400_BAD_REQUEST)

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PhotoboothUserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.create(serializer.validated_data)
            
            # Generate and send OTP
            otp = user.generate_otp()
            user_name = f"{user.user.first_name} {user.user.last_name}".strip()

            
            # Send OTP email
            subject = 'Bestätigungscode für Ihr EpassTransfer-Konto' #Verification code for your EpassTransfer account
            message = render_to_string('email/otp_email.html', {
                'otp': otp,
                'site_name': 'EpassTransfer',
                'user_name': user_name
            })

            # Send email using email utility
            email_sent = send_email(
                user.user.email,
                subject,
                message
            )
            
            if email_sent:
                return Response({
                    'message': 'Registration successful. Please check your email for OTP verification.'
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'error': 'Failed to send verification email. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        # Get username from query parameters
        username = request.query_params.get('username', None)
        
        if not username:
            return Response({
                'error': 'Username parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Use the serializer to validate the username
        serializer = UsernameCheckSerializer(data={'username': username})
        
        if serializer.is_valid():
            # If validation passes, username is available
            return Response({
                'available': True,
                'message': 'Username is available'
            }, status=status.HTTP_200_OK)
        else:
            # If validation fails, username is taken
            return Response({
                'available': False,
                'message': 'Username is already taken'
            }, status=status.HTTP_200_OK)


class UserInviteView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = InviteUserSerializer(data=request.data)
        if serializer.is_valid():
            # Get the authenticated user requesting to invite someone
            try:
                inviter = PhotoboothUser.objects.get(user=request.user)
                role = serializer.validated_data['role']
                email = serializer.validated_data['email']
                
                
                if role == 'employee' and not inviter.can_invite_employees():
                    return Response({
                        'error': 'Only owners and managers can invite employees'
                    }, status=status.HTTP_403_FORBIDDEN)
                
                
                # Prepare data for email
                company_name = inviter.company_name.replace(" ", "_") if inviter.company_name else "Unknown_Company"
                website = inviter.website or "Not available"
                legal_form = inviter.legal_form or ""
                
                # Determine the owner code to use
                owner_code = inviter.owner_code
                if inviter.user_type == 'manager' and role == 'employee':
                    owner_code = inviter.owner_code if inviter.employer else None
                    if not owner_code:
                        return Response({
                            'error': 'Failed to get owner code for invitation'
                        }, status=status.HTTP_400_BAD_REQUEST)
                if inviter.user_type == 'manager' and role == 'manager':
                    owner_code = inviter.employer.owner_code if inviter.employer else None
                    if not owner_code:
                        return Response({
                            'error': 'Failed to get owner code for invitation'
                        }, status=status.HTTP_400_BAD_REQUEST)
                
                # Create registration link with parameters
                registration_link = (f"https://e-passtransfer.de/registration/?email={email}"
                                f"&company_name={company_name}&owner_code={owner_code}&website={website}"
                                f"&legal_form={legal_form}&user_type={role}")
                
                # Prepare email content
                role_name = 'Manager' if role == 'manager' else 'Mitarbeiter'
                subject = f'Einladung zur Registrierung als {role_name} bei EpassTransfer'
                inviter_name = f"{inviter.user.first_name} {inviter.user.last_name}".strip()
                
                # Render email template
                message = render_to_string('email/invite_email.html', {
                    'employee_email': email,
                    'company_name': company_name,
                    'website': website,
                    'registration_link': registration_link,
                    'site_name': 'EpassTransfer',
                    'owner_name': inviter_name,
                    'owner_email': inviter.user.email,
                    'role': role_name
                })
                
                # Send email using email utility
                email_sent = send_email(
                    email,
                    subject,
                    message
                )
                
                if email_sent:
                    return Response({
                        'message': f'Invitation email sent successfully to {role}'
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'Failed to send invitation email. Please try again.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
            except PhotoboothUser.DoesNotExist:
                return Response({
                    'error': 'User profile not found'
                }, status=status.HTTP_404_NOT_FOUND)
            except Exception as general_error:
                return Response({
                    'error': f'Unexpected error: {str(general_error)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        try:
            user = PhotoboothUser.objects.get(user=request.user)
            role = request.query_params.get('role', 'employee')
            
            if role == 'manager' and not user.is_owner():
                return Response({
                    'error': 'Only owners can view managers'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Get users based on role and requester's type
            if role == 'manager':
                # Only owners can see managers, and they see their direct managers
                users = PhotoboothUser.objects.filter(employer=user, user_type='manager')
            else:  # employee
                if user.user_type == 'owner':
                    # Owners see their direct employees
                    users = PhotoboothUser.objects.filter(employer=user, user_type='employee')
                elif user.user_type == 'manager':
                    # Managers see employees under their owner
                    users = PhotoboothUser.objects.filter(employer=user.employer, user_type='employee')
                else:
                    return Response({
                        'error': 'Only owners and managers can view employees'
                    }, status=status.HTTP_403_FORBIDDEN)
            
            serializer = PhotoboothUserProfileSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except PhotoboothUser.DoesNotExist:
            return Response({
                'error': 'User profile not found'
            }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    serializer = OTPVerificationSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        
        try:
            user = PhotoboothUser.objects.get(user__email=email)
            
            # Check if OTP is expired
            if user.otp_expiry and user.otp_expiry < timezone.now():
                return Response({
                    'error': 'OTP has expired. Please request a new one.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify OTP
            if user.email_otp == otp:
                if not user.email_verified:
                    #generate license hash for owner and managers
                    if user.user_type in ['owner', 'manager']:
                        license_hash = user.generate_license_hash()
                    else:
                        license_hash = None
                    user.email_verified = True
                    user.email_otp = None  # Clear OTP after successful verification
                    user.otp_expiry = None
                    user.save()
                    
                    response_data = {'message': 'Email verified successfully'}
                    response_data['license_hash'] = license_hash
                    
                    return Response(response_data, status=status.HTTP_200_OK)
                return Response({
                    'error': 'Email already verified'
                }, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'error': 'Invalid OTP'
            }, status=status.HTTP_400_BAD_REQUEST)
        except PhotoboothUser.DoesNotExist:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def resend_otp(request):
    serializer = ResendOTPSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = PhotoboothUser.objects.get(user__email=email)
            if not user.email_verified:
                # Generate new OTP
                otp = user.generate_otp()
                
                # Get company name or username for the email
                company_name = user.company_name
                user_name = f"{user.user.first_name} {user.user.last_name}".strip()
                
                # Send OTP email
                subject = 'Bestätigungscode für Ihr EpassTransfer-Konto'
                message = render_to_string('email/otp_email.html', {
                    'otp': otp,
                    'site_name': 'EpassTransfer',
                    'company_name': company_name,
                    'user_name': user_name
                })

                # Send email using email utility
                email_sent = send_email(
                    user.user.email,
                    subject,
                    message
                )
                
                if email_sent:
                    return Response({
                        'message': 'New OTP sent successfully'
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'error': 'Failed to send OTP email. Please try again.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
            return Response({
                'error': 'Email already verified'
            }, status=status.HTTP_400_BAD_REQUEST)
        except PhotoboothUser.DoesNotExist:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_license(request):
    serializer = LicenseVerificationSerializer(data=request.data)
    if serializer.is_valid():
        photobooth_user = PhotoboothUser.objects.get(user=request.user)
        operating_system = serializer.validated_data['operating_system']
        license_hash = serializer.validated_data['license_hash']
        #if request user is employee check if license hash is of his employer
        if photobooth_user.user_type == 'employee':
            if photobooth_user.employer.license_hash != license_hash:
                return Response({
                    'error': 'Invalid license hash'
                }, status=status.HTTP_400_BAD_REQUEST)
        #if request user is manager or owner    check if license hash is of his own
        if photobooth_user.user_type in ['manager', 'owner']:
            if photobooth_user.license_hash != license_hash:
                return Response({
                    'error': 'Invalid license hash'
                }, status=status.HTTP_400_BAD_REQUEST)

        photobooth_user.licensed = True
        photobooth_user.save()
        try:
            # Get the latest active software package for the specified OS
            package = SoftwarePackage.objects.filter(
                is_active=True,
                operating_system=operating_system
            ).first()
            
            if package:
                response_data = pre_sign_url_generator(package)
                response_data['licensed'] = photobooth_user.licensed
                return Response(response_data, status=status.HTTP_200_OK)

            return Response({
                'error': f'No active software package available for {operating_system}'
            }, status=status.HTTP_404_NOT_FOUND)
        except PhotoboothUser.DoesNotExist:
            return Response({
                'error': 'Invalid license hash'
            }, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_download_url(request):
    #check if user is owner or manager
    if request.user.photoboothuser.user_type not in ['owner', 'manager']:
        return Response({
            'error': 'Only owners and managers can get download URL'
        }, status=status.HTTP_403_FORBIDDEN)
    #serialize data from url
    serializer = DownloadURLSerializer(data=request.query_params)
    if serializer.is_valid():
        operating_system = serializer.validated_data['operating_system']
        package = SoftwarePackage.objects.filter(
            is_active=True,
            operating_system=operating_system
        ).first()
        return Response(pre_sign_url_generator(package), status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



def pre_sign_url_generator(package):
    # Generate a proper pre-signed URL using boto3
            s3_client = boto3.client(
                's3',
                region_name=settings.AWS_S3_REGION_NAME,
                config=boto3.session.Config(signature_version='s3v4')
            )
            
            # Parse the S3 bucket and key from the file path
            bucket_name = package.file.storage.bucket_name
            key = package.file.name
            
            # Generate a pre-signed URL that expires in 180 seconds
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket_name,
                    'Key': key,
                },
                ExpiresIn=300
            )
            
            return ({
                'download_url': url,
                'expires_in': 300,
                'version': package.version
            })


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    serializer = PhotoboothUserLoginSerializer(data=request.data)
    
    # Try to validate the serializer
    try:
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        mac_address = serializer.validated_data['mac_address']
        
        # Find the user by email
        try:
            user_obj = User.objects.get(email=email)
            # Authenticate with the found username and provided password
            user = authenticate(username=user_obj.username, password=password)
            
            if user:
                try:
                    photobooth_user = PhotoboothUser.objects.get(user=user)
                    
                    # Check if email is verified
                    if not photobooth_user.email_verified:
                        return Response({
                            'error': 'Email not verified. Please verify your email before logging in.'
                        }, status=status.HTTP_403_FORBIDDEN)
                    
                    # MAC address verification logic
                    if photobooth_user.mac_address != mac_address:
                        # Different device detected, generate OTP
                        otp = photobooth_user.generate_otp()
                        
                        # Get user's name
                        user_name = f"{user.first_name} {user.last_name}".strip() or user.username
                        
                        # Prepare email content
                        subject = 'Neue Geräteverifizierung bei EpassTransfer'
                        message = render_to_string('email/device_verification_email.html', {
                            'otp': otp,
                            'user_name': user_name,
                            'site_name': 'EpassTransfer'
                        })
                        
                        # Send email using email utility
                        email_sent = send_email(
                            user.email,
                            subject,
                            message
                        )
                        
                        return Response({
                            "email_sent": email_sent,
                            "message": "New device detected. Please verify with the OTP sent to your email.",
                            "require_mac_verification": True
                        }, status=status.HTTP_200_OK)
                    
                    # If MAC address matches, proceed with login
                    refresh = RefreshToken.for_user(user)
                    
                    # Add a flag to indicate this is a desktop app login
                    refresh['login_type'] = 'desktop'
                    
                    return Response({
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh),
                        'licensed': photobooth_user.licensed
                    }, status=status.HTTP_200_OK)
                except PhotoboothUser.DoesNotExist:
                    return Response({
                        'error': 'User is not registered as a photobooth user'
                    }, status=status.HTTP_403_FORBIDDEN)
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({
                'error': 'No user found with this email'
            }, status=status.HTTP_404_NOT_FOUND)
            
    except serializers.ValidationError as e:
        error_detail = str(e.detail[0]) if isinstance(e.detail, list) else str(e.detail)
        
        # Check if error is due to invalid software version
        if "Invalid software version" in error_detail:
            operating_system = request.data.get('operating_system')
            
            # Get the latest active software package for the OS
            try:
                package = SoftwarePackage.objects.filter(
                    is_active=True,
                    operating_system=operating_system
                ).first()
                
                if package:
                    # Generate pre-signed URL and return download information
                    download_info = pre_sign_url_generator(package)
                    download_info['error'] = error_detail
                    return Response(download_info, status=status.HTTP_400_BAD_REQUEST)
            except Exception as ex:
                return Response({
                    'error': f'Error generating download link: {str(ex)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # For other validation errors, return them normally
        return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
    
    # This is for non-validation errors
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            photobooth_user = PhotoboothUser.objects.get(user=request.user)
            serializer = PhotoboothUserProfileSerializer(photobooth_user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except PhotoboothUser.DoesNotExist:
            return Response({
                'error': 'User profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    def put(self, request):
        try:
            photobooth_user = PhotoboothUser.objects.get(user=request.user)
            serializer = PhotoboothUserProfileSerializer(photobooth_user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PhotoboothUser.DoesNotExist:
            return Response({
                'error': 'User profile not found'
            }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_timestamp(request):
    # Check if the request is from a desktop app login
    if 'login_type' in request.auth.payload and request.auth.payload['login_type'] == 'web':
        return Response({
            'error': 'This endpoint is only available for desktop application users'
        }, status=status.HTTP_403_FORBIDDEN)
    
    try:
        photobooth_user = PhotoboothUser.objects.get(user=request.user)
        serializer = UserTimestampSerializer(data=request.data)
        if serializer.is_valid():
            # Get the version from the login validation
            active_package = SoftwarePackage.objects.filter(is_active=True).first()
            UserTimestamp.objects.create(
                user=photobooth_user,
                software_version=active_package.version
            )
            return Response({
                'message': 'Timestamp saved successfully'
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except PhotoboothUser.DoesNotExist:
        return Response({
            'error': 'User is not registered as a photobooth user'
        }, status=status.HTTP_403_FORBIDDEN)

class ShopAddressView(APIView): 
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            photobooth_user = PhotoboothUser.objects.get(user=request.user)
            # For GET, determine which shops to show based on user type
            if photobooth_user.user_type == 'employee' and photobooth_user.employer:
                # Employees see their employer's shops
                shops = ShopAddress.objects.filter(photobooth_user=photobooth_user.employer)
            elif photobooth_user.user_type == 'manager' and photobooth_user.employer:
                # Managers see their employer's shops
                shops = ShopAddress.objects.filter(photobooth_user=photobooth_user.employer)
            else:
                # Owners see their own shops
                shops = ShopAddress.objects.filter(photobooth_user=photobooth_user)
                
            serializer = ShopAddressSerializer(shops, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except PhotoboothUser.DoesNotExist:
            return Response({
                'error': 'User is not registered as a photobooth user'
            }, status=status.HTTP_403_FORBIDDEN)
            

    def post(self, request):
        try:
            photobooth_user = PhotoboothUser.objects.get(user=request.user)
            # Only owners can register new shops
            if photobooth_user.user_type in ['employee', 'manager']:
                return Response(
                    {'error': 'Only shop owners can register new shop addresses.'},
                    status=status.HTTP_403_FORBIDDEN
                )
                
            serializer = ShopAddressSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(photobooth_user=photobooth_user)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PhotoboothUser.DoesNotExist:
            return Response({
            'error': 'User is not registered as a photobooth user'}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, pk):
        try:
            photobooth_user = PhotoboothUser.objects.get(user=request.user)
            shop_address = ShopAddress.objects.get(id=pk, photobooth_user=photobooth_user)
            shop_address.delete()
            return Response({
                'message': 'Shop address deleted successfully'
            }, status=status.HTTP_200_OK)
        except ShopAddress.DoesNotExist:
            return Response({
                'error': 'Shop address not found'
            }, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([AllowAny])
def shops_nearby(request):
    # Validate query parameters using the dedicated serializer
    query_serializer = LocationQuerySerializer(data=request.query_params)
    if not query_serializer.is_valid():
        return Response(query_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Get validated data
    validated_data = query_serializer.validated_data
    latitude = validated_data['latitude']
    longitude = validated_data['longitude']
    radius = validated_data['radius']
    
    try:
        # Get all shop addresses
        shops = ShopAddress.objects.all()
        
        # Calculate distance for each shop and filter by radius
        nearby_shops = []
        for shop in shops:
            # Calculate distance using Haversine formula
            distance = calculate_distance(
                latitude, longitude, 
                float(shop.latitude), float(shop.longitude)
            )
            
            # If within radius, add to results
            if distance <= radius:
                shop_data = ShopAddressSerializer(shop).data
                shop_data['distance'] = round(distance, 2)  # Add distance to response
                nearby_shops.append(shop_data)
        
        # Sort by distance
        nearby_shops = sorted(nearby_shops, key=lambda x: x['distance'])
        
        return Response(nearby_shops, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': f'An error occurred: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    """
    from math import radians, cos, sin, asin, sqrt
    
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    r = 6371  # Radius of earth in kilometers
    
    return c * r

class UserPasswordResetView(APIView):
    """
    API view to request a password reset by providing the registered email.
    Sends a reset code to the email if the user exists.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                photobooth_user = PhotoboothUser.objects.get(user=user)
                
                # Generate and send reset code
                reset_code = photobooth_user.generate_otp()  # Reusing OTP functionality
                
                # Prepare email content
                current_site = 'EpassTransfer'
                mail_subject = 'Passwort zurücksetzen'
                
                # Get company name or user's name
                #company_name = photobooth_user.company_name
                user_name = f"{user.first_name} {user.last_name}".strip() or user.username
                
                # Render email template
                html_message = render_to_string('email/password_reset_email.html', {
                    'user_name': user_name,
                    #'company_name': company_name,
                    'reset_code': reset_code,
                    'site_name': current_site,
                })
                
                # Send email
                send_email(user.email, mail_subject, html_message)
                
                return Response({
                    "message": "Password reset instructions have been sent to your email."
                }, status=status.HTTP_200_OK)
                
            except (User.DoesNotExist, PhotoboothUser.DoesNotExist):
                # We don't want to reveal if a user exists or not for security reasons
                return Response({
                    "message": "If a user with this email exists, password reset instructions have been sent."
                }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
    def put(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            new_password = serializer.validated_data['new_password']
            
            try:
                user = User.objects.get(email=email)
                photobooth_user = PhotoboothUser.objects.get(user=user)
                
                # Reset the user's password
                user.password = make_password(new_password)
                user.save()
                
                # Clear the OTP fields
                photobooth_user.email_otp = None
                photobooth_user.otp_expiry = None
                photobooth_user.save()
                
                return Response({
                    "message": "Password has been reset successfully."
                }, status=status.HTTP_200_OK)
                
            except (User.DoesNotExist, PhotoboothUser.DoesNotExist):
                return Response({
                    "error": "User not found."
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

   
@csrf_exempt
@permission_classes([IsAuthenticated])
def eid_token_exchange(request):
    """
    Endpoint to exchange an authorization code for an access token
    Requires authentication
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            authorization_code = data.get('code')
            
            if not authorization_code:
                return JsonResponse({'error': 'Authorization code is required'}, status=400)
            
            # Call the utility function to get the token
            response_text = get_access_token(authorization_code)
            
            # Return the raw response as is
            return HttpResponse(response_text, content_type='application/json')
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def seed(request):
    # Generate a random 7-character hash
    random_hash = uuid.uuid4().hex[:7]
    return Response({
        'seed': random_hash
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_mac_otp(request):
    serializer = MacOTPVerificationSerializer(data=request.data)
    
    if serializer.is_valid():
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        mac_address = serializer.validated_data['mac_address']
        
        try:
            user = User.objects.get(email=email)
            photobooth_user = PhotoboothUser.objects.get(user=user)
            
            # OTP validation is already done in serializer, proceed to update MAC
            photobooth_user.mac_address = mac_address
            
            # Clear OTP fields
            photobooth_user.email_otp = None
            photobooth_user.otp_expiry = None
            photobooth_user.save()
            
            return Response({
                'message': 'Device verified successfully, please login again'
            }, status=status.HTTP_200_OK)
            
        except (User.DoesNotExist, PhotoboothUser.DoesNotExist):
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def web_login(request):
    serializer = WebLoginSerializer(data=request.data)
    
    try:
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Find the user by email
        try:
            user_obj = User.objects.get(email=email)
            # Authenticate with the found username and provided password
            user = authenticate(username=user_obj.username, password=password)
            
            if user:
                try:
                    photobooth_user = PhotoboothUser.objects.get(user=user)
                    #get user type
                    user_type = photobooth_user.user_type
                    # If email verified and authentication successful, generate tokens
                    refresh = RefreshToken.for_user(user)
                    
                    # Set a flag in the token to indicate this is a web login
                    refresh['login_type'] = 'web'
                    
                    return Response({
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh),
                        'user_type': user_type
                    }, status=status.HTTP_200_OK)
                
                except PhotoboothUser.DoesNotExist:
                    return Response({
                        'error': 'User is not registered as a photobooth user'
                    }, status=status.HTTP_403_FORBIDDEN)
            
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        except User.DoesNotExist:
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
            
    except serializers.ValidationError as e:
        return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = PasswordChangeSerializer(context={'request': request}, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'Password changed successfully.'
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

