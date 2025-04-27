from django.test import TestCase
from django.contrib.auth.models import User
from .models import PhotoboothUser, UserTimestamp, ShopAddress
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
import random
import string
from django.urls import reverse

class PhotoboothModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='zathar34@gmail.com',
            first_name='Test',
            last_name='User'
        )
        self.photobooth_user = PhotoboothUser.objects.create(
            user=self.user,
            phone='1234567890',
            phone_2='0987654321',
            salutation='Herr',
            date_of_birth='1990-01-01',
            company_name='Test Company',
            legal_form='GmbH',
            website='https://test.com',
            user_type='owner'
        )

    def test_photobooth_user_creation(self):
        self.assertEqual(self.photobooth_user.user.username, 'testuser')
        self.assertEqual(self.photobooth_user.phone, '1234567890')
        self.assertEqual(self.photobooth_user.phone_2, '0987654321')
        self.assertEqual(self.photobooth_user.salutation, 'Herr')
        self.assertEqual(self.photobooth_user.date_of_birth,'1990-01-01')
        self.assertEqual(self.photobooth_user.company_name, 'Test Company')
        self.assertEqual(self.photobooth_user.legal_form, 'GmbH')
        self.assertEqual(self.photobooth_user.website, 'https://test.com')

    def test_otp_generation(self):
        self.photobooth_user.generate_otp()
        self.assertEqual(len(self.photobooth_user.email_otp), 6)
        self.assertIsNotNone(self.photobooth_user.otp_expiry)

    def test_user_timestamp_creation(self):
        timestamp = UserTimestamp.objects.create(
            user=self.photobooth_user,
            software_version='0.0.1'
        )
        self.assertEqual(timestamp.software_version, '0.0.1')
        self.assertAlmostEqual(timestamp.timestamp, timezone.now(), delta=timezone.timedelta(seconds=1))

    def test_shop_address_creation(self):
        shop = ShopAddress.objects.create(
            photobooth_user=self.photobooth_user,
            name='Test Shop',
            address='123 Test St',
            shop_phone='0987654321',
            zipcode='12345',
            city='Test City'
        )
        self.assertEqual(shop.name, 'Test Shop')
        self.assertEqual(shop.city, 'Test City')

    def test_owner_code_generation(self):
        # Test owner code generation functionality
        self.photobooth_user.generate_owner_code()
        self.assertEqual(len(self.photobooth_user.owner_code), 8)
        self.assertRegex(self.photobooth_user.owner_code, r'^[A-Z0-9]{8}$')

    def test_employee_relationship(self):
        # Create employee user
        employee_user = User.objects.create_user(
            username='employee',
            password='employee123',
            email='zathar34+1@gmail.com',
            first_name='Test',
            last_name='Employee'
        )
        
        employee = PhotoboothUser.objects.create(
            user=employee_user,
            phone='5556667777',
            salutation='Frau',
            user_type='employee',
            employer=self.photobooth_user
        )
        
        # Test employee-employer relationship
        self.assertEqual(employee.employer, self.photobooth_user)
        self.assertIn(employee, self.photobooth_user.employees.all())

class PhotoboothViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='zathar34@gmail.com',
            first_name='Test',
            last_name='User'
        )
        self.photobooth_user = PhotoboothUser.objects.create(
            user=self.user,
            phone='1234567890',
            phone_2='0987654321',
            salutation='Herr',
            date_of_birth='1990-01-01',
            company_name='Test Company',
            legal_form='GmbH',
            website='https://test.com',
            email_verified=True,
            user_type='owner'
        )
        # Create a SoftwarePackage for timestamp tests
        from admin_portal.models import SoftwarePackage
        self.software_package = SoftwarePackage.objects.create(
            version='0.0.1',
            is_active=True
        )

    def test_user_registration(self):
        url = '/api/photobooth/register/'
        data = {
            'user': {
                'username': 'newuser',
                'email': 'zohaib.athar@mira-ee.de',
                'password': 'newpass123',
                'first_name': 'New',
                'last_name': 'User'
            },
            'phone': '1234567890',
            'phone_2': '0987654321',
            'salutation': 'Frau',
            'date_of_birth': '1995-05-15',
            'company_name': 'New Company',
            'legal_form': 'GmbH',
            'website': 'https://newcompany.com'
        }
        response = self.client.post(url, data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print(response.data)  # Print the error details for debugging
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(PhotoboothUser.objects.count(), 2)

    def test_user_login(self):
        url = '/api/photobooth/login/'
        data = {
            'email': 'zathar34@gmail.com',
            'password': 'testpass123',
            'software_version': '0.0.1',
            'operating_system': 'WINDOWS'
        }
        response = self.client.post(url, data, format='json')
        if response.status_code != status.HTTP_200_OK:
            print(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)

    def test_save_timestamp(self):
        self.client.force_authenticate(user=self.user)
        url = '/api/photobooth/save-timestamp/'
        response = self.client.post(url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(UserTimestamp.objects.count(), 1)

    def test_shop_address_management(self):
        self.photobooth_user.email_verified = True
        self.photobooth_user.save()
        self.client.force_authenticate(user=self.user)
        url = '/api/photobooth/registered-shops/'
        
        # Test creating a shop
        data = {
            'name': 'Test Shop',
            'address': '123 Test St',
            'shop_phone': '0987654321',
            'zipcode': '12345',
            'city': 'Test City',
            'website': 'https://test.com',
            'latitude': '33.60172',
            'longitude': '72.9215'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        print(response)
        
        # Test getting shops
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_otp_verification(self):
            # Override the email_verified status to False for this test
        self.photobooth_user.email_verified = False
        self.photobooth_user.save()
        self.photobooth_user.generate_otp()
        url = reverse('photobooth:verify_otp')
        data = {
            'email': 'zathar34@gmail.com',
            'otp': self.photobooth_user.email_otp
        }
        response = self.client.post(url, data, format='json')
        if response.status_code != status.HTTP_200_OK:
            print(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_z_duplicate_email_registration(self):
        # Try to register with the same email as in setUp
        url = '/api/photobooth/register/'
        data = {
            'user': {
                'username': 'testuser1',  # Different username
                'email': 'zathar34@gmail.com',  # Same email as in setUp
                'password': 'testpass123',
                'first_name': 'Duplicate',
                'last_name': 'User'
            },
            'phone': '1234567890',
            'phone_2': '0987654321',
            'salutation': 'Herr',
            'date_of_birth': '1990-01-01',
            'company_name': 'Duplicate Company',
            'legal_form': 'GmbH',
            'website': 'https://duplicate.com'
        }
        
        # This should fail because the email already exists
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_user_registration_with_user_type(self):
        url = '/api/photobooth/register/'
        data = {
            'user': {
                'username': 'newusertype',
                'email': 'zohaib.athar@mira-ee.de',
                'password': 'newpass123',
                'first_name': 'New',
                'last_name': 'User'
            },
            'phone': '1234567890',
            'phone_2': '0987654321',
            'salutation': 'Frau',  # Testing the new salutation option
            'date_of_birth': '1995-05-15',
            'company_name': 'New Company',
            'legal_form': 'GmbH',
            'website': 'https://newcompany.com',
            'user_type': 'owner'
        }
        response = self.client.post(url, data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print(response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(PhotoboothUser.objects.last().user_type, 'owner')
    
    
    def test_employee_registration(self):
        # First generate owner code for the existing user
        self.photobooth_user.generate_owner_code()
        owner_code = self.photobooth_user.owner_code
        self.photobooth_user.email_verified = True
        self.photobooth_user.save()
        
        url = '/api/photobooth/register/'
        data = {
            'user': {
                'username': 'employee1',
                'email': 'zathar34+1@gmail.com',
                'password': 'emppass123',
                'first_name': 'Employee',
                'last_name': 'One'
            },
            'phone': '9876543210',
            'salutation': 'Frau',
            'owner_code': owner_code,
            'user_type': 'employee'
        }
        response = self.client.post(url, data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print(response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Check if employee is linked to the correct employer
        employee = PhotoboothUser.objects.get(user__username='employee1')
        self.assertEqual(employee.employer, self.photobooth_user)
        self.assertEqual(employee.user_type, 'employee')
        
