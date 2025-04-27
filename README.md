# API Documentation

This document provides detailed information about all available API endpoints in the E-Passbild Backend system.

## Table of Contents
- [Authentication Endpoints](#authentication-endpoints)
  - [Register User](#register-user)
  - [Check Username Availability](#check-username-availability)
  - [Verify OTP](#verify-otp)
  - [Resend OTP](#resend-otp)
  - [User Login](#user-login)
  - [Web Login](#web-login)
  - [Invite-employee](#invite-employee)
  - [Admin Login](#admin-login)
  - [Request Password Reset](#request-password-reset)
  - [Confirm Password Reset](#confirm-password-reset)
  - [Verify New Device](#verify-new-device)
  - [Update Password](#update-password)
- [License Management](#license-management)
  - [Verify License](#verify-license)
  - [Get Download URL](#get-download-url)
- [User Management](#user-management)
  - [User Profile](#user-profile)
  - [Save Timestamp](#save-timestamp)
  - [Shop Addresses](#shop-addresses)
  - [Get Signature](#get-signature)
  - [eID Token Exchange](#eid-token-exchange)
  - [Seed](#seed)
- [Admin Management](#admin-management)
  - [Create Admin User](#create-admin-user)
  - [Upload Software Package](#upload-software-package)

## Authentication Endpoints

### Register User

Register a new photobooth user in the system.

**Endpoint:** `POST /photobooth/register/`

**Authentication Required:** No

**Request Body:**
```json
{
    "user": {
        "username": "photobooth_user1",
        "email": "user@example.com",
        "password": "securepassword123",
        "first_name": "John",
        "last_name": "Doe"
    },
    "phone": "+49123456789",
    "phone_2": "+49987654321",
    "salutation": "Herr",
    "date_of_birth": "1990-01-01",
    "company_name": "Photo Studio GmbH",
    "legal_form": "GmbH",
    "website": "https://www.photostudio.com",
    "user_type":"owner" or "employee" or "manager",
    "owner_code":"asdf4567" not required for owner
}
```

**Success Response (201 Created):**
```json
{
    "message": "Registration successful. Please check your email for OTP verification."
}
```

**Error Response (400 Bad Request):**
```json
{
    "user": {
        "username": ["This username is already taken."],
        "email": ["Enter a valid email address."]
    },
    "phone": ["This field is required."]
}
```

**Error Response (400 Bad Request) - Email Already Exists:**
```json
{
    "user": {
        "username": [
            "A user with that username already exists."
        ]
    }
}
```

**Error Response (400 Bad Request) - Email Exists But Not Verified:**
```json
{
    "user": {
        "username": [
            "A user with that username already exists."
        ],
        "email": {
            "email": "Please verify your email."
        }
    }
}
```

### Check Username Availability

Check if a username is available for registration.

**Endpoint:** `GET /photobooth/register/?username=username_to_check`

**Authentication Required:** No

**Success Response (200 OK) - Username Available:**
```json
{
    "available": true,
    "message": "Username is available"
}
```

**Success Response (200 OK) - Username Taken:**
```json
{
    "available": false,
    "message": "Username is already taken"
}
```

**Error Response (400 Bad Request):**
```json
{
    "error": "Username parameter is required"
}
```

### Verify OTP

Verify the OTP sent to user's email after registration.

**Endpoint:** `POST /photobooth/verify-otp/`

**Authentication Required:** No

**Request Body:**
```json
{
    "email": "user@example.com",
    "otp": "123456"
}
```

**Success Response (200 OK):**
```json
{
    "message": "Email verified successfully",
    "license_hash": "a1b2c3d4e5f6..."
}
```

**Error Response (400 Bad Request):**
```json
{
    "error": "Invalid OTP"
}
```

**Notes:** 
- License hash is only returned for owner accounts

### Resend OTP

Request a new OTP if the previous one expired.

**Endpoint:** `POST /photobooth/resend-otp/`

**Authentication Required:** No

**Request Body:**
```json
{
    "email": "user@example.com"
}
```

**Success Response (200 OK):**
```json
{
    "message": "New OTP sent successfully"
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "User not found"
}
```

### User Login

Login for desktop application users.

**Endpoint:** `POST /photobooth/login/`

**Authentication Required:** No

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "securepassword123",
    "software_version": "0.0.1",
    "operating_system": "WINDOWS",
    "mac_address" : "XX:XX:XX:XX:XX:XX"
}
```

**Success Response (200 OK):**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "licensed" : "true or false"
}
```

**Notes:**
- The `licensed` field becomes `true` under the following conditions:
  - For **employees**: When the validate_license endpoint is hit with their inviter's license
  - For **managers** and **owners**: When the validate_license endpoint is hit with their own license only
  - The license must not be expired and must be valid

**Success Response (200 OK) - New Device Detected:**
```json
{
    "email_sent": true,
    "message": "New device detected. Please verify with the OTP sent to your email.",
    "require_mac_verification": true
}
```

**Error Response (400 Bad Request) - Version Mismatch:**
```json
{
    "download_url": "https://epasstransfer........",
    "expires_in": 300,
    "version": "0.0.2",
    "error": "Invalid software version. Current active version for WINDOWS is 0.0.2"
}
```


**Error Response (401 Unauthorized):**
```json
{
    "error": "Invalid credentials"
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "No user found with this email"
}
```

**Error Response (403 Forbidden) - Email Not Verified:**
```json
{
    "error": "Email not verified. Please verify your email before logging in."
}
```

### Web Login

Login for website users.

**Endpoint:** `POST /photobooth/web-login/`

**Authentication Required:** No

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "securepassword123"
}
```

**Success Response (200 OK):**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Error Response (401 Unauthorized):**
```json
{
    "error": "Invalid credentials"
}
```

**Error Response (403 Forbidden):**
```json
{
    "error": "User is not registered as a photobooth user"
}
```

**Error Response (400 Bad Request) - Email Not Verified:**
```json
{
    "email": ["Please verify your email before logging in."]
}
```

### Invite Employee

Send an invitation to a potential employee or manager to join the system under an owner's account.

**Endpoint:** `POST, GET /photobooth/invite-employee/`

**Authentication Required:** Yes (Bearer Token from Owner)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Request Body:**
```json
{
    "email": "employee@example.com",
    "user_type": "employee"
}
```

**Alternative Request Body for Manager:**
```json
{
    "email": "manager@example.com",
    "user_type": "manager"
}
```

**Success Response (200 OK):**
```json
{
    "message": "Invitation email sent successfully to employee"
}
```

**Error Response (403 Forbidden):**
```json
{
    "error": "Only owners/managers can invite employees or managers"
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "Owner profile not found"
}
```

**Error Response (400 Bad Request):**
```json
{
    "email": ["A user with this email already exists."]
}
```
**Notes:**
- The GET method returns a list of all employees and managers associated with the authenticated owner
- Each employee/manager record includes their profile information, user type, and employer details
- The GET method is authenticated and empty
- Only owners can invite employees or managers
- Managers have additional permissions over regular employees, including managing shop data and viewing reports


### Admin Login

Login for admin users.

**Endpoint:** `POST /admin/login/`

**Authentication Required:** No

**Request Body:**
```json
{
    "username": "admin_user",
    "password": "admin_password"
}
```

**Success Response (200 OK):**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Error Response (401 Unauthorized):**
```json
{
    "error": "Invalid credentials or not an admin user"
}
```

### Request Password Reset

Request a password reset by providing the registered email.

**Endpoint:** `POST /photobooth/request-password-reset/`

**Authentication Required:** No

**Request Body:**
```json
{
    "email": "user@example.com"
}
```

**Success Response (200 OK):**
```json
{
    "message": "Password reset instructions have been sent to your email."
}
```

**Success Response (200 OK) - User Not Found:**
```json
{
    "message": "If a user with this email exists, password reset instructions have been sent."
}
```

**Error Response (400 Bad Request):**
```json
{
    "email": ["No user is registered with this email address."]
}
```

### Confirm Password Reset

Confirm the password reset with the reset code and set a new password.

**Endpoint:** `PUT /photobooth/request-password-reset/`

**Authentication Required:** No

**Request Body:**
```json
{
    "email": "user@example.com",
    "reset_code": "123456",
    "new_password": "newSecurePassword123"
}
```

**Success Response (200 OK):**
```json
{
    "message": "Password has been reset successfully."
}
```

**Error Response (400 Bad Request) - Invalid Reset Code:**
```json
{
    "reset_code": ["Invalid reset code."]
}
```

**Error Response (400 Bad Request) - Expired Reset Code:**
```json
{
    "reset_code": ["Reset code has expired."]
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "User not found."
}
```


### Verify New Device

Verify a new device's MAC address using the OTP sent to the user's email.

**Endpoint:** `POST /photobooth/mac-otp-verification/`

**Authentication Required:** No

**Request Body:**
```json
{
    "email": "user@example.com",
    "otp": "123456",
    "mac_address": "XX:XX:XX:XX:XX:XX"
}
```

**Success Response (200 OK):**
```json
{
    "message": "Device verified successfully, please login again"
}
```

**Error Response (400 Bad Request) - Invalid OTP:**
```json
{
    "otp": ["Invalid OTP."]
}
```

**Error Response (400 Bad Request) - Expired OTP:**
```json
{
    "otp": ["OTP has expired."]
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "User not found"
}
```

### Update Password

Update the password for an authenticated user.

**Endpoint:** `POST /photobooth/profile/change-password/`

**Authentication Required:** Yes (Bearer Token)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Request Body:**
```json
{
    "current_password": "currentSecurePassword123",
    "new_password": "newSecurePassword456",
    "confirm_password": "newSecurePassword456"
}
```

**Success Response (200 OK):**
```json
{
    "message": "Password updated successfully"
}
```

**Error Response (400 Bad Request) - Invalid Current Password:**
```json
{
    "current_password": ["Incorrect current password."]
}
```

**Error Response (400 Bad Request) - Password Validation:**
```json
{
    "new_password": ["Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number."]
}
```

**Error Response (401 Unauthorized):**
```json
{
    "detail": "Authentication credentials were not provided."
}
```

**Error Response (400 Bad Request) - Password Mismatch:**
```json
{
    "confirm_password": ["The passwords do not match."]
}
```

## License Management

### Verify License

Verify a license hash and get software download URL for a specific operating system.

**Endpoint:** `POST /photobooth/verify-license/`

**Authentication Required:** Yes

**Request Body:**
```json
{
    "license_hash": "a1b2c3d4e5f6...",
    "operating_system": "WINDOWS"
}
```

**Success Response (200 OK):**
```json
{
    "download_url": "https://your-s3-bucket.s3.amazonaws.com/software_packages/...",
    "expires_in": 180,
    "version": "1.0.0"
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "Invalid license hash"
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "No active software package available for WINDOWS"
}
```

### Get Download URL

Retrieve a pre-signed download URL for the latest software package for a specific operating system.

**Endpoint:** `GET /photobooth/get-download-url/`

**Authentication Required:** Yes (Bearer Token from Owner or Manager)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Query Parameters:**
- `operating_system` (required): The operating system for which to get the download URL (WINDOWS, MAC)

**Example Request:** `GET /photobooth/get-download-url/?operating_system=WINDOWS`

**Success Response (200 OK):**
```json
{
    "download_url": "https://your-s3-bucket.s3.amazonaws.com/software_packages/...",
    "expires_in": 300,
    "version": "1.0.0"
}
```

**Error Response (403 Forbidden):**
```json
{
    "error": "Only owners and managers can get download URL"
}
```

**Error Response (400 Bad Request):**
```json
{
    "operating_system": ["\"LINUX\" is not a valid choice."]
}
```

**Error Response (404 Not Found):**
```json
{
    "error": "No active software package available for WINDOWS"
}
```

**Notes:**
- The download URL is pre-signed and expires after 300 seconds (5 minutes)
- Only owners and managers can access this endpoint
- This endpoint is useful for retrieving the latest software version without requiring a license hash

## User Management

### User Profile

Get or update the authenticated user's profile information.

**Endpoint:** `GET, PUT /photobooth/profile/`

**Authentication Required:** Yes (Bearer Token)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**GET Response (200 OK):**
```json
{
    "first_name": "John",
    "last_name": "Doe",
    "email": "user@example.com",
    "phone": "+49123456789",
    "phone_2": "+49987654321",
    "salutation": "Herr",
    "date_of_birth": "1990-01-01",
    "company_name": "Photo Studio GmbH",
    "legal_form": "GmbH",
    "website": "https://www.photostudio.com"
}
```

**PUT Request Body:**
```json
{
    "first_name": "John",
    "last_name": "Doe",
    "phone": "+49123456789",
    "phone_2": "+49987654321",
    "salutation": "Herr",
    "date_of_birth": "1990-01-01",
    "company_name": "Photo Studio GmbH",
    "legal_form": "GmbH",
    "website": "https://www.photostudio.com"
}
```

**PUT Success Response (200 OK):**
```json
{
    "first_name": "John",
    "last_name": "Doe",
    "email": "user@example.com",
    "phone": "+49123456789",
    "phone_2": "+49987654321",
    "salutation": "Herr",
    "date_of_birth": "1990-01-01",
    "company_name": "Photo Studio GmbH",
    "legal_form": "GmbH",
    "website": "https://www.photostudio.com"
}
```

**Error Responses:**
- **401 Unauthorized:** User is not authenticated
- **403 Forbidden:** User is not a registered photobooth user
- **404 Not Found:** User profile not found
- **400 Bad Request:** Invalid data provided

### Save Timestamp

Save user's software usage timestamp.

**Endpoint:** `POST /photobooth/save-timestamp/`

**Authentication Required:** Yes (Bearer Token)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Request Body:** Empty

**Success Response (200 OK):**
```json
{
    "message": "Timestamp saved successfully"
}
```

**Error Response (403 Forbidden):**
```json
{
    "error": "User is not registered as a photobooth user"
}
```

### Shop Addresses

Manage shop addresses for a photobooth user.

**Endpoint:** `GET, POST /photobooth/registered-shops/`
**Endpoint for Delete:** `DELETE /photobooth/registered-shops/<int:id>/`

**Authentication Required:** Yes (Bearer Token)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**GET Response (200 OK):**
```json
[
    {
        "id": 1,
        "name": "Photo Studio Main",
        "address": "123 Photo Street",
        "shop_phone": "+49123456789",
        "zipcode": "12345",
        "city": "Berlin",
        "latitude": 52.5200,
        "longitude": 13.4050,
        "website": "https://dknjsd......."
        "created_at": "2024-03-15T10:30:00Z"
    }
]
```

**POST Request Body:**
```json
{
    "name": "Photo Studio Branch",
    "address": "456 Camera Road",
    "shop_phone": "+49987654321",
    "zipcode": "54321",
    "city": "Munich",
    "latitude": 48.1351,
    "longitude": 11.5820
}
```

**POST Success Response (201 Created):**
```json
{
    "id": 2,
    "name": "Photo Studio Branch",
    "address": "456 Camera Road",
    "shop_phone": "+49987654321",
    "zipcode": "54321",
    "city": "Munich",
    "latitude": 48.1351,
    "longitude": 11.5820,
    "created_at": "2024-03-15T11:00:00Z"
}
```

**DELETE Success Response (200 OK):**
```json
{
    "message": "Shop address deleted successfully"
}
```

**DELETE Error Response (404 Not Found):**
```json
{
    "error": "Shop address not found"
}
```

**Notes:** 
- Employees will see shops belonging to their employer
- Only owners can register new shops (POST method)
- To delete a shop address, make a DELETE request to `/photobooth/registered-shops/{id}/` where `{id}` is the shop address ID

### Shops Nearby

Find shops within a specified radius of a given location.

**Endpoint:** `GET /photobooth/shops-nearby/`

**Authentication Required:** No

**Query Parameters:**
- `latitude` (required): Latitude of the center point (float between -90 and 90)
- `longitude` (required): Longitude of the center point (float between -180 and 180)
- `radius` (optional): Search radius in kilometers (default: 5.0)

**Example Request:** `GET /photobooth/shops-nearby/?latitude=52.5200&longitude=13.4050&radius=10.0`

**Success Response (200 OK):**
```json
[
    {
        "id": 1,
        "name": "Photo Studio Main",
        "address": "123 Photo Street",
        "shop_phone": "+49123456789",
        "zipcode": "12345",
        "city": "Berlin",
        "latitude": 52.5200,
        "longitude": 13.4050,
        "created_at": "2024-03-15T10:30:00Z",
        "distance": 0.0
    },
    {
        "id": 3,
        "name": "Photo Express",
        "address": "789 Picture Avenue",
        "shop_phone": "+49555666777",
        "zipcode": "12347",
        "city": "Berlin",
        "latitude": 52.5300,
        "longitude": 13.4150,
        "created_at": "2024-03-16T09:15:00Z",
        "distance": 1.25
    }
]
```

**Error Response (400 Bad Request):**
```json
{
    "latitude": ["Latitude must be between -90 and 90 degrees."],
    "longitude": ["Longitude must be between -180 and 180 degrees."],
    "radius": ["Radius must be a positive number."]
}
```

**Error Response (500 Internal Server Error):**
```json
{
    "error": "An error occurred: [error details]"
}
```

### Get Signature

Retrieve the system's signature for verification purposes.

**Endpoint:** `GET /photobooth/signature/`

**Authentication Required:** No

**Request Body:**
```json
{
    "operating_system": "WINDOWS" or "MAC"
}
```

**Success Response (200 OK):**
```json
{
    "Signature": "xyyxsyabscascbBDJASDBCIAsub........"
}
```

**Error Response (400 Bad Request):**
```json
{
    "error": "Invalid operating system"
}
```

### eID Token Exchange

Exchange an authorization code for an access token for eID verification.

**Endpoint:** `POST /photobooth/eid-token-exchange/`

**Authentication Required:** Yes (Bearer Token)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```


**Request Body:**
```json
{
    "code": "authorization_code_from_eid_provider"
}
```

**Success Response (200 OK):**
```json
{
    // Raw response from the eID token service
    "id_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "access_token": "XAiOiJKV1QiLCJhbGc...",
    "token_type": "Bearer"
    // Additional fields may be present depending on the eID provider
}
```

**Error Response (400 Bad Request):**
```json
{
    "error": "Authorization code is required"
}
```

**Error Response (500 Internal Server Error):**
```json
{
    "error": "Error message from the eID service or internal error"
}
```

### Seed

Generate a random 7-character hash for the user.

**Endpoint:** `GET /photobooth/seed/`

**Authentication Required:** Yes (Bearer Token)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```
**Success Response (200 OK):**
```json
{
    "seed": "abc1234"
}
```

**Error Response (401 Unauthorized):**
```json
{
    "detail": "Authentication credentials were not provided."
}
```

**Error Response (403 Forbidden):**
```json
{
    "detail": "You do not have permission to perform this action."
}
```

## Admin Management

### Create Admin User

Create a new admin user (Superuser only).

**Endpoint:** `POST /admin/create-admin/`

**Authentication Required:** Yes (Bearer Token from Superuser)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Request Body:**
```json
{
    "username": "new_admin",
    "password": "admin_password",
    "email": "admin@example.com"
}
```

**Success Response (201 Created):**
```json
{
    "message": "Admin user created successfully",
    "username": "new_admin"
}
```

**Error Response (403 Forbidden):**
```json
{
    "error": "Only superusers can create admin accounts"
}
```

### Upload Software Package

Upload a new software package version.

**Endpoint:** `POST /admin/upload-package/`

**Authentication Required:** Yes (Bearer Token from Admin)

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Request Body (multipart/form-data):**
```
version: "1.0.0"
operating_system: "WINDOWS"
file: [binary file data]
```

**Success Response (201 Created):**
```json
{
    "message": "Software package uploaded successfully"
}
```

**Error Response (400 Bad Request):**
```json
{
    "version": ["Version must be in semantic format (X.Y.Z) where X, Y, and Z are numbers"],
    "operating_system": ["Invalid choice. Valid choices are: WINDOWS, MAC"]
}
```

## Authentication

Most endpoints require authentication using JWT (JSON Web Tokens). To authenticate requests, include the access token in the Authorization header:

```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

The access token is obtained through the login endpoints. The token expires after a certain period, and you'll need to use the refresh token to get a new access token.

## Error Responses

All endpoints may return these common error responses:

**401 Unauthorized:**
```json
{
    "detail": "Authentication credentials were not provided."
}
```

**403 Forbidden:**
```json
{
    "detail": "You do not have permission to perform this action."
}
```

**500 Internal Server Error:**
```json
{
    "error": "An unexpected error occurred."
}
``` 