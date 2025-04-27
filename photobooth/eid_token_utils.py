import os
import requests
import certifi
import tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from django.conf import settings



def get_access_token(authorization_code):
    """
    Exchange an authorization code for an access token using OAuth 2.0
    
    Args:
        authorization_code (str): The authorization code received from the authorization server
        
    Returns:
        str: The raw response from the token endpoint
    """
    # Get credentials from environment variables
    token_endpoint = settings.EID_TOKEN_ENDPOINT
    client_id = settings.EID_CLIENT_ID
    client_secret = settings.EID_CLIENT_SECRET
    redirect_uri = settings.EID_REDIRECT_URI
    cert_path = settings.EID_CERT_PATH
    cert_password = settings.EID_CERT_PASSWORD
    
    # Prepare the request payload
    payload = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret
    }
    
    try:
        # Load the PKCS12 certificate using cryptography
        with open(cert_path, 'rb') as f:
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                f.read(),
                cert_password.encode('utf-8')
            )
        
        # Create temporary files for certificate and key
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as cert_file, \
             tempfile.NamedTemporaryFile(delete=False, mode='w') as key_file:
            
            # Write certificate and key to temporary files
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8'))
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'))
            
            cert_path = cert_file.name
            key_path = key_file.name
        
        response = requests.post(
            token_endpoint,
            data=payload,
            cert=(cert_path, key_path),
            verify=certifi.where()
        )
        
        # Clean up temporary files
        os.unlink(cert_path)
        os.unlink(key_path)
        
        # Return the raw response text
        return response.text
    
    except Exception as e:
        raise e