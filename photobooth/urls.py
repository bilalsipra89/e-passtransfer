from django.urls import path
from . import views
from .views import UserRegistrationView, UserPasswordResetView, UserProfileView, UserInviteView, ShopAddressView



app_name = 'photobooth'

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register_user'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('resend-otp/', views.resend_otp, name='resend_otp'),
    path('verify-license/', views.verify_license, name='verify-license'),
    path('get-download-url/', views.get_download_url, name='get-download-url'),
    path('login/', views.login_user, name='login'),
    path('web-login/', views.web_login, name='web-login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('profile/change-password/', views.change_password, name='change-password'),
    path('invite-employee/', UserInviteView.as_view(), name='invite-user'),
    path('save-timestamp/', views.save_timestamp, name='save-timestamp'),
    path('registered-shops/', ShopAddressView.as_view(), name='shop-addresses'),
    path('registered-shops/<int:pk>/', ShopAddressView.as_view(), name='shop-address-detail'),
    path('shops-nearby/', views.shops_nearby, name='shops-nearby'),
    path('signature/', views.signature, name='signature'),
    path('request-password-reset/', UserPasswordResetView.as_view(), name='request-password-reset'),
    path('eid-token-exchange/', views.eid_token_exchange, name='eid-token-exchange'),
    path('seed/', views.seed, name='seed'),
    path('mac-otp-verification/', views.verify_mac_otp, name='verify-mac-otp'),
    
] 