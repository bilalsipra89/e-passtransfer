from django.urls import path
from . import views

app_name = 'admin_portal'

urlpatterns = [
    # path('register/', views.register_admin, name='register'),  # Commented out public registration
    path('login/', views.login_admin, name='login'),
    path('upload-package/', views.upload_package, name='upload-package'),
    path('create-admin/', views.create_admin_user, name='create-admin'),  # New endpoint
] 