from django.contrib import admin
from .models import SoftwarePackage
from photobooth.models import PhotoboothUser, UserTimestamp, ShopAddress
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count

@admin.register(SoftwarePackage)
class SoftwarePackageAdmin(admin.ModelAdmin):
    list_display = ('version', 'operating_system', 'is_active', 'uploaded_by', 'uploaded_at', 'file_download')
    list_filter = ('is_active', 'operating_system', 'uploaded_at')
    search_fields = ('version', 'uploaded_by__username')
    ordering = ('-uploaded_at',)
    readonly_fields = ('uploaded_at',)

    def file_download(self, obj):
        if obj.file:
            return format_html('<a href="{}">Download</a>', obj.file.url)
        return "-"
    file_download.short_description = 'Download'

@admin.register(PhotoboothUser)
class PhotoboothUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'full_name', 'email', 'phone', 'user_type', 'manager_or_employer_name', 
                   'company_name', 'is_licensed', 'created_at', 'last_active', 'total_timestamps')
    list_filter = ('user_type', 'licensed', 'created_at', 'updated_at', 'salutation')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'phone', 
                    'phone_2', 'company_name', 'legal_form', 'owner_code', 'user__email')
    readonly_fields = ('created_at', 'updated_at', 'license_hash', 'owner_code')
    
    def username(self, obj):
        return obj.user.username
    
    def email(self, obj):
        return obj.user.email
    
    def full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"
    
    def is_licensed(self, obj):
        return obj.licensed
    is_licensed.boolean = True
    is_licensed.short_description = 'Licensed'
    
    def manager_or_employer_name(self, obj):
        if obj.user_type == 'employee' and obj.employer:
            return f"{obj.employer.user.username} (Manager)"
        elif obj.user_type == 'manager' and obj.employer:
            return f"{obj.employer.user.username} (Owner)"
        return "-"
    manager_or_employer_name.short_description = 'Employer'
    
    def last_active(self, obj):
        last_timestamp = UserTimestamp.objects.filter(user=obj).order_by('-timestamp').first()
        if last_timestamp:
            return last_timestamp.timestamp
        return "-"
    
    def total_timestamps(self, obj):
        return UserTimestamp.objects.filter(user=obj).count()
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'employer__user')
    
    total_timestamps.short_description = 'Activity Count'

@admin.register(ShopAddress)
class ShopAddressAdmin(admin.ModelAdmin):
    list_display = ('name', 'city', 'shop_phone', 'user_username', 'created_at', 'latitude', 'longitude', 'website')
    list_filter = ('city', 'created_at')
    search_fields = ('name', 'address', 'city', 'shop_phone', 'photobooth_user__user__username')
    readonly_fields = ('created_at', 'updated_at')

    def user_username(self, obj):
        return obj.photobooth_user.user.username
    user_username.short_description = 'Username'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('photobooth_user__user')

@admin.register(UserTimestamp)
class UserTimestampAdmin(admin.ModelAdmin):
    list_display = ('user_username', 'timestamp', 'software_version')
    list_filter = ('timestamp', 'software_version')
    search_fields = ('user__user__username', 'software_version')
    ordering = ('-timestamp',)
    
    def user_username(self, obj):
        return obj.user.user.username
    user_username.short_description = 'Username'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user__user')
