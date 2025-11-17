from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin

User = get_user_model()


class CustomUserAdmin(UserAdmin):
    PROTECTED_SUPERUSER_EMAILS = settings.PROTECTED_SUPERUSER_EMAILS

    def save_model(self, request, obj, form, change):
        if obj.is_superuser and obj.email not in self.PROTECTED_SUPERUSER_EMAILS:
            messages.error(request, "Superuser can only use protected system emails.")
            return
        super().save_model(request, obj, form, change)


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
