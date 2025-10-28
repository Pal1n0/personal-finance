# finance/permissions.py
from rest_framework import permissions

class IsOwner(permissions.BasePermission):
    """
    Permission for control, that user have access only to his own data.
    """
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user