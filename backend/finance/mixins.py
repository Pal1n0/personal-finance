# finance/mixins.py
from rest_framework import serializers
from .models import WorkspaceMembership
from rest_framework.exceptions import ValidationError as DRFValidationError

class TargetUserMixin:
    """
    Mixin for serializers that need automatic user assignment.
    Uses request.target_user for admin impersonation support.
    """
    def validate(self, attrs):
        """
        Automatically assign user from request.target_user.
        
        Args:
            attrs: Serializer data
            
        Returns:
            dict: Updated data with user assignment
        """
        attrs = super().validate(attrs)
        request = self.context.get('request')
        if request and hasattr(request, 'target_user'):
            attrs['user'] = request.target_user
        return attrs

class WorkspaceMembershipMixin:
    """
    Mixin for caching workspace membership data in request context
    to avoid duplicate database queries.
    """
    
    def _get_user_memberships(self, request):
        """
        Get or cache user memberships in request context.
        
        Args:
            request: HTTP request object
            
        Returns:
            dict: Cached memberships {workspace_id: membership}
        """
        if not hasattr(request, '_cached_user_memberships'):
            # Cache all user memberships for this request
            memberships = WorkspaceMembership.objects.filter(user=request.user)
            request._cached_user_memberships = {m.workspace_id: m for m in memberships}
        
        return request._cached_user_memberships
    
    def _get_membership_for_workspace(self, obj, request):
        """
        Get user membership for specific workspace from cache.
        
        Args:
            obj: Workspace instance
            request: HTTP request object
            
        Returns:
            WorkspaceMembership or None: User's membership in workspace
        """
        memberships = self._get_user_memberships(request)
        return memberships.get(obj.id)
    
class CategoryWorkspaceMixin:
    """
    Mixin for category serializers to validate workspace consistency.
    Prevents cross-workspace access during admin impersonation.
    """
    
    def validate(self, data):
        """
        Validate category belongs to current workspace.
        
        Ensures category version matches the workspace context to prevent
        cross-workspace access during admin impersonation.
        
        Args:
            data: Category data to validate
            
        Returns:
            dict: Validated category data
            
        Raises:
            DRFValidationError: If workspace validation fails
        """
        request = self.context.get('request')
        if request and hasattr(request, 'workspace'):
            workspace = request.workspace
            version = data.get('version') or (self.instance.version if self.instance else None)
            
            if version and version.workspace != workspace:
                raise DRFValidationError("Category version does not belong to this workspace")
        
        return data