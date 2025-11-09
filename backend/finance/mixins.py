"""
Enterprise-grade mixins for Django REST Framework serializers.
Provides request-level caching, security validation, and admin impersonation support.
"""

import logging
from rest_framework.exceptions import ValidationError as DRFValidationError
from .models import WorkspaceMembership

logger = logging.getLogger(__name__)


class TargetUserMixin:
    """
    Mixin for automatic user assignment from request.target_user.
    Supports secure admin impersonation with comprehensive audit logging.
    """

    def validate(self, attrs):
        """
        Automatically assign user and workspace from request context.
        
        Returns:
            dict: Updated attributes with user and workspace assignment
        """
        attrs = super().validate(attrs)
        request = self.context.get('request')
        
        if request:
            # Assign user from target_user (impersonation support)
            if hasattr(request, 'target_user'):
                attrs['user'] = request.target_user
                logger.debug(
                    "User assignment from target_user completed",
                    extra={
                        "target_user_id": request.target_user.id,
                        "impersonation_active": getattr(request, 'is_admin_impersonation', False),
                        "action": "target_user_assignment",
                        "component": "TargetUserMixin",
                    },
                )
            
            # Assign workspace from request context
            if hasattr(request, 'workspace') and 'workspace' not in attrs:
                attrs['workspace'] = request.workspace
                logger.debug(
                    "Workspace assignment from request completed",
                    extra={
                        "workspace_id": request.workspace.id,
                        "action": "workspace_assignment", 
                        "component": "TargetUserMixin",
                    },
                )
        
        return attrs


class WorkspaceMembershipMixin:
    """
    Advanced mixin for cached workspace membership data access.
    Eliminates duplicate database queries through optimized request-level caching.
    """

    def _get_user_memberships(self, request):
        """
        Retrieve cached membership data from request context with fallback strategy.
        
        Returns:
            dict: Cached workspace memberships {workspace_id: role}
        """
        if not hasattr(request, '_cached_user_memberships'):
            target_user = getattr(request, 'target_user', request.user)
            memberships = WorkspaceMembership.objects.filter(
                user=target_user
            ).select_related('workspace') 
            
            request._cached_user_memberships = {m.workspace_id: m.role for m in memberships}
            
            logger.debug(
                "Membership cache initialized from database",
                extra={
                    "user_id": request.user.id,
                    "cached_workspaces_count": len(request._cached_user_memberships),
                    "action": "membership_cache_initialized",
                    "component": "WorkspaceMembershipMixin",
                },
            )
        
        return request._cached_user_memberships

    def _get_membership_for_workspace(self, obj, request):
        """
        Get user role for specific workspace from optimized cache.
        
        Returns:
            str or None: User's role in the workspace
        """

        # 1. Check if user is owner of this workspace
        if request.user == obj.owner:
            logger.debug(
                "Workspace role: user is owner",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "user_role": 'owner',
                    "action": "workspace_owner_role",
                    "component": "WorkspaceMembershipMixin",
                },
            )
            return 'owner'

        # 2. Check membership in WorkspaceMembership 
        memberships = self._get_user_memberships(request)
        role = memberships.get(obj.id)
        
        if role:
            logger.debug(
                "Workspace role retrieved from cache",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "user_role": role,
                    "action": "workspace_role_cache_hit",
                    "component": "WorkspaceMembershipMixin",
                },
            )
        
        return role


class CategoryWorkspaceMixin:
    """
    Security-focused mixin for category workspace validation.
    Prevents cross-workspace access during admin impersonation sessions.
    """

    def validate(self, data):
        """
        Validate category belongs to current workspace context.
        
        Raises:
            DRFValidationError: If workspace validation fails
        """
        request = self.context.get('request')
        
        if request and hasattr(request, 'workspace'):
            workspace = request.workspace
            version = data.get('version') or (self.instance.version if self.instance else None)
            
            if version and version.workspace_id != workspace.id:
                logger.warning(
                    "Category workspace security violation prevented",
                    extra={
                        "category_version_id": version.id,
                        "version_workspace_id": version.workspace_id,
                        "request_workspace_id": workspace.id,
                        "impersonation_active": getattr(request, 'is_admin_impersonation', False),
                        "action": "cross_workspace_access_blocked",
                        "component": "CategoryWorkspaceMixin",
                        "severity": "high",
                    },
                )
                raise DRFValidationError("Category version does not belong to this workspace")
        
        return data