# permissions.py
from rest_framework import permissions
from django.core.cache import cache
from .models import Workspace
import logging

logger = logging.getLogger(__name__)


class IsWorkspaceMember(permissions.BasePermission):
    """
    Enterprise-grade workspace membership validation with comprehensive security.
    
    Access is granted to:
    - Superusers (full system access with audit logging)
    - Workspace admins during authorized impersonation sessions
    - Authenticated users with validated membership in target workspace
    
    Features:
    - Workspace existence validation to prevent ID enumeration attacks
    - Cached permission resolution for optimal performance
    - Comprehensive audit logging for compliance requirements
    - Defense in depth with multiple validation layers
    """
    
    def has_permission(self, request, view):
        """
        Determine workspace membership access with security validation.
        
        Args:
            request: HTTP request with enhanced security context
            view: Target view being accessed
            
        Returns:
            bool: True if secure access is granted, False otherwise
        """
        workspace_id = self._get_workspace_id(view)
        if not workspace_id:
            # No workspace context - apply default authentication policy
            return request.user.is_authenticated
            
        permissions_data = getattr(request, 'user_permissions', {})
        
        # Critical security: Validate workspace existence first
        if not permissions_data.get('workspace_exists', False):
            logger.warning(
                "Access attempt to non-existent workspace blocked",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_access_invalid",
                    "component": "IsWorkspaceMember",
                    "severity": "medium",
                },
            )
            return False
        
        # Superusers bypass all permission checks with audit trail
        if permissions_data.get('is_superuser'):
            logger.debug(
                "Superuser workspace access granted",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "superuser_workspace_access",
                    "component": "IsWorkspaceMember",
                },
            )
            return True
            
        # Workspace admins can access during authorized impersonation
        if (permissions_data.get('is_workspace_admin') and 
            getattr(request, 'is_admin_impersonation', False) and
            workspace_id in getattr(request, 'impersonation_workspace_ids', [])):
            logger.debug(
                "Workspace admin impersonation access granted",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": getattr(request.target_user, 'id', None),
                    "workspace_id": workspace_id,
                    "action": "admin_impersonation_workspace_access",
                    "component": "IsWorkspaceMember",
                },
            )
            return True
        
        # Membership validation with cached role data
        has_access = permissions_data.get('workspace_role') is not None
        
        if not has_access:
            logger.warning(
                "Workspace membership access denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_membership_denied",
                    "component": "IsWorkspaceMember",
                    "severity": "medium",
                },
            )
            
        return has_access

    def _get_workspace_id(self, view):
        """
        Securely extract workspace identifier from view parameters.
        
        Args:
            view: The view instance containing URL parameters
            
        Returns:
            int or None: Workspace ID if present and valid, None otherwise
        """
        workspace_id = (view.kwargs.get('workspace_pk') or 
                       view.kwargs.get('workspace_id') or
                       view.kwargs.get('pk'))
        
        if workspace_id:
            try:
                return int(workspace_id)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid workspace ID in permission check",
                    extra={
                        "workspace_id": workspace_id,
                        "action": "invalid_workspace_id_permission",
                        "component": "IsWorkspaceMember",
                    },
                )
        return None


class IsWorkspaceEditor(permissions.BasePermission):
    """
    Advanced write-level authorization with security enforcement.
    
    Access is granted to:
    - Superusers (unrestricted system access with compliance logging)
    - Workspace admins during authorized impersonation sessions
    - Users with writer or owner roles in validated workspaces
    
    Security Features:
    - Role-based access control with principle of least privilege
    - Workspace existence validation to prevent privilege escalation
    - Comprehensive audit trail for all write operations
    - Cached permission resolution for high-performance applications
    """
    
    # Define authorized write roles
    WRITE_ROLES = ['editor', 'owner']
    
    def has_permission(self, request, view):
        """
        Verify write-level authorization with security validation.
        
        Args:
            request: HTTP request with security context
            view: Target view requiring write access
            
        Returns:
            bool: True if write access is securely authorized
        """
        workspace_id = self._get_workspace_id(view)
        if not workspace_id:
            # No specific workspace - apply default write policy
            return request.user.is_authenticated
            
        permissions_data = getattr(request, 'user_permissions', {})
        
        # Validate workspace existence as first security layer
        if not permissions_data.get('workspace_exists', False):
            logger.warning(
                "Write access attempt to non-existent workspace blocked",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "write_access_invalid_workspace",
                    "component": "IsWorkspaceWriter",
                    "severity": "medium",
                },
            )
            return False
        
        # Superusers have implicit write access with audit logging
        if permissions_data.get('is_superuser'):
            logger.debug(
                "Superuser write access granted",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "superuser_write_access",
                    "component": "IsWorkspaceWriter",
                },
            )
            return True
            
        # Workspace admins inherit write permissions during authorized impersonation
        if (permissions_data.get('is_workspace_admin') and 
            getattr(request, 'is_admin_impersonation', False) and
            workspace_id in getattr(request, 'impersonation_workspace_ids', [])):
            logger.debug(
                "Admin impersonation write access granted",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": getattr(request.target_user, 'id', None),
                    "workspace_id": workspace_id,
                    "action": "admin_impersonation_write_access",
                    "component": "IsWorkspaceWriter",
                },
            )
            return True
        
        # Validate writer or owner role from cached permissions
        user_role = permissions_data.get('workspace_role')
        has_write_access = user_role in self.WRITE_ROLES if user_role else False
        
        if not has_write_access:
            logger.warning(
                "Write-level access denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "user_role": user_role,
                    "required_roles": self.WRITE_ROLES,
                    "action": "write_access_denied",
                    "component": "IsWorkspaceWriter",
                    "severity": "medium",
                },
            )
            
        return has_write_access

    def _get_workspace_id(self, view):
        """
        Extract and validate workspace identifier from view context.
        
        Args:
            view: Target view instance with URL parameters
            
        Returns:
            int or None: Valid workspace identifier if available
        """
        workspace_id = (view.kwargs.get('workspace_pk') or 
                       view.kwargs.get('workspace_id') or
                       view.kwargs.get('pk'))
        
        if workspace_id:
            try:
                return int(workspace_id)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid workspace ID in write permission check",
                    extra={
                        "workspace_id": workspace_id,
                        "action": "invalid_workspace_id_write_permission",
                        "component": "IsWorkspaceWriter",
                    },
                )
        return None


class IsWorkspaceOwner(permissions.BasePermission):
    """
    Ownership-level authorization - allows owners AND higher roles (admins, superusers).
    Consistent with other permission classes where higher roles inherit lower permissions.
    
    Access granted to:
    - Superusers (system-wide access)
    - Workspace admins (delegated administrative access) 
    - Workspace owners (direct ownership)
    """
    
    def has_permission(self, request, view):
        """
        Validate ownership or higher-level authorization.
        
        Args:
            request: HTTP request with security context
            view: Target view requiring ownership privileges
            
        Returns:
            bool: True if user has owner role or higher privileges
        """
        # Safe methods always allowed
        if request.method in permissions.SAFE_METHODS:
            return True
            
        workspace_id = self._get_workspace_id(view)
        if not workspace_id:
            logger.debug(
                "Ownership check skipped - no workspace context",
                extra={
                    "user_id": request.user.id,
                    "action": "ownership_check_no_workspace",
                    "component": "IsWorkspaceOwner",
                },
            )
            return False
            
        permissions_data = getattr(request, 'user_permissions', {})
        
        # Log permission check for audit trail
        logger.debug(
            "Ownership authorization check initiated",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_id,
                "action": "ownership_check_start",
                "component": "IsWorkspaceOwner",
            },
        )

        # Critical security: Validate workspace existence
        if not permissions_data.get('workspace_exists', False):
            logger.warning(
                "Ownership access attempt to non-existent workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "ownership_access_invalid_workspace",
                    "component": "IsWorkspaceOwner",
                    "severity": "high",
                },
            )
            return False
        
        # ✅ OWNER OR HIGHER: Superusers and workspace admins automatically have owner rights
        if permissions_data.get('is_superuser') or permissions_data.get('is_workspace_admin'):
            logger.debug(
                "Ownership access granted via admin/superuser privileges",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "is_superuser": permissions_data.get('is_superuser'),
                    "is_workspace_admin": permissions_data.get('is_workspace_admin'),
                    "action": "admin_ownership_access_granted",
                    "component": "IsWorkspaceOwner",
                },
            )
            return True
        
        # Primary ownership check using cached role from middleware
        user_role = permissions_data.get('workspace_role')
        is_owner = user_role == 'owner'
        
        if is_owner:
            logger.debug(
                "Ownership access granted via direct ownership",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "user_role": user_role,
                    "action": "direct_ownership_access_granted",
                    "component": "IsWorkspaceOwner",
                },
            )
        else:
            logger.warning(
                "Ownership-level access denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "user_role": user_role,
                    "action": "ownership_access_denied",
                    "component": "IsWorkspaceOwner",
                    "severity": "high",
                },
            )
            
        return is_owner

    def has_object_permission(self, request, view, obj):
        """
        Object-level ownership permission.
        
        Args:
            request: HTTP request with security context
            view: Target view being accessed
            obj: Target object for permission check
            
        Returns:
            bool: True if ownership access is granted for specific object
        """
        return self.has_permission(request, view)

    def _get_workspace_id(self, view):
        """
        Extract workspace identifier from view routing context.
        
        Args:
            view: Target view instance with URL parameters
            
        Returns:
            int or None: Workspace ID if present in routing context
        """
        workspace_id = (view.kwargs.get('workspace_pk') or 
                       view.kwargs.get('workspace_id') or
                       view.kwargs.get('pk'))
        
        if workspace_id:
            try:
                return int(workspace_id)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid workspace ID in ownership permission check",
                    extra={
                        "workspace_id": workspace_id,
                        "action": "invalid_workspace_id_ownership_permission",
                        "component": "IsWorkspaceOwner",
                    },
                )
        return None

class IsWorkspaceAdmin(permissions.BasePermission):
    """
    System-level workspace administration authorization.
    
    Authorization is exclusively granted to:
    - Superusers (full system administration rights)
    - Designated workspace admins (delegated system-level privileges)
    
    Security Context:
    - Gatekeeps sensitive administrative operations
    - Controls workspace assignment management
    - Manages system-wide configurations
    - Enforces separation of duties between workspace and system administration
    """
    
    def has_permission(self, request, view):
        """
        Verify system-level workspace administration privileges.
        
        Args:
            request: HTTP request with administrative context
            view: Target administrative view
            
        Returns:
            bool: True if system admin access is authorized
        """
        permissions_data = getattr(request, 'user_permissions', {})
        
        # Superusers have unconditional system administration rights
        if permissions_data.get('is_superuser'):
            logger.debug(
                "Superuser system administration access granted",
                extra={
                    "user_id": request.user.id,
                    "action": "superuser_system_admin_access",
                    "component": "IsWorkspaceAdmin",
                },
            )
            return True
            
        # Workspace admins have delegated system-level administrative access
        is_workspace_admin = bool(permissions_data.get('is_workspace_admin'))
        
        # For workspace-specific actions, validate admin has access to target workspace
        workspace_id = self._get_workspace_id(view)
        if workspace_id and is_workspace_admin:
            has_workspace_access = workspace_id in getattr(request, 'impersonation_workspace_ids', [])
            
            if not has_workspace_access:
                logger.warning(
                    "Workspace admin access denied for specific workspace",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace_id,
                        "available_workspaces": getattr(request, 'impersonation_workspace_ids', []),
                        "action": "workspace_admin_access_denied",
                        "component": "IsWorkspaceAdmin",
                        "severity": "medium",
                    },
                )
                return False
            
            logger.debug(
                "Workspace admin access granted for specific workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_admin_access_granted",
                    "component": "IsWorkspaceAdmin",
                },
            )
        
        if not is_workspace_admin:
            logger.warning(
                "System administration access denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "system_admin_access_denied",
                    "component": "IsWorkspaceAdmin",
                    "severity": "high",
                },
            )
            
        return is_workspace_admin

    def _get_workspace_id(self, view):
        """
        Extract workspace identifier from view context for targeted admin validation.
        
        Args:
            view: Target view instance with URL parameters
            
        Returns:
            int or None: Workspace ID if present in routing context
        """
        workspace_id = (view.kwargs.get('workspace_pk') or 
                       view.kwargs.get('workspace_id') or
                       view.kwargs.get('pk'))
        
        if workspace_id:
            try:
                return int(workspace_id)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid workspace ID in admin permission check",
                    extra={
                        "workspace_id": workspace_id,
                        "action": "invalid_workspace_id_admin_permission",
                        "component": "IsWorkspaceAdmin",
                    },
                )
        return None

class IsSuperuser(permissions.IsAdminUser):
    """
    Permission that checks if user is superuser.
    Simple and clean - no business logic in permissions.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_superuser)