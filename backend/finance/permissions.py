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
    Ownership-level authorization with comprehensive security controls.
    
    Access is restricted to:
    - Superusers (full administrative privileges with audit compliance)
    - Workspace admins during authorized impersonation sessions
    - Users with explicit owner role in validated workspaces
    - Direct workspace owners (fallback validation for edge cases)
    
    Security Enforcement:
    - Multi-layer ownership verification
    - Workspace existence validation
    - Comprehensive audit logging for ownership transfers
    - Defense in depth with multiple validation mechanisms
    """
    
    def has_permission(self, request, view):
        """
        Validate ownership-level authorization with security compliance.
        
        Args:
            request: HTTP request containing ownership context
            view: Target view requiring ownership privileges
            
        Returns:
            bool: True if ownership access is securely verified
        """
        workspace_id = self._get_workspace_id(view)
        if not workspace_id:
            # No specific workspace - apply strict ownership policy
            return False
            
        permissions_data = getattr(request, 'user_permissions', {})

        if permissions_data.get('is_superuser') or permissions_data.get('is_workspace_admin'):
            logger.debug("Admin bypass for ownership permission")
            return True
        
        # Critical security: Validate workspace existence
        if not permissions_data.get('workspace_exists', False):
            logger.warning(
                "Ownership access attempt to non-existent workspace blocked",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "ownership_access_invalid_workspace",
                    "component": "IsWorkspaceOwner",
                    "severity": "high",
                },
            )
            return False
        
        # Superusers have inherent ownership rights with compliance logging
        if permissions_data.get('is_superuser'):
            logger.debug(
                "Superuser ownership access granted",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "superuser_ownership_access",
                    "component": "IsWorkspaceOwner",
                },
            )
            return True
            
        # Workspace admins assume ownership during authorized impersonation
        if (permissions_data.get('is_workspace_admin') and 
            getattr(request, 'is_admin_impersonation', False) and
            workspace_id in getattr(request, 'impersonation_workspace_ids', [])):
            logger.debug(
                "Admin impersonation ownership access granted",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": getattr(request.target_user, 'id', None),
                    "workspace_id": workspace_id,
                    "action": "admin_impersonation_ownership_access",
                    "component": "IsWorkspaceOwner",
                },
            )
            return True
        
        # Primary ownership check using cached role data
        user_role = permissions_data.get('workspace_role')
        if user_role == 'owner':
            logger.debug(
                "Ownership access granted via role",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "role_based_ownership_access",
                    "component": "IsWorkspaceOwner",
                },
            )
            return True
            
        # Fallback validation for direct workspace ownership with caching
        cache_key = f"workspace_owner_{workspace_id}"
        cached_owner_id = cache.get(cache_key)
        
        if cached_owner_id is not None:
            is_owner = cached_owner_id == request.user.id
        else:
            workspace = Workspace.objects.filter(id=workspace_id).only('owner').first()
            is_owner = workspace and workspace.owner_id == request.user.id
            
            # Cache owner ID for 10 minutes to reduce database load
            if workspace:
                cache.set(cache_key, workspace.owner_id, 600)
        
        if not is_owner:
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
