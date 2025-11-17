# permissions.py
import logging

from rest_framework import permissions

logger = logging.getLogger(__name__)


class IsWorkspaceMember(permissions.BasePermission):
    """
    Production-grade workspace membership validation.

    Authorization granted to:
    - Superusers (system-wide access)
    - Workspace admins during authorized impersonation
    - Authenticated workspace members

    Security Features:
    - Trusts middleware for workspace validation and role calculation
    - Comprehensive audit logging for compliance
    - Defense in depth with middleware validation
    """

    def has_permission(self, request, view):
        """
        Validate workspace membership using middleware-calculated permissions.

        Args:
            request: HTTP request with security context
            view: Target view being accessed

        Returns:
            bool: True if user has workspace membership access
        """
        permissions_data = getattr(request, "user_permissions", {})

        # Critical: Validate workspace existence via middleware
        if not permissions_data.get("workspace_exists", False):
            logger.warning(
                "Workspace access denied - workspace not found",
                extra={
                    "user_id": request.user.id,
                    "action": "workspace_access_denied_not_found",
                    "component": "IsWorkspaceMember",
                    "severity": "medium",
                },
            )
            return False

        # Authorization hierarchy
        is_authorized = (
            permissions_data.get("is_superuser")
            or permissions_data.get("workspace_role") is not None
            or (
                permissions_data.get("is_workspace_admin")
                and getattr(request, "is_admin_impersonation", False)
            )
        )

        if is_authorized:
            logger.debug(
                "Workspace membership access granted",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": permissions_data.get("current_workspace_id"),
                    "user_role": permissions_data.get("workspace_role"),
                    "is_superuser": permissions_data.get("is_superuser"),
                    "is_admin_impersonation": getattr(
                        request, "is_admin_impersonation", False
                    ),
                    "action": "workspace_membership_granted",
                    "component": "IsWorkspaceMember",
                },
            )
        else:
            logger.warning(
                "Workspace membership access denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": permissions_data.get("current_workspace_id"),
                    "user_role": permissions_data.get("workspace_role"),
                    "action": "workspace_membership_denied",
                    "component": "IsWorkspaceMember",
                    "severity": "medium",
                },
            )

        return is_authorized


class IsWorkspaceEditor(permissions.BasePermission):
    """
    Enterprise-grade write-level authorization.

    Authorization granted to:
    - Superusers (unrestricted system access)
    - Workspace admins during authorized impersonation
    - Users with editor, admin, or owner roles

    Security Features:
    - Role-based access control with principle of least privilege
    - Comprehensive audit trail for write operations
    - Trusts middleware for workspace validation and role calculation
    """

    # Authorized write roles
    WRITE_ROLES = ["editor", "admin", "owner"]

    def has_permission(self, request, view):
        """
        Verify write-level authorization using middleware data.

        Args:
            request: HTTP request with security context
            view: Target view requiring write access

        Returns:
            bool: True if write access is authorized
        """
        permissions_data = getattr(request, "user_permissions", {})

        # Critical: Validate workspace existence via middleware
        if not permissions_data.get("workspace_exists", False):
            logger.warning(
                "Write access denied - workspace not found",
                extra={
                    "user_id": request.user.id,
                    "action": "write_access_denied_not_found",
                    "component": "IsWorkspaceEditor",
                    "severity": "medium",
                },
            )
            return False

        user_role = permissions_data.get("workspace_role")

        # Authorization hierarchy for write operations
        is_authorized = (
            permissions_data.get("is_superuser")
            or (
                permissions_data.get("is_workspace_admin")
                and getattr(request, "is_admin_impersonation", False)
            )
            or user_role in self.WRITE_ROLES
        )

        if is_authorized:
            logger.debug(
                "Write-level access granted",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": permissions_data.get("current_workspace_id"),
                    "user_role": user_role,
                    "is_superuser": permissions_data.get("is_superuser"),
                    "is_admin_impersonation": getattr(
                        request, "is_admin_impersonation", False
                    ),
                    "action": "write_access_granted",
                    "component": "IsWorkspaceEditor",
                },
            )
        else:
            logger.warning(
                "Write-level access denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": permissions_data.get("current_workspace_id"),
                    "user_role": user_role,
                    "required_roles": self.WRITE_ROLES,
                    "action": "write_access_denied",
                    "component": "IsWorkspaceEditor",
                    "severity": "medium",
                },
            )

        return is_authorized


class IsWorkspaceOwner(permissions.BasePermission):
    """
    Production-ready ownership-level authorization.

    Authorization Hierarchy (highest to lowest):
    - Superusers (system-wide administrative access)
    - Workspace admins (delegated administrative privileges)
    - Workspace owners (direct ownership rights)

    Security Features:
    - Role inheritance - higher roles include lower role permissions
    - Comprehensive audit logging for ownership-level operations
    - Trusts middleware for workspace validation and role calculation
    """

    def has_permission(self, request, view):
        """
        Validate ownership or higher-level authorization.

        Args:
            request: HTTP request with security context
            view: Target view requiring ownership privileges

        Returns:
            bool: True if user has owner-level access
        """
        permissions_data = getattr(request, "user_permissions", {})

        # Critical: Validate workspace existence via middleware
        if not permissions_data.get("workspace_exists", False):
            logger.warning(
                "Ownership access denied - workspace not found",
                extra={
                    "user_id": request.user.id,
                    "action": "ownership_access_denied_not_found",
                    "component": "IsWorkspaceOwner",
                    "severity": "medium",
                },
            )
            return False

        user_role = permissions_data.get("workspace_role")

        # Ownership authorization hierarchy
        is_authorized = (
            permissions_data.get("is_superuser")
            or permissions_data.get("is_workspace_admin")
            or user_role == "owner"
        )

        if is_authorized:
            logger.debug(
                "Ownership-level access granted",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": permissions_data.get("current_workspace_id"),
                    "user_role": user_role,
                    "is_superuser": permissions_data.get("is_superuser"),
                    "is_workspace_admin": permissions_data.get("is_workspace_admin"),
                    "action": "ownership_access_granted",
                    "component": "IsWorkspaceOwner",
                },
            )
        else:
            logger.warning(
                "Ownership-level access denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": permissions_data.get("current_workspace_id"),
                    "user_role": user_role,
                    "required_role": "owner",
                    "action": "ownership_access_denied",
                    "component": "IsWorkspaceOwner",
                    "severity": "high",
                },
            )

        return is_authorized

    def has_object_permission(self, request, view, obj):
        """
        Object-level ownership permission validation.

        Args:
            request: HTTP request with security context
            view: Target view being accessed
            obj: Target object for permission check

        Returns:
            bool: True if ownership access is granted for specific object
        """
        # Trust middleware for object-level permissions
        return self.has_permission(request, view)


class IsWorkspaceAdmin(permissions.BasePermission):
    """
    System-level workspace administration authorization.

    Authorization exclusively granted to:
    - Superusers (full system administration rights)
    - Designated workspace admins (delegated system-level privileges)

    Security Context:
    - Gatekeeps sensitive administrative operations
    - Controls workspace assignment management
    - Manages system-wide configurations
    - Enforces separation of duties
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
        permissions_data = getattr(request, "user_permissions", {})

        # System administration authorization
        is_authorized = permissions_data.get("is_superuser") or permissions_data.get(
            "is_workspace_admin"
        )

        if is_authorized:
            logger.debug(
                "System administration access granted",
                extra={
                    "user_id": request.user.id,
                    "is_superuser": permissions_data.get("is_superuser"),
                    "is_workspace_admin": permissions_data.get("is_workspace_admin"),
                    "action": "system_admin_access_granted",
                    "component": "IsWorkspaceAdmin",
                },
            )
        else:
            logger.warning(
                "System administration access denied",
                extra={
                    "user_id": request.user.id,
                    "is_superuser": permissions_data.get("is_superuser"),
                    "is_workspace_admin": permissions_data.get("is_workspace_admin"),
                    "action": "system_admin_access_denied",
                    "component": "IsWorkspaceAdmin",
                    "severity": "high",
                },
            )

        return is_authorized


class IsSuperuser(permissions.IsAdminUser):
    """
    Enterprise superuser authorization with enhanced logging.

    Authorization exclusively granted to authenticated superusers.
    Provides comprehensive audit trail for superuser operations.
    """

    def has_permission(self, request, view):
        """
        Verify superuser authorization with audit logging.

        Args:
            request: HTTP request with security context
            view: Target view requiring superuser access

        Returns:
            bool: True if user is authenticated superuser
        """
        is_superuser = bool(request.user and request.user.is_superuser)

        if is_superuser:
            logger.debug(
                "Superuser access granted",
                extra={
                    "user_id": request.user.id,
                    "action": "superuser_access_granted",
                    "component": "IsSuperuser",
                },
            )
        else:
            logger.warning(
                "Superuser access denied",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "action": "superuser_access_denied",
                    "component": "IsSuperuser",
                    "severity": "high",
                },
            )

        return is_superuser
