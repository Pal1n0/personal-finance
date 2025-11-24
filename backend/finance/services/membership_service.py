"""
Production-grade membership service for workspace membership management.
Handles role assignments, permission checks, and membership operations
with comprehensive security validation and audit logging.
"""

import logging

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from rest_framework.exceptions import PermissionDenied

from ..models import Workspace, WorkspaceAdmin, WorkspaceMembership
from .membership_cache_service import MembershipCacheService

logger = logging.getLogger(__name__)


class MembershipService:
    """
    High-performance membership management service.
    Provides atomic operations for membership lifecycle with role-based security.
    """

    def __init__(self, cache_service=None):
        """Initialize service with optional cache service dependency."""
        self.cache_service = cache_service or MembershipCacheService()

    @transaction.atomic
    def update_member_role(
        self, workspace: Workspace, target_user_id: int, new_role: str, requesting_user
    ) -> WorkspaceMembership:
        """
        Atomically update workspace member role with permission validation.

        Args:
            workspace: Workspace instance
            target_user_id: ID of user whose role is being updated
            new_role: New role ('viewer', 'editor', 'owner')
            requesting_user: User initiating the role change

        Returns:
            WorkspaceMembership: Updated membership instance

        Raises:
            PermissionDenied: If user cannot manage members
            ValidationError: If role change is invalid
        """
        logger.info(
            "Workspace member role update initiated",
            extra={
                "workspace_id": workspace.id,
                "target_user_id": target_user_id,
                "new_role": new_role,
                "requesting_user_id": requesting_user.id,
                "action": "member_role_update_start",
                "component": "MembershipService",
            },
        )

        try:
            # Validate permission to manage members using cache
            if not self._can_manage_members(workspace, requesting_user):
                logger.warning(
                    "Member role update permission denied",
                    extra={
                        "workspace_id": workspace.id,
                        "requesting_user_id": requesting_user.id,
                        "target_user_id": target_user_id,
                        "action": "member_role_update_denied",
                        "component": "MembershipService",
                        "severity": "high",
                    },
                )
                raise PermissionDenied(
                    "You don't have permission to manage workspace members"
                )

            # Validate role - ONLY member roles (admin is separate)
            valid_member_roles = ["viewer", "editor", "owner"]
            if new_role not in valid_member_roles:
                raise ValidationError(
                    f"Invalid member role. Must be one of: {', '.join(valid_member_roles)}"
                )

            # Get target membership
            try:
                target_membership = WorkspaceMembership.objects.get(
                    workspace=workspace, user_id=target_user_id
                )
            except WorkspaceMembership.DoesNotExist:
                raise ValidationError("User is not a member of this workspace")

            # Prevent changing owner role through this endpoint
            if target_membership.user == workspace.owner:
                raise ValidationError("Cannot change owner role through this endpoint")

            old_role = target_membership.role
            target_membership.role = new_role
            target_membership.save()

            # Invalidate cache for target user
            self.cache_service.invalidate_user_cache(target_user_id)

            logger.info(
                "Workspace member role updated successfully",
                extra={
                    "workspace_id": workspace.id,
                    "target_user_id": target_user_id,
                    "old_role": old_role,
                    "new_role": new_role,
                    "requesting_user_id": requesting_user.id,
                    "action": "member_role_update_success",
                    "component": "MembershipService",
                },
            )

            return target_membership

        except (PermissionDenied, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "Member role update failed unexpectedly",
                extra={
                    "workspace_id": workspace.id,
                    "target_user_id": target_user_id,
                    "requesting_user_id": requesting_user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "member_role_update_failed",
                    "component": "MembershipService",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise

    @transaction.atomic
    def remove_member(
        self, workspace: Workspace, target_user_id: int, requesting_user
    ) -> bool:
        """
        Atomically remove member from workspace with permission validation.

        Args:
            workspace: Workspace instance
            target_user_id: ID of user to remove
            requesting_user: User initiating the removal

        Returns:
            bool: True if member was removed, False if not found

        Raises:
            PermissionDenied: If user cannot manage members
            ValidationError: If removal is invalid
        """
        logger.warning(
            "Workspace member removal initiated",
            extra={
                "workspace_id": workspace.id,
                "target_user_id": target_user_id,
                "requesting_user_id": requesting_user.id,
                "action": "member_removal_start",
                "component": "MembershipService",
                "severity": "medium",
            },
        )

        try:
            # Validate permission to manage members using cache
            if not self._can_manage_members(workspace, requesting_user):
                logger.warning(
                    "Member removal permission denied",
                    extra={
                        "workspace_id": workspace.id,
                        "requesting_user_id": requesting_user.id,
                        "target_user_id": target_user_id,
                        "action": "member_removal_denied",
                        "component": "MembershipService",
                        "severity": "high",
                    },
                )
                raise PermissionDenied(
                    "You don't have permission to remove workspace members"
                )

            # Prevent removing owner
            if target_user_id == workspace.owner_id:
                raise ValidationError("Cannot remove workspace owner")

            # Get target membership
            try:
                target_membership = WorkspaceMembership.objects.get(
                    workspace=workspace, user_id=target_user_id
                )
            except WorkspaceMembership.DoesNotExist:
                logger.debug(
                    "Member not found for removal",
                    extra={
                        "workspace_id": workspace.id,
                        "target_user_id": target_user_id,
                        "action": "member_removal_skip",
                        "component": "MembershipService",
                    },
                )
                return False

            # Also deactivate any admin assignments
            WorkspaceAdmin.objects.filter(
                workspace=workspace, user_id=target_user_id
            ).update(is_active=False)

            # Remove membership
            target_membership.delete()

            # Invalidate cache for target user
            self.cache_service.invalidate_user_cache(target_user_id)

            logger.warning(
                "Workspace member removed successfully",
                extra={
                    "workspace_id": workspace.id,
                    "target_user_id": target_user_id,
                    "requesting_user_id": requesting_user.id,
                    "removed_role": target_membership.role,
                    "action": "member_removal_success",
                    "component": "MembershipService",
                    "severity": "medium",
                },
            )

            return True

        except (PermissionDenied, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "Member removal failed unexpectedly",
                extra={
                    "workspace_id": workspace.id,
                    "target_user_id": target_user_id,
                    "requesting_user_id": requesting_user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "member_removal_failed",
                    "component": "MembershipService",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise

    def get_workspace_members_with_roles(
        self, workspace: Workspace, requesting_user
    ) -> list:
        """
        Get all workspace members with their roles and permissions.

        Args:
            workspace: Workspace instance
            requesting_user: User requesting the member list

        Returns:
            list: Members with role and permission data

        Raises:
            PermissionDenied: If user cannot view workspace members
        """
        logger.debug(
            "Retrieving workspace members with roles",
            extra={
                "workspace_id": workspace.id,
                "requesting_user_id": requesting_user.id,
                "action": "workspace_members_retrieval_start",
                "component": "MembershipService",
            },
        )

        try:
            # Validate user can view workspace members using cache
            if not self._can_view_members(workspace, requesting_user):
                raise PermissionDenied(
                    "You don't have permission to view workspace members"
                )

            # OPTIMIZATION: Fetch all members and their roles in a single, optimized query.
            # This is more reliable than trying to construct the list from a single user's cache.
            memberships = WorkspaceMembership.objects.filter(
                workspace=workspace
            ).select_related("user")

            members_data = []
            for membership in memberships:
                user_id = membership.user.id
                members_data.append(
                    {
                        "user_id": user_id,
                        "username": membership.user.username,
                        "email": membership.user.email,
                        "role": membership.role,
                        "joined_at": membership.joined_at,
                        "is_owner": workspace.owner_id == user_id,
                        "is_admin": self.cache_service.is_workspace_admin(
                            user_id, workspace.id
                        ),
                    }
                )

            logger.debug(
                "Workspace members retrieved successfully",
                extra={
                    "workspace_id": workspace.id,
                    "member_count": len(members_data),
                    "action": "workspace_members_retrieval_success",
                    "component": "MembershipService",
                },
            )

            return members_data

        except PermissionDenied:
            raise
        except Exception as e:
            logger.error(
                "Workspace members retrieval failed",
                extra={
                    "workspace_id": workspace.id,
                    "requesting_user_id": requesting_user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_members_retrieval_failed",
                    "component": "MembershipService",
                    "severity": "medium",
                },
            )
            raise

    def get_user_workspace_permissions(self, user, workspace: Workspace) -> dict:
        """
        Get comprehensive permissions for user in workspace using cache.

        Args:
            user: User instance
            workspace: Workspace instance

        Returns:
            dict: Comprehensive permission set
        """
        logger.debug(
            "Retrieving user workspace permissions",
            extra={
                "user_id": user.id,
                "workspace_id": workspace.id,
                "action": "user_permissions_retrieval_start",
                "component": "MembershipService",
            },
        )

        try:
            # Get user data from cache
            user_data = self.cache_service.get_comprehensive_user_data(user.id)
            memberships = user_data.get("memberships", {})

            # Get user role from cache
            user_role = None
            workspace_membership = memberships.get(workspace.id)
            if workspace_membership:
                user_role = workspace_membership.get("role")

            # Check admin status from cache
            is_admin = self.cache_service.is_workspace_admin(user.id, workspace.id)
            is_owner = workspace.owner_id == user.id
            is_superuser = user.is_superuser

            # Calculate permissions
            permissions = self._calculate_permissions(
                user_role, is_owner, is_admin, is_superuser, workspace.is_active
            )

            logger.debug(
                "User workspace permissions retrieved successfully from cache",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace.id,
                    "user_role": user_role,
                    "is_owner": is_owner,
                    "is_admin": is_admin,
                    "permission_count": len(permissions),
                    "action": "user_permissions_retrieval_success",
                    "component": "MembershipService",
                },
            )

            return permissions

        except Exception as e:
            logger.error(
                "User workspace permissions retrieval failed",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "user_permissions_retrieval_failed",
                    "component": "MembershipService",
                    "severity": "medium",
                },
            )
            raise

    def _can_manage_members(self, workspace: Workspace, user) -> bool:
        """
        Check if user can manage workspace members using cache.

        Args:
            workspace: Workspace instance
            user: User instance

        Returns:
            bool: True if user can manage members
        """
        if user.is_superuser:
            return True

        if user.is_anonymous:
            return False

        # Use cache to check membership and role
        user_role = self.cache_service.get_user_workspace_role(user.id, workspace.id)
        is_admin = self.cache_service.is_workspace_admin(user.id, workspace.id)

        return user_role == "owner" or is_admin

    def _can_view_members(self, workspace: Workspace, user) -> bool:
        """
        Check if user can view workspace members using cache.

        Args:
            workspace: Workspace instance
            user: User instance

        Returns:
            bool: True if user can view members
        """
        if user.is_superuser:
            return True

        # Use cache to check membership
        return self.cache_service.is_user_workspace_member(user.id, workspace.id)

    def _calculate_permissions(
        self,
        user_role: str,
        is_owner: bool,
        is_admin: bool,
        is_superuser: bool,
        workspace_active: bool,
    ) -> dict:
        """
        Calculate comprehensive user permissions based on role and status.

        Args:
            user_role: User's role in workspace (viewer, editor, owner)
            is_owner: Whether user is workspace owner
            is_admin: Whether user is workspace admin (separate from membership)
            is_superuser: Whether user is superuser
            workspace_active: Whether workspace is active

        Returns:
            dict: Comprehensive permission set
        """
        # Base permissions
        can_view = workspace_active or is_owner or is_admin or is_superuser
        can_see_inactive = is_owner or is_admin or is_superuser

        # Role-based permissions
        is_editor = user_role in [
            "editor",
            "owner",
        ]  # Admin is NOT editor unless also member
        can_manage_members = (
            user_role in ["owner"] or is_admin or is_superuser
        )  # Only owners and admins

        permissions = {
            # Basic permissions
            "can_view": can_view,
            "can_see_inactive": can_see_inactive,
            # Workspace management
            "can_edit": (is_owner or is_admin) and workspace_active,
            "can_activate": (is_owner or is_admin or is_superuser)
            and not workspace_active,
            "can_deactivate": (is_owner or is_admin or is_superuser)
            and workspace_active,
            "can_soft_delete": (is_owner or is_admin or is_superuser)
            and workspace_active,
            # Member management
            "can_manage_members": can_manage_members and workspace_active,
            "can_invite": can_manage_members and workspace_active,
            "can_view_members": can_view,
            # Data management
            "can_create_transactions": (is_editor or is_admin or is_superuser)
            and workspace_active,  # Admins can create too
            "can_view_transactions": can_view,
            "can_manage_categories": (is_owner or is_admin) and workspace_active,
            # Ownership-specific permissions
            "can_hard_delete": is_owner or is_superuser,
            "can_transfer_ownership": is_owner and workspace_active,
            # Admin permissions
            "is_superuser": is_superuser,
            "is_workspace_admin": is_admin,  # Separate from membership
            "is_workspace_owner": is_owner,
            "workspace_role": user_role,  # Membership role (viewer, editor, owner)
        }

        return permissions
