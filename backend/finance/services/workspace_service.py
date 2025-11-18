"""
Production-grade workspace service for complex workspace operations.
Handles workspace lifecycle, ownership transfers, and administrative operations
with comprehensive security validation and audit logging.
"""

import logging

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import DatabaseError, transaction
from rest_framework.exceptions import PermissionDenied, ValidationError

from ..models import (Transaction, Workspace, WorkspaceAdmin,
                      WorkspaceMembership)
from .membership_cache_service import MembershipCacheService

logger = logging.getLogger(__name__)


class WorkspaceService:
    """
    High-performance workspace management service.
    Provides atomic operations for workspace lifecycle with comprehensive security validation.
    """

    def __init__(self):
        """Initialize service with dependency injection."""
        self.membership_service = MembershipCacheService()

    @transaction.atomic
    def create_workspace(self, name: str, description: str, owner) -> Workspace:
        """
        Atomically create workspace with owner membership synchronization.

        Args:
            name: Workspace name (2-100 characters)
            description: Optional workspace description
            owner: User instance who will own the workspace

        Returns:
            Workspace: Created workspace instance

        Raises:
            ValidationError: If workspace data is invalid
            DatabaseError: If database operation fails
        """
        logger.info(
            "Workspace creation initiated",
            extra={
                "owner_id": owner.id,
                "workspace_name": name,
                "action": "workspace_creation_start",
                "component": "WorkspaceService",
            },
        )

        try:
            # Validate input data
            self._validate_workspace_name(name)

            # Create workspace instance
            workspace = Workspace.objects.create(
                name=name.strip(), description=description, owner=owner
            )

            # Synchronize owner to membership (handles atomic rollback on failure)
            self._sync_owner_to_membership(workspace, is_new=True)

            logger.info(
                "Workspace created successfully",
                extra={
                    "workspace_id": workspace.id,
                    "owner_id": owner.id,
                    "workspace_name": workspace.name,
                    "action": "workspace_creation_success",
                    "component": "WorkspaceService",
                },
            )

            return workspace

        except ValidationError:
            logger.warning(
                "Workspace creation failed - validation error",
                extra={
                    "owner_id": owner.id,
                    "workspace_name": name,
                    "action": "workspace_creation_validation_failed",
                    "component": "WorkspaceService",
                    "severity": "medium",
                },
            )
            raise

        except DatabaseError as e:
            logger.error(
                "Workspace creation failed - database error",
                extra={
                    "owner_id": owner.id,
                    "workspace_name": name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_creation_database_error",
                    "component": "WorkspaceService",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise

    @transaction.atomic
    def change_ownership(
        self,
        workspace: Workspace,
        new_owner_id: int,
        changed_by,
        old_owner_action: str = "editor",
    ) -> Workspace:
        """
        Atomically transfer workspace ownership with configurable old owner handling.

        Args:
            workspace: Workspace instance to modify
            new_owner_id: ID of user to become new owner
            changed_by: User initiating the change
            old_owner_action: Action for old owner - 'editor', 'viewer', or 'remove'

        Returns:
            Workspace: Updated workspace instance

        Raises:
            PermissionDenied: If user cannot change ownership
            ValidationError: If ownership change is invalid
            DatabaseError: If database operation fails
        """
        logger.info(
            "Workspace ownership transfer initiated",
            extra={
                "workspace_id": workspace.id,
                "current_owner_id": workspace.owner_id,
                "new_owner_id": new_owner_id,
                "changed_by_id": changed_by.id,
                "old_owner_action": old_owner_action,
                "action": "workspace_ownership_transfer_start",
                "component": "WorkspaceService",
            },
        )

        try:
            # Get new_owner object for consistency
            User = get_user_model()
            try:
                new_owner = User.objects.get(id=new_owner_id)
            except User.DoesNotExist:
                raise ValidationError("New owner user not found")

            # Validate permission to change ownership
            if not self._can_change_ownership(workspace, changed_by):
                logger.warning(
                    "Workspace ownership transfer permission denied",
                    extra={
                        "workspace_id": workspace.id,
                        "changed_by_id": changed_by.id,
                        "current_owner_id": workspace.owner_id,
                        "action": "workspace_ownership_transfer_denied",
                        "component": "WorkspaceService",
                        "severity": "high",
                    },
                )
                raise PermissionDenied("User cannot change workspace ownership")

            # Validate new owner
            if new_owner.id == workspace.owner_id:
                raise ValidationError("New owner cannot be the same as current owner")

            # Check if new owner is workspace member
            if not self.membership_service.is_user_workspace_member(
                new_owner.id, workspace.id
            ):
                raise ValidationError("New owner must be a member of the workspace")

            # Validate old_owner_action
            valid_actions = ["editor", "viewer", "remove"]
            if old_owner_action not in valid_actions:
                raise ValidationError(
                    f"old_owner_action must be one of: {', '.join(valid_actions)}"
                )

            old_owner = workspace.owner

            # Update workspace owner
            workspace.owner = new_owner
            workspace.save()

            # Handle old owner based on action parameter
            if old_owner_action == "remove":
                # Remove old owner completely from workspace
                WorkspaceMembership.objects.filter(
                    workspace=workspace, user=old_owner
                ).delete()
                WorkspaceAdmin.objects.filter(
                    workspace=workspace, user=old_owner
                ).update(is_active=False)
                new_role = None
            else:
                # Change old owner's role to specified role
                WorkspaceMembership.objects.filter(
                    workspace=workspace, user=old_owner
                ).update(role=old_owner_action)
                new_role = old_owner_action

            # Invalidate cache for both users
            self.membership_service.invalidate_user_cache(old_owner.id)
            self.membership_service.invalidate_user_cache(new_owner.id)

            logger.info(
                "Workspace ownership transferred successfully",
                extra={
                    "workspace_id": workspace.id,
                    "old_owner_id": old_owner.id,
                    "new_owner_id": new_owner.id,
                    "changed_by_id": changed_by.id,
                    "old_owner_action": old_owner_action,
                    "old_owner_new_role": new_role,
                    "action": "workspace_ownership_transfer_success",
                    "component": "WorkspaceService",
                },
            )

            return workspace

        except (PermissionDenied, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "Workspace ownership transfer failed unexpectedly",
                extra={
                    "workspace_id": workspace.id,
                    "changed_by_id": changed_by.id,
                    "new_owner_id": new_owner_id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_ownership_transfer_failed",
                    "component": "WorkspaceService",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise

    @transaction.atomic
    def hard_delete_workspace(
        self, workspace: Workspace, requesting_user, confirmation_data: dict
    ) -> dict:
        """
        Permanently delete workspace with comprehensive safety checks and admin privileges.

        Args:
            workspace: Workspace instance to delete
            requesting_user: User initiating the deletion
            confirmation_data: Confirmation data for irreversible action

        Returns:
            dict: Deletion results with metadata

        Raises:
            PermissionDenied: If user cannot delete workspace
            ValidationError: If confirmation is invalid
            DatabaseError: If deletion fails
        """
        logger.warning(
            "Workspace hard deletion initiated",
            extra={
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "requesting_user_id": requesting_user.id,
                "workspace_owner_id": workspace.owner_id,
                "action": "workspace_hard_deletion_start",
                "component": "WorkspaceService",
                "severity": "high",
            },
        )

        try:
            # Check admin privileges
            has_admin_privileges = self._get_user_admin_privileges(
                requesting_user, workspace.id
            )

            # Apply security rules based on privileges
            if not has_admin_privileges:
                # Standard user rules
                if workspace.owner != requesting_user:
                    raise PermissionDenied(
                        "Only workspace owner can permanently delete the workspace"
                    )

                # Safety check: no other members
                member_count = workspace.members.count()
                if member_count > 1:  # Includes owner
                    raise ValidationError(
                        {
                            "error": "Cannot delete workspace with other members.",
                            "detail": f"Workspace has {member_count - 1} other member(s). Remove all members first.",
                            "member_count": member_count - 1,
                        }
                    )

            # Enhanced confirmation requirements
            self._validate_hard_delete_confirmation(
                workspace, confirmation_data, has_admin_privileges, requesting_user
            )

            # Get counts before deletion for logging
            member_count = workspace.members.count()
            transaction_count = Transaction.objects.filter(workspace=workspace).count()

            # Perform deletion
            workspace_id = workspace.id
            workspace_name = workspace.name
            workspace.delete()

            # Invalidate relevant caches
            cache_keys = [
                f"workspace_{workspace_id}",
                f"workspace_members_{workspace_id}",
            ]
            for key in cache_keys:
                cache.delete(key)

            result = {
                "message": "Workspace permanently deleted.",
                "details": {
                    "workspace_name": workspace_name,
                    "members_affected": member_count,
                    "transactions_deleted": transaction_count,
                },
            }

            # Add admin context if applicable
            if has_admin_privileges:
                result["admin_context"] = {
                    "deleted_by_admin": True,
                    "admin_user_id": requesting_user.id,
                    "original_owner_id": workspace.owner_id,
                }

            logger.critical(
                "Workspace hard deleted permanently",
                extra={
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "requesting_user_id": requesting_user.id,
                    "member_count": member_count,
                    "transaction_count": transaction_count,
                    "has_admin_privileges": has_admin_privileges,
                    "action": "workspace_hard_deletion_success",
                    "component": "WorkspaceService",
                    "severity": "critical",
                },
            )

            return result

        except (PermissionDenied, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "Workspace hard deletion failed",
                extra={
                    "workspace_id": workspace.id,
                    "requesting_user_id": requesting_user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_hard_deletion_failed",
                    "component": "WorkspaceService",
                    "severity": "critical",
                },
                exc_info=True,
            )
            raise

    def soft_delete_workspace(self, workspace: Workspace, user) -> Workspace:
        """
        Deactivate workspace (soft delete) with permission validation.

        Args:
            workspace: Workspace instance to deactivate
            user: User initiating the deactivation

        Returns:
            Workspace: Deactivated workspace instance

        Raises:
            PermissionDenied: If user cannot deactivate workspace
            ValidationError: If workspace is already inactive
        """
        logger.info(
            "Workspace soft deletion initiated",
            extra={
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "user_id": user.id,
                "current_status": "active" if workspace.is_active else "inactive",
                "action": "workspace_soft_deletion_start",
                "component": "WorkspaceService",
            },
        )

        try:
            if not workspace.is_active:
                raise ValidationError("Workspace is already inactive")

            # Check permissions using consistent method
            if not self._can_manage_workspace(workspace, user):
                raise PermissionDenied("Only admins or owners can deactivate workspace")

            workspace.is_active = False
            workspace.save()

            # Invalidate workspace cache
            cache.delete(f"workspace_{workspace.id}")

            logger.info(
                "Workspace soft deleted successfully",
                extra={
                    "workspace_id": workspace.id,
                    "user_id": user.id,
                    "previous_status": "active",
                    "new_status": "inactive",
                    "action": "workspace_soft_deletion_success",
                    "component": "WorkspaceService",
                },
            )

            return workspace

        except (PermissionDenied, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "Workspace soft deletion failed",
                extra={
                    "workspace_id": workspace.id,
                    "user_id": user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_soft_deletion_failed",
                    "component": "WorkspaceService",
                    "severity": "medium",
                },
            )
            raise

    def activate_workspace(self, workspace: Workspace, user) -> Workspace:
        """
        Activate inactive workspace with permission validation.

        Args:
            workspace: Workspace instance to activate
            user: User initiating the activation

        Returns:
            Workspace: Activated workspace instance

        Raises:
            PermissionDenied: If user cannot activate workspace
            ValidationError: If workspace is already active
        """
        logger.info(
            "Workspace activation initiated",
            extra={
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "user_id": user.id,
                "current_status": "active" if workspace.is_active else "inactive",
                "action": "workspace_activation_start",
                "component": "WorkspaceService",
            },
        )

        try:
            if workspace.is_active:
                raise ValidationError("Workspace is already active")

            # Check permissions using consistent method
            if not self._can_manage_workspace(workspace, user):
                raise PermissionDenied("Only admins or owners can activate workspace")

            workspace.is_active = True
            workspace.save()

            # Invalidate workspace cache
            cache.delete(f"workspace_{workspace.id}")

            logger.info(
                "Workspace activated successfully",
                extra={
                    "workspace_id": workspace.id,
                    "user_id": user.id,
                    "previous_status": "inactive",
                    "new_status": "active",
                    "action": "workspace_activation_success",
                    "component": "WorkspaceService",
                },
            )

            return workspace

        except (PermissionDenied, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "Workspace activation failed",
                extra={
                    "workspace_id": workspace.id,
                    "user_id": user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_activation_failed",
                    "component": "WorkspaceService",
                    "severity": "medium",
                },
            )
            raise

    def get_workspace_members_with_roles(self, workspace: Workspace):
        """
        Get all workspace members with their roles and permissions.

        Args:
            workspace: Workspace instance

        Returns:
            list: Members with role and permission data
        """
        return workspace.get_all_workspace_users_with_roles()

    def _validate_workspace_name(self, name: str) -> None:
        """Validate workspace name format and length."""
        stripped_name = name.strip()

        if not stripped_name or len(stripped_name) < 2:
            raise ValidationError("Workspace name must be at least 2 characters long.")

        if len(stripped_name) > 100:
            raise ValidationError("Workspace name must be at most 100 characters long.")

    def _sync_owner_to_membership(self, workspace: Workspace, is_new: bool) -> None:
        """Synchronize workspace owner to membership table."""
        try:
            WorkspaceMembership.objects.update_or_create(
                workspace=workspace, user=workspace.owner, defaults={"role": "owner"}
            )

            logger.debug(
                "Owner synchronized to membership",
                extra={
                    "workspace_id": workspace.id,
                    "owner_id": workspace.owner.id,
                    "is_new_workspace": is_new,
                    "action": "owner_sync_completed",
                    "component": "WorkspaceService",
                },
            )
        except Exception as e:
            logger.error(
                "Failed to sync owner to membership",
                extra={
                    "workspace_id": workspace.id,
                    "owner_id": workspace.owner.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "owner_sync_failed",
                    "component": "WorkspaceService",
                    "severity": "high",
                },
            )
            raise

    def _can_change_ownership(self, workspace: Workspace, user) -> bool:
        """Check if user can change workspace ownership."""
        # Superusers can always change ownership
        if user.is_superuser:
            return True

        # Current owner can transfer ownership
        if user == workspace.owner:
            return True

        # Workspace admins can change ownership
        return WorkspaceAdmin.objects.filter(
            user=user, workspace=workspace, is_active=True, can_manage_users=True
        ).exists()

    def _can_manage_workspace(self, workspace: Workspace, user) -> bool:
        """Check if user can manage workspace (admin/owner)."""
        if user.is_superuser:
            return True

        user_role = self.membership_service.get_user_workspace_role(
            user.id, workspace.id
        )
        return user_role in ["admin", "owner"]

    def _get_user_admin_privileges(self, user, workspace_id) -> bool:
        """Check if user has admin privileges for workspace."""
        if user.is_superuser:
            return True
        return self.membership_service.is_workspace_admin(user.id, workspace_id)

    def _validate_hard_delete_confirmation(
        self,
        workspace: Workspace,
        confirmation_data: dict,
        has_admin_privileges: bool,
        requesting_user,
    ) -> None:
        """Validate hard delete confirmation requirements."""
        if not isinstance(confirmation_data, dict):
            raise ValidationError(
                "Confirmation must be an object with required fields."
            )

        # Standard confirmation for all users
        requires_standard_confirmation = not has_admin_privileges or (
            has_admin_privileges and workspace.owner == requesting_user
        )

        if requires_standard_confirmation:
            standard_confirmation = confirmation_data.get("standard")
            workspace_name_confirmation = confirmation_data.get("workspace_name")

            if not standard_confirmation or standard_confirmation is not True:
                raise ValidationError(
                    {
                        "error": "Standard confirmation required",
                        "detail": "You must confirm understanding that this action is irreversible.",
                        "confirmation_required": {
                            "type": "standard",
                            "field": "confirmation.standard",
                            "value": True,
                        },
                    }
                )

            if workspace_name_confirmation != workspace.name:
                raise ValidationError(
                    {
                        "error": "Workspace name confirmation does not match",
                        "detail": f"Please type the workspace name exactly: {workspace.name}",
                        "expected_name": workspace.name,
                    }
                )

        # Admin extra confirmation for foreign workspace deletion
        if has_admin_privileges and workspace.owner != requesting_user:
            admin_confirmation = confirmation_data.get("admin")
            expected_admin_code = f"admin-delete-{workspace.id}"

            if not admin_confirmation or admin_confirmation != expected_admin_code:
                raise ValidationError(
                    {
                        "error": "Admin confirmation required",
                        "detail": "As an admin deleting another user's workspace, additional confirmation is required.",
                        "confirmation_required": {
                            "type": "admin",
                            "field": "confirmation.admin",
                            "value": expected_admin_code,
                            "message": f"Type: {expected_admin_code} to confirm admin deletion",
                        },
                    }
                )

    @transaction.atomic
    def deactivate_workspace_admin(self, admin_assignment_id: int, deactivated_by) -> bool:
        """
        Atomically deactivate workspace admin assignment with security validation.
        
        Args:
            admin_assignment_id: WorkspaceAdmin instance ID
            deactivated_by: User performing the deactivation
            
        Returns:
            bool: True if deactivated, False if already inactive
            
        Raises:
            PermissionDenied: If user cannot deactivate admin
            ValidationError: If admin assignment not found
        """
        logger.info(
            "Workspace admin deactivation initiated",
            extra={
                "admin_assignment_id": admin_assignment_id,
                "deactivated_by_id": deactivated_by.id,
                "action": "workspace_admin_deactivation_start",
                "component": "WorkspaceService",
            },
        )

        try:
            # Get admin assignment with related data
            admin_assignment = WorkspaceAdmin.objects.select_related('user', 'workspace').get(id=admin_assignment_id)
            
            # Security validation - only superusers can deactivate
            if not deactivated_by.is_superuser:
                logger.warning(
                    "Workspace admin deactivation permission denied",
                    extra={
                        "admin_assignment_id": admin_assignment_id,
                        "attempted_by_id": deactivated_by.id,
                        "action": "workspace_admin_deactivation_denied",
                        "component": "WorkspaceService",
                        "severity": "high",
                    },
                )
                raise PermissionDenied("Only superusers can deactivate workspace admins")
                
            # Deactivate using model method
            admin_assignment.deactivate(deactivated_by=deactivated_by)
            
            # Invalidate relevant caches
            self.membership_service.invalidate_user_cache(admin_assignment.user.id)
            
            logger.info(
                "Workspace admin deactivated successfully",
                extra={
                    "admin_assignment_id": admin_assignment_id,
                    "admin_user_id": admin_assignment.user.id,
                    "workspace_id": admin_assignment.workspace.id,
                    "deactivated_by_id": deactivated_by.id,
                    "action": "workspace_admin_deactivation_success",
                    "component": "WorkspaceService",
                },
            )
            
            return True
            
        except WorkspaceAdmin.DoesNotExist:
            logger.warning(
                "Workspace admin assignment not found for deactivation",
                extra={
                    "admin_assignment_id": admin_assignment_id,
                    "deactivated_by_id": deactivated_by.id,
                    "action": "workspace_admin_deactivation_not_found",
                    "component": "WorkspaceService",
                },
            )
            raise ValidationError("Workspace admin assignment not found")
        except Exception as e:
            logger.error(
                "Workspace admin deactivation failed",
                extra={
                    "admin_assignment_id": admin_assignment_id,
                    "deactivated_by_id": deactivated_by.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_admin_deactivation_failed",
                    "component": "WorkspaceService",
                    "severity": "high",
                },
            )
            raise