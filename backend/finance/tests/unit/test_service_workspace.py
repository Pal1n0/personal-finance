# finance/tests/unit/test_service_workspace.py
import logging
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.cache import cache
from django.db import DatabaseError
from rest_framework.exceptions import PermissionDenied, ValidationError

from finance.models import Transaction, Workspace, WorkspaceAdmin, WorkspaceMembership
from finance.services.workspace_service import WorkspaceService, WorkspaceServiceError


@pytest.mark.django_db
class TestWorkspaceServiceCreateWorkspace:
    """Testy pre create_workspace metódu"""

    def setup_method(self):
        self.service = WorkspaceService()

    def test_create_workspace_success(self, test_user):
        """Test úspešného vytvorenia workspace a synchronizácie vlastníka"""
        name = "Test Workspace"
        description = "Test description"

        workspace = self.service.create_workspace(name, description, test_user)

        assert workspace is not None
        assert workspace.name == name
        assert workspace.description == description
        assert workspace.owner == test_user
        assert Workspace.objects.filter(id=workspace.id).exists()
        assert WorkspaceMembership.objects.filter(
            workspace=workspace, user=test_user, role="owner"
        ).exists()

    def test_create_workspace_atomic_rollback(self, test_user):
        """Test, že sa workspace nevytvorí, ak zlyhá synchronizácia členstva (atomicita)"""
        with patch.object(
            self.service, "_sync_owner_to_membership", side_effect=DatabaseError
        ):
            with pytest.raises(DatabaseError):
                self.service.create_workspace(
                    "Rollback Test", "Should not be created", test_user
                )

        assert not Workspace.objects.filter(name="Rollback Test").exists()
        assert not WorkspaceMembership.objects.filter(user=test_user).exists()

    def test_create_workspace_validation_error_short_name(self, test_user):
        """Test vytvorenia workspace s príliš krátkym názvom"""
        with pytest.raises(ValidationError) as exc_info:
            self.service.create_workspace("A", "Description", test_user)
        assert "at least 2 characters" in str(exc_info.value)

    def test_create_workspace_validation_error_long_name(self, test_user):
        """Test vytvorenia workspace s príliš dlhým názvom"""
        with pytest.raises(ValidationError) as exc_info:
            self.service.create_workspace("A" * 101, "Description", test_user)
        assert "at most 100 characters" in str(exc_info.value)

    def test_create_workspace_validation_error_empty_name(self, test_user):
        """Test vytvorenia workspace s prázdnym názvom"""
        with pytest.raises(ValidationError) as exc_info:
            self.service.create_workspace("   ", "Description", test_user)
        assert "at least 2 characters" in str(exc_info.value)

    def test_create_workspace_success_logs_info(self, test_user):
        """Test that successful workspace creation is logged."""
        name = "Logging Test Workspace"
        with patch("finance.services.workspace_service.logger") as mock_logger:
            self.service.create_workspace(name, "Description", test_user)

            # Check that logging.info was called at least once
            assert mock_logger.info.call_count >= 1

            # Check the content of the success log message
            success_log_found = False
            for call in mock_logger.info.call_args_list:
                if "Workspace created successfully" in call[0][0]:
                    success_log_found = True
                    log_extra = call[1]["extra"]
                    assert log_extra["action"] == "workspace_creation_success"
                    assert "workspace_id" in log_extra
            assert success_log_found, "Success log message not found."


@pytest.mark.django_db
class TestWorkspaceServiceChangeOwnership:
    """Testy pre change_ownership metódu"""

    def setup_method(self):
        self.service = WorkspaceService()

    def test_change_ownership_success(self, test_user, test_user2, test_workspace):
        """Test úspešného prenosu vlastníctva vlastníkom"""
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )

        with patch.object(test_workspace, "change_owner") as mock_change_owner:
            self.service.change_ownership(
                test_workspace, test_user2.id, test_user, "viewer"
            )

            mock_change_owner.assert_called_once()
            # Verifies that the service correctly retrieves the user and calls the model method
            called_with_user = mock_change_owner.call_args[1]["new_owner"]
            assert called_with_user.id == test_user2.id
            assert mock_change_owner.call_args[1]["changed_by"] == test_user
            assert mock_change_owner.call_args[1]["old_owner_action"] == "viewer"

    def test_change_ownership_permission_denied(
        self, test_user, test_user2, test_workspace
    ):
        """Test prenosu vlastníctva bez oprávnenia (bežný člen)"""
        non_owner_member = test_user2
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=non_owner_member, role="viewer"
        )
        # The new_owner must exist for the code to reach the permission check.
        # We can use an existing user like test_user. The permission check happens before other validation.
        new_owner = test_user

        with patch.object(
            self.service, "_can_change_ownership", return_value=False
        ) as mock_can_change:
            with pytest.raises(PermissionDenied):
                self.service.change_ownership(
                    test_workspace, new_owner.id, non_owner_member, "editor"
                )
            mock_can_change.assert_called_once_with(test_workspace, non_owner_member)

    def test_change_ownership_to_self_raises_validation_error(
        self, test_user, test_workspace
    ):
        """Test prenosu vlastníctva na toho istého vlastníka"""
        with pytest.raises(ValidationError) as exc_info:
            self.service.change_ownership(
                test_workspace, test_user.id, test_user, "editor"
            )
        assert "same as current owner" in str(exc_info.value)

    def test_change_ownership_new_owner_not_member_raises_validation_error(
        self, test_user, test_user2, test_workspace
    ):
        """Test prenosu vlastníctva na používateľa ktorý nie je členom"""
        with patch.object(
            self.service.membership_service,
            "is_user_workspace_member",
            return_value=False,
        ):
            with pytest.raises(ValidationError) as exc_info:
                self.service.change_ownership(
                    test_workspace, test_user2.id, test_user, "editor"
                )
            assert "must be a member" in str(exc_info.value)

    def test_change_ownership_invalid_action_raises_validation_error(
        self, test_user, test_user2, test_workspace
    ):
        """Test prenosu vlastníctva s neplatnou akciou pre starého vlastníka"""
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )

        with pytest.raises(ValidationError) as exc_info:
            self.service.change_ownership(
                test_workspace, test_user2.id, test_user, "invalid_action"
            )
        assert "old_owner_action must be one of" in str(exc_info.value)

    def test_change_ownership_new_owner_not_found_raises_validation_error(
        self, test_user, test_workspace
    ):
        """Test prenosu vlastníctva na neexistujúceho používateľa"""
        non_existent_user_id = 99999
        with pytest.raises(ValidationError) as exc_info:
            self.service.change_ownership(
                test_workspace, non_existent_user_id, test_user, "editor"
            )
        assert "New owner user not found" in str(exc_info.value)

    def test_change_ownership_model_error_raises_service_error(
        self, test_user, test_user2, test_workspace
    ):
        """Test, že chyba z `workspace.change_owner` je prebalená ako WorkspaceServiceError"""
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )

        with patch.object(
            test_workspace, "change_owner", side_effect=PermissionError("Model Error")
        ) as mock_change_owner:
            with pytest.raises(WorkspaceServiceError, match="Model Error"):
                self.service.change_ownership(
                    test_workspace, test_user2.id, test_user, "editor"
                )
            mock_change_owner.assert_called_once()


@pytest.mark.django_db
class TestWorkspaceServiceHardDelete:
    """Tests for the hard_delete_workspace method."""

    def setup_method(self):
        self.service = WorkspaceService()

    def test_hard_delete_workspace_success_owner(self, test_user, test_workspace):
        """Test successful workspace deletion by the owner."""
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}
        test_workspace.owner = test_user
        test_workspace.save()

        with patch.object(
            self.service, "_validate_hard_delete_confirmation"
        ) as mock_validate, patch.object(
            test_workspace, "delete"
        ) as mock_delete, patch.object(
            self.service, "_get_user_admin_privileges", return_value=False
        ):
            result = self.service.hard_delete_workspace(
                test_workspace, test_user, confirmation_data
            )

            assert "permanently deleted" in result["message"]
            mock_validate.assert_called_once_with(
                test_workspace, confirmation_data, False, test_user
            )
            mock_delete.assert_called_once()
    
    def test_hard_delete_workspace_logs_critical_error(self, test_user, test_workspace):
        """Test that hard-deleting a workspace logs a critical error."""
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}
        test_workspace.owner = test_user
        test_workspace.save()

        with patch("finance.services.workspace_service.logger") as mock_logger:
            # Mock validation to avoid raising an error
            with patch.object(self.service, "_validate_hard_delete_confirmation"):
                # also need to make sure there are no other members in the workspace
                WorkspaceMembership.objects.filter(workspace=test_workspace).exclude(user=test_user).delete()
                self.service.hard_delete_workspace(
                    test_workspace, test_user, confirmation_data
                )

                mock_logger.critical.assert_called_once()
                log_message = mock_logger.critical.call_args[0][0]
                log_extra = mock_logger.critical.call_args[1]["extra"]

                assert "Workspace hard deleted permanently" in log_message
                assert log_extra["severity"] == "critical"
                assert log_extra["action"] == "workspace_hard_deletion_success"


    def test_hard_delete_workspace_success_admin(
        self, test_user, test_workspace, superuser
    ):
        """Test successful workspace deletion by a superuser (admin)."""
        confirmation_data = {
            "admin": f"admin-delete-{test_workspace.id}",
        }
        test_workspace.owner = test_user
        test_workspace.save()

        with patch.object(
            self.service, "_validate_hard_delete_confirmation"
        ) as mock_validate, patch.object(
            test_workspace, "delete"
        ) as mock_delete, patch.object(
            self.service, "_get_user_admin_privileges", return_value=True
        ):
            result = self.service.hard_delete_workspace(
                test_workspace, superuser, confirmation_data
            )

            assert "permanently deleted" in result["message"]
            assert result["admin_context"]["deleted_by_admin"] is True
            mock_validate.assert_called_once_with(
                test_workspace, confirmation_data, True, superuser
            )
            mock_delete.assert_called_once()

    def test_hard_delete_workspace_permission_denied_non_owner(
        self, test_user, test_user2, test_workspace
    ):
        """Test that a non-owner cannot delete the workspace."""
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}
        test_workspace.owner = test_user
        test_workspace.save()

        with pytest.raises(PermissionDenied, match="Only workspace owner"):
            self.service.hard_delete_workspace(
                test_workspace, test_user2, confirmation_data
            )

    def test_hard_delete_workspace_with_members_raises_error(
        self, test_user, test_workspace, workspace_member
    ):
        """Test that deleting a workspace with other members fails."""
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}

        # The workspace_member fixture adds a member to the workspace
        with pytest.raises(ValidationError) as exc_info:
            self.service.hard_delete_workspace(
                test_workspace, test_user, confirmation_data
            )
        assert "Cannot delete workspace with other members" in exc_info.value.detail["error"]

    def test_hard_delete_validation_failure(self, test_user, test_workspace):
        """Test that hard delete fails if confirmation validation fails."""
        confirmation_data = {"standard": False}  # Invalid confirmation

        with patch.object(
            self.service,
            "_validate_hard_delete_confirmation",
            side_effect=ValidationError("Validation Failed"),
        ) as mock_validate:
            with pytest.raises(ValidationError, match="Validation Failed"):
                self.service.hard_delete_workspace(
                    test_workspace, test_user, confirmation_data
                )
            mock_validate.assert_called_once()

    def test_hard_delete_workspace_admin_deleting_own_workspace_requires_standard_confirmation(
        self, workspace_admin, test_workspace, test_user
    ):
        """Test, že admin, ktorý maže vlastný workspace, potrebuje štandardné potvrdenie."""
        service = WorkspaceService()
        
        # Demote the original owner to allow a new owner to be assigned
        WorkspaceMembership.objects.filter(workspace=test_workspace, user=test_user).update(role='editor')

        # Nastav admina ako vlastníka tohto workspace
        test_workspace.owner = workspace_admin.user
        test_workspace.save()

        # Potvrdenie chýba
        confirmation_data = {}

        with patch.object(
            service, "_get_user_admin_privileges", return_value=True
        ) as mock_admin_priv:
            with pytest.raises(ValidationError, match="Standard confirmation required"):
                service.hard_delete_workspace(
                    test_workspace, workspace_admin.user, confirmation_data
                )

            # Over, že sa volala kontrola privilégií
            mock_admin_priv.assert_called_once_with(
                workspace_admin.user, test_workspace.id
            )

    def test_hard_delete_workspace_admin_missing_admin_confirmation(
        self, test_user, test_workspace, workspace_admin
    ):
        """Test admin zmazania bez admin potvrdenia"""
        service = WorkspaceService()
        confirmation_data = {
            "standard": True,
            "workspace_name": test_workspace.name,
            # Chýba admin confirmation
        }

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            mock_admin_priv.return_value = True

            with pytest.raises(ValidationError) as exc_info:
                service.hard_delete_workspace(
                    test_workspace, workspace_admin.user, confirmation_data
                )

        assert "Admin confirmation required" in exc_info.value.detail['error']


@pytest.mark.django_db
class TestWorkspaceServiceSoftDeleteAndActivate:
    """Tests for soft-deleting and activating a workspace."""

    def setup_method(self):
        self.service = WorkspaceService()

    def test_soft_delete_workspace_success(self, test_user, test_workspace):
        """Test successful soft deletion of a workspace."""
        test_workspace.is_active = True
        test_workspace.save()

        with patch.object(
            self.service, "_can_manage_workspace", return_value=True
        ) as mock_can_manage, patch.object(
            cache, "delete"
        ) as mock_cache_delete:
            workspace = self.service.soft_delete_workspace(test_workspace, test_user)

            assert workspace.is_active is False
            mock_can_manage.assert_called_once_with(test_workspace, test_user)
            mock_cache_delete.assert_called_with(f"workspace_{test_workspace.id}")

    def test_soft_delete_workspace_already_inactive_raises_error(
        self, test_user, test_workspace
    ):
        """Test that soft-deleting an already inactive workspace fails."""
        test_workspace.is_active = False
        test_workspace.save()

        with pytest.raises(ValidationError) as exc_info:
            self.service.soft_delete_workspace(test_workspace, test_user)
        assert "already inactive" in str(exc_info.value)

    def test_soft_delete_workspace_permission_denied(self, test_user, test_workspace):
        """Test that soft deletion fails without manage permissions."""
        with patch.object(
            self.service, "_can_manage_workspace", return_value=False
        ) as mock_can_manage:
            with pytest.raises(PermissionDenied, match="Only admins or owners"):
                self.service.soft_delete_workspace(test_workspace, test_user)
            mock_can_manage.assert_called_once_with(test_workspace, test_user)

    def test_activate_workspace_success(self, test_user, test_workspace):
        """Test successful activation of a workspace."""
        test_workspace.is_active = False
        test_workspace.save()

        with patch.object(
            self.service, "_can_manage_workspace", return_value=True
        ) as mock_can_manage, patch.object(
            cache, "delete"
        ) as mock_cache_delete:
            workspace = self.service.activate_workspace(test_workspace, test_user)

            assert workspace.is_active is True
            mock_can_manage.assert_called_once_with(test_workspace, test_user)
            mock_cache_delete.assert_called_with(f"workspace_{test_workspace.id}")

    def test_activate_workspace_already_active_raises_error(
        self, test_user, test_workspace
    ):
        """Test that activating an already active workspace fails."""
        test_workspace.is_active = True
        test_workspace.save()

        with pytest.raises(ValidationError) as exc_info:
            self.service.activate_workspace(test_workspace, test_user)
        assert "already active" in str(exc_info.value)

    def test_activate_workspace_permission_denied(self, test_user, test_workspace):
        """Test that activation fails without manage permissions."""
        test_workspace.is_active = False
        test_workspace.save()

        with patch.object(
            self.service, "_can_manage_workspace", return_value=False
        ) as mock_can_manage:
            with pytest.raises(PermissionDenied, match="Only admins or owners"):
                self.service.activate_workspace(test_workspace, test_user)
            mock_can_manage.assert_called_once_with(test_workspace, test_user)


@pytest.mark.django_db
class TestWorkspaceServiceHelperMethods:
    """Tests for private helper methods in WorkspaceService."""

    def setup_method(self):
        self.service = WorkspaceService()

    @pytest.mark.parametrize(
        "name", ["Valid Name", "AB", "A" * 100]
    )
    def test_validate_workspace_name_success(self, name):
        """Test successful validation of various correct workspace names."""
        # Should not raise
        self.service._validate_workspace_name(name)

    @pytest.mark.parametrize(
        "name, error_match",
        [
            ("", "at least 2 characters"),
            ("A", "at least 2 characters"),
            ("A" * 101, "at most 100 characters"),
            ("   ", "at least 2 characters"),
        ],
    )
    def test_validate_workspace_name_failure(self, name, error_match):
        """Test that invalid workspace names raise a ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.service._validate_workspace_name(name)
        assert error_match in str(exc_info.value)

    def test_sync_owner_to_membership(self, test_workspace):
        """Test that the owner is correctly synced to the membership table."""
        with patch.object(
            WorkspaceMembership.objects, "update_or_create"
        ) as mock_update_or_create:
            self.service._sync_owner_to_membership(test_workspace, is_new=True)
            mock_update_or_create.assert_called_once_with(
                workspace=test_workspace,
                user=test_workspace.owner,
                defaults={"role": "owner"},
            )

    @pytest.mark.parametrize(
        "user_type, can_change",
        [
            ("owner", True),
            ("superuser", True),
            ("admin_can_manage", True),
            ("admin_cannot_manage", False),
            ("regular_user", False),
        ],
    )
    def test_can_change_ownership(
        self, user_type, can_change, test_user, test_user2, test_workspace, superuser
    ):
        """Test the _can_change_ownership logic for different user types."""
        user = test_user
        if user_type == "owner":
            user = test_workspace.owner
        elif user_type == "superuser":
            user = superuser
        elif user_type.startswith("admin"):
            user = test_user2
            WorkspaceAdmin.objects.create(
                user=user,
                workspace=test_workspace,
                can_manage_users=(user_type == "admin_can_manage"),
                assigned_by=superuser,
            )
        elif user_type == "regular_user":
            user = test_user2

        assert self.service._can_change_ownership(test_workspace, user) is can_change


@pytest.mark.django_db
class TestWorkspaceServiceGetMembers:
    """Test for get_workspace_members_with_roles method."""

    def test_get_workspace_members_with_roles(self, test_workspace):
        """Test retrieving workspace members with their roles."""
        service = WorkspaceService()
        expected_data = [{"user_id": 1, "role": "owner", "username": "testuser"}]

        with patch.object(
            test_workspace, "get_all_workspace_users_with_roles", return_value=expected_data
        ) as mock_get:
            members = service.get_workspace_members_with_roles(test_workspace)

            assert members == expected_data
            mock_get.assert_called_once()


@pytest.mark.django_db
class TestWorkspaceServiceIntegration:
    """High-level integration tests for the WorkspaceService."""

    def test_complete_workspace_lifecycle(self, test_user, test_user2):
        """Test the full lifecycle of a workspace from creation to activation."""
        service = WorkspaceService()

        # 1. Create
        workspace = service.create_workspace(
            "Lifecycle Workspace", "Test lifecycle", test_user
        )
        assert workspace.owner == test_user
        assert WorkspaceMembership.objects.filter(
            workspace=workspace, user=test_user, role="owner"
        ).exists()

        # 2. Change Ownership
        WorkspaceMembership.objects.create(
            workspace=workspace, user=test_user2, role="editor"
        )
        service.change_ownership(workspace, test_user2.id, test_user, "editor")
        workspace.refresh_from_db()
        assert workspace.owner == test_user2
        assert WorkspaceMembership.objects.get(
            workspace=workspace, user=test_user
        ).role == "editor"

        # 3. Soft Delete
        service.soft_delete_workspace(workspace, test_user2)
        workspace.refresh_from_db()
        assert workspace.is_active is False

        # 4. Activate
        service.activate_workspace(workspace, test_user2)
        workspace.refresh_from_db()
        assert workspace.is_active is True


@pytest.mark.django_db
class TestWorkspaceServiceEdgeCases:
    """Tests for edge cases and miscellaneous scenarios."""

    def test_workspace_name_trimming_on_create(self, test_user):
        """Test that workspace name is trimmed on creation."""
        service = WorkspaceService()
        with patch.object(Workspace.objects, "create") as mock_create:
            with patch.object(service, "_sync_owner_to_membership"):
                mock_workspace = Mock(id=1, owner=test_user)
                mock_create.return_value = mock_workspace

                service.create_workspace("  Spaced Name  ", "Desc", test_user)

                mock_create.assert_called_with(
                    name="Spaced Name", description="Desc", owner=test_user
                )

    def test_cache_invalidation_on_hard_delete(self, test_user, test_workspace):
        """Test that cache is invalidated upon hard deletion."""
        service = WorkspaceService()
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}
        
        # Ensure the user is the owner and no other members exist
        test_workspace.owner = test_user
        test_workspace.save()
        WorkspaceMembership.objects.filter(workspace=test_workspace).exclude(user=test_user).delete()

        workspace_id = test_workspace.id
        with patch.object(cache, "delete") as mock_cache_delete:
            service.hard_delete_workspace(test_workspace, test_user, confirmation_data)
            
            # Check for invalidation of workspace and its members cache
            mock_cache_delete.assert_any_call(f"workspace_{workspace_id}")
            mock_cache_delete.assert_any_call(f"workspace_members_{workspace_id}")


@pytest.mark.django_db
class TestWorkspaceServiceDeactivateAdmin:
    """Testy pre deactivate_workspace_admin metódu"""

    def setup_method(self):
        self.service = WorkspaceService()

    def test_deactivate_admin_success_by_superuser(
        self, superuser, workspace_admin
    ):
        """Test úspešnej deaktivácie admina superuserom"""
        with patch.object(
            self.service.membership_service, "invalidate_user_cache"
        ) as mock_invalidate_cache:
            result = self.service.deactivate_workspace_admin(
                workspace_admin.id, deactivated_by=superuser
            )

        assert result is True
        workspace_admin.refresh_from_db()
        assert workspace_admin.is_active is False
        assert workspace_admin.deactivated_by == superuser
        mock_invalidate_cache.assert_called_once_with(workspace_admin.user.id)

    def test_deactivate_admin_permission_denied_for_non_superuser(
        self, test_user, workspace_admin
    ):
        """Test, že bežný používateľ nemôže deaktivovať admina"""
        with pytest.raises(PermissionDenied, match="Only superusers can deactivate"):
            self.service.deactivate_workspace_admin(
                workspace_admin.id, deactivated_by=test_user
            )

    def test_deactivate_admin_not_found_raises_validation_error(self, superuser):
        """Test, že sa vyvolá chyba, ak admin assignment neexistuje"""
        non_existent_id = 999
        with pytest.raises(ValidationError) as exc_info:
            self.service.deactivate_workspace_admin(
                non_existent_id, deactivated_by=superuser
            )
        assert "assignment not found" in str(exc_info.value)

    def test_deactivate_admin_already_inactive(self, superuser, workspace_admin):
        """Test, že deaktivácia už neaktívneho admina je idempotentná (v rámci modelu)"""
        workspace_admin.is_active = False
        workspace_admin.save()

        # The model's deactivate method will not raise an error, it just won't do anything.
        # The service method returns True if the operation succeeds without errors.
        result = self.service.deactivate_workspace_admin(
            workspace_admin.id, deactivated_by=superuser
        )
        assert result is True
        workspace_admin.refresh_from_db()
        assert workspace_admin.is_active is False

@pytest.mark.django_db
class TestWorkspaceServiceHardDeleteValidation:
    """Tests for the _validate_hard_delete_confirmation helper method."""

    def setup_method(self):
        self.service = WorkspaceService()

    def test_validate_hard_delete_confirmation_not_a_dict(self, test_user, test_workspace):
        """Test that validation fails if confirmation_data is not a dictionary."""
        with pytest.raises(ValidationError, match="Confirmation must be an object"):
            self.service._validate_hard_delete_confirmation(
                test_workspace, "not-a-dict", False, test_user
            )

    def test_validate_hard_delete_confirmation_incorrect_workspace_name(self, test_user, test_workspace):
        """Test that validation fails if the workspace name confirmation is incorrect."""
        confirmation_data = {"standard": True, "workspace_name": "Incorrect Name"}
        with pytest.raises(ValidationError) as exc_info:
            self.service._validate_hard_delete_confirmation(
                test_workspace, confirmation_data, False, test_user
            )
        assert "Workspace name confirmation does not match" in str(exc_info.value)


@pytest.mark.django_db
class TestWorkspaceServiceCanManage:
    """Tests for the _can_manage_workspace helper method."""

    def setup_method(self):
        self.service = WorkspaceService()

    @pytest.mark.parametrize(
        "user_role, is_superuser, can_manage",
        [
            ("owner", False, True),
            ("admin", False, True),
            ("editor", False, False),
            ("viewer", False, False),
            ("viewer", True, True), # superuser can manage regardless of role
        ],
    )
    def test_can_manage_workspace(self, test_user, test_workspace, user_role, is_superuser, can_manage):
        test_user.is_superuser = is_superuser
        test_user.save()

        with patch.object(self.service.membership_service, "get_user_workspace_role", return_value=user_role):
            assert self.service._can_manage_workspace(test_workspace, test_user) is can_manage
            