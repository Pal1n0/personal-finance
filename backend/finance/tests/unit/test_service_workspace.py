# finance/tests/unit/test_service_workspace.py
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from rest_framework.exceptions import PermissionDenied

from finance.models import (Transaction, Workspace, WorkspaceAdmin,
                            WorkspaceMembership)
from finance.services.workspace_service import WorkspaceService


class TestWorkspaceServiceCreateWorkspace:
    """Testy pre create_workspace metódu"""

    def test_create_workspace_success(self, test_user):
        """Test úspešného vytvorenia workspace"""
        service = WorkspaceService()
        name = "Test Workspace"
        description = "Test description"

        with patch.object(Workspace.objects, "create") as mock_create:
            with patch.object(service, "_sync_owner_to_membership") as mock_sync:
                mock_workspace = Mock(
                    id=1, name=name, description=description, owner=test_user
                )
                mock_create.return_value = mock_workspace

                workspace = service.create_workspace(name, description, test_user)

        assert workspace.id == 1
        assert workspace.name == name
        mock_create.assert_called_once_with(
            name=name.strip(), description=description, owner=test_user
        )
        mock_sync.assert_called_once_with(mock_workspace, is_new=True)

    def test_create_workspace_validation_error_short_name(self, test_user):
        """Test vytvorenia workspace s príliš krátkym názvom"""
        service = WorkspaceService()
        short_name = "A"  # Príliš krátky názov

        with pytest.raises(ValidationError) as exc_info:
            service.create_workspace(short_name, "Description", test_user)

        assert "at least 2 characters" in str(exc_info.value)

    def test_create_workspace_validation_error_long_name(self, test_user):
        """Test vytvorenia workspace s príliš dlhým názvom"""
        service = WorkspaceService()
        long_name = "A" * 101  # Príliš dlhý názov

        with pytest.raises(ValidationError) as exc_info:
            service.create_workspace(long_name, "Description", test_user)

        assert "at most 100 characters" in str(exc_info.value)

    def test_create_workspace_validation_error_empty_name(self, test_user):
        """Test vytvorenia workspace s prázdnym názvom"""
        service = WorkspaceService()

        with pytest.raises(ValidationError) as exc_info:
            service.create_workspace("   ", "Description", test_user)  # Len medzery

        assert "at least 2 characters" in str(exc_info.value)

    def test_create_workspace_database_error(self, test_user):
        """Test vytvorenia workspace s databázovou chybou"""
        service = WorkspaceService()

        with patch.object(Workspace.objects, "create") as mock_create:
            mock_create.side_effect = DatabaseError("Connection failed")

            with pytest.raises(DatabaseError):
                service.create_workspace("Test Workspace", "Description", test_user)


class TestWorkspaceServiceChangeOwnership:
    """Testy pre change_ownership metódu"""

    def test_change_ownership_success_owner(
        self, test_user, test_user2, test_workspace
    ):
        """Test úspešného prenosu vlastníctva vlastníkom"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "is_user_workspace_member"
        ) as mock_member:
            with patch.object(Workspace, "save") as mock_save:
                with patch.object(WorkspaceMembership.objects, "filter") as mock_filter:
                    with patch.object(
                        WorkspaceAdmin.objects, "filter"
                    ) as mock_admin_filter:
                        mock_member.return_value = True
                        mock_filter.return_value.update.return_value = 1
                        mock_admin_filter.return_value.update.return_value = 1

                        workspace = service.change_ownership(
                            test_workspace, test_user2.id, test_user, "editor"
                        )

        assert workspace.owner == test_user2
        mock_save.assert_called_once()

    def test_change_ownership_success_admin(
        self, test_user, test_user2, test_workspace, workspace_admin
    ):
        """Test úspešného prenosu vlastníctva adminom"""
        service = WorkspaceService()

        with patch.object(service, "_can_change_ownership") as mock_can_change:
            with patch.object(
                service.membership_service, "is_user_workspace_member"
            ) as mock_member:
                with patch.object(Workspace, "save") as mock_save:
                    mock_can_change.return_value = True
                    mock_member.return_value = True

                    workspace = service.change_ownership(
                        test_workspace, test_user2.id, workspace_admin.user, "viewer"
                    )

        assert workspace.owner == test_user2

    def test_change_ownership_permission_denied(
        self, test_user, test_user2, test_workspace
    ):
        """Test prenosu vlastníctva bez oprávnenia"""
        service = WorkspaceService()

        with patch.object(service, "_can_change_ownership") as mock_can_change:
            mock_can_change.return_value = False

            with pytest.raises(PermissionDenied) as exc_info:
                service.change_ownership(
                    test_workspace, test_user2.id, test_user2, "editor"
                )

        assert "cannot change workspace ownership" in str(exc_info.value)

    def test_change_ownership_same_owner(self, test_user, test_workspace):
        """Test prenosu vlastníctva na toho istého vlastníka"""
        service = WorkspaceService()

        with pytest.raises(ValidationError) as exc_info:
            service.change_ownership(test_workspace, test_user.id, test_user, "editor")

        assert "cannot be the same as current owner" in str(exc_info.value)

    def test_change_ownership_new_owner_not_member(
        self, test_user, test_user2, test_workspace
    ):
        """Test prenosu vlastníctva na používateľa ktorý nie je členom"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "is_user_workspace_member"
        ) as mock_member:
            mock_member.return_value = False

            with pytest.raises(ValidationError) as exc_info:
                service.change_ownership(
                    test_workspace, test_user2.id, test_user, "editor"
                )

        assert "must be a member" in str(exc_info.value)

    def test_change_ownership_invalid_action(
        self, test_user, test_user2, test_workspace
    ):
        """Test prenosu vlastníctva s neplatnou akciou pre starého vlastníka"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "is_user_workspace_member"
        ) as mock_member:
            mock_member.return_value = True

            with pytest.raises(ValidationError) as exc_info:
                service.change_ownership(
                    test_workspace, test_user2.id, test_user, "invalid_action"
                )

        assert "must be one of" in str(exc_info.value)

    def test_change_ownership_remove_old_owner(
        self, test_user, test_user2, test_workspace
    ):
        """Test prenosu vlastníctva s odstránením starého vlastníka"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "is_user_workspace_member"
        ) as mock_member:
            with patch.object(Workspace, "save"):
                with patch.object(
                    WorkspaceMembership.objects, "filter"
                ) as mock_membership_filter:
                    with patch.object(
                        WorkspaceAdmin.objects, "filter"
                    ) as mock_admin_filter:
                        mock_member.return_value = True
                        mock_membership_filter.return_value.delete.return_value = (
                            1,
                            {},
                        )
                        mock_admin_filter.return_value.update.return_value = 1

                        workspace = service.change_ownership(
                            test_workspace, test_user2.id, test_user, "remove"
                        )

        assert workspace.owner == test_user2
        mock_membership_filter.return_value.delete.assert_called_once()

    def test_change_ownership_new_owner_not_found(self, test_user, test_workspace):
        """Test prenosu vlastníctva na neexistujúceho používateľa"""
        service = WorkspaceService()

        with pytest.raises(ValidationError) as exc_info:
            service.change_ownership(test_workspace, 99999, test_user, "editor")

        assert "New owner user not found" in str(exc_info.value)


class TestWorkspaceServiceHardDelete:
    """Testy pre hard_delete_workspace metódu"""

    def test_hard_delete_workspace_success_owner(self, test_user, test_workspace):
        """Test úspešného zmazania workspace vlastníkom"""
        service = WorkspaceService()
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            with patch.object(Transaction.objects, "filter") as mock_transactions:
                with patch.object(Workspace, "delete") as mock_delete:
                    mock_admin_priv.return_value = False
                    mock_transactions.return_value.count.return_value = 5

                    result = service.hard_delete_workspace(
                        test_workspace, test_user, confirmation_data
                    )

        assert "permanently deleted" in result["message"]
        mock_delete.assert_called_once()

    def test_hard_delete_workspace_success_admin(
        self, test_user, test_workspace, workspace_admin
    ):
        """Test úspešného zmazania workspace adminom"""
        service = WorkspaceService()
        confirmation_data = {
            "standard": True,
            "workspace_name": test_workspace.name,
            "admin": f"admin-delete-{test_workspace.id}",
        }

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            with patch.object(Transaction.objects, "filter") as mock_transactions:
                with patch.object(Workspace, "delete") as mock_delete:
                    mock_admin_priv.return_value = True
                    mock_transactions.return_value.count.return_value = 10

                    result = service.hard_delete_workspace(
                        test_workspace, workspace_admin.user, confirmation_data
                    )

        assert "permanently deleted" in result["message"]
        assert result["details"]["admin_context"]["deleted_by_admin"] is True

    def test_hard_delete_workspace_permission_denied(
        self, test_user, test_user2, test_workspace
    ):
        """Test zmazania workspace bez oprávnenia"""
        service = WorkspaceService()
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            mock_admin_priv.return_value = False

            with pytest.raises(PermissionDenied) as exc_info:
                service.hard_delete_workspace(
                    test_workspace, test_user2, confirmation_data
                )

        assert "Only workspace owner" in str(exc_info.value)

    def test_hard_delete_workspace_with_members(
        self, test_user, test_workspace, workspace_member
    ):
        """Test zmazania workspace s ďalšími členmi"""
        service = WorkspaceService()
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            mock_admin_priv.return_value = False

            with pytest.raises(ValidationError) as exc_info:
                service.hard_delete_workspace(
                    test_workspace, test_user, confirmation_data
                )

        assert "with other members" in str(exc_info.value["error"])
        assert "member_count" in str(exc_info.value)

    def test_hard_delete_workspace_missing_standard_confirmation(
        self, test_user, test_workspace
    ):
        """Test zmazania workspace bez štandardného potvrdenia"""
        service = WorkspaceService()
        confirmation_data = {
            "workspace_name": test_workspace.name  # Chýba standard: True
        }

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            mock_admin_priv.return_value = False

            with pytest.raises(ValidationError) as exc_info:
                service.hard_delete_workspace(
                    test_workspace, test_user, confirmation_data
                )

        assert "Standard confirmation required" in str(exc_info.value["error"])

    def test_hard_delete_workspace_wrong_name_confirmation(
        self, test_user, test_workspace
    ):
        """Test zmazania workspace s nesprávnym potvrdením názvu"""
        service = WorkspaceService()
        confirmation_data = {
            "standard": True,
            "workspace_name": "Wrong Name",  # Nesprávny názov
        }

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            mock_admin_priv.return_value = False

            with pytest.raises(ValidationError) as exc_info:
                service.hard_delete_workspace(
                    test_workspace, test_user, confirmation_data
                )

        assert "name confirmation does not match" in str(exc_info.value["error"])

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

        assert "Admin confirmation required" in str(exc_info.value["error"])


class TestWorkspaceServiceSoftDeleteAndActivate:
    """Testy pre soft_delete_workspace a activate_workspace metódy"""

    def test_soft_delete_workspace_success(self, test_user, test_workspace):
        """Test úspešného soft zmazania workspace"""
        service = WorkspaceService()

        with patch.object(service, "_can_manage_workspace") as mock_can_manage:
            with patch.object(Workspace, "save") as mock_save:
                with patch.object(cache, "delete") as mock_cache_delete:
                    mock_can_manage.return_value = True
                    test_workspace.is_active = True

                    workspace = service.soft_delete_workspace(test_workspace, test_user)

        assert workspace.is_active is False
        mock_save.assert_called_once()
        mock_cache_delete.assert_called_once_with(f"workspace_{test_workspace.id}")

    def test_soft_delete_workspace_already_inactive(self, test_user, test_workspace):
        """Test soft zmazania už neaktívneho workspace"""
        service = WorkspaceService()
        test_workspace.is_active = False

        with pytest.raises(ValidationError) as exc_info:
            service.soft_delete_workspace(test_workspace, test_user)

        assert "already inactive" in str(exc_info.value)

    def test_soft_delete_workspace_permission_denied(self, test_user, test_workspace):
        """Test soft zmazania bez oprávnenia"""
        service = WorkspaceService()

        with patch.object(service, "_can_manage_workspace") as mock_can_manage:
            mock_can_manage.return_value = False

            with pytest.raises(PermissionDenied) as exc_info:
                service.soft_delete_workspace(test_workspace, test_user)

        assert "Only admins or owners" in str(exc_info.value)

    def test_activate_workspace_success(self, test_user, test_workspace):
        """Test úspešnej aktivácie workspace"""
        service = WorkspaceService()
        test_workspace.is_active = False

        with patch.object(service, "_can_manage_workspace") as mock_can_manage:
            with patch.object(Workspace, "save") as mock_save:
                with patch.object(cache, "delete") as mock_cache_delete:
                    mock_can_manage.return_value = True

                    workspace = service.activate_workspace(test_workspace, test_user)

        assert workspace.is_active is True
        mock_save.assert_called_once()
        mock_cache_delete.assert_called_once_with(f"workspace_{test_workspace.id}")

    def test_activate_workspace_already_active(self, test_user, test_workspace):
        """Test aktivácie už aktívneho workspace"""
        service = WorkspaceService()
        test_workspace.is_active = True

        with pytest.raises(ValidationError) as exc_info:
            service.activate_workspace(test_workspace, test_user)

        assert "already active" in str(exc_info.value)

    def test_activate_workspace_permission_denied(self, test_user, test_workspace):
        """Test aktivácie bez oprávnenia"""
        service = WorkspaceService()
        test_workspace.is_active = False

        with patch.object(service, "_can_manage_workspace") as mock_can_manage:
            mock_can_manage.return_value = False

            with pytest.raises(PermissionDenied) as exc_info:
                service.activate_workspace(test_workspace, test_user)

        assert "Only admins or owners" in str(exc_info.value)


class TestWorkspaceServiceHelperMethods:
    """Testy pre pomocné metódy"""

    def test_validate_workspace_name_success(self):
        """Test úspešnej validácie názvu workspace"""
        service = WorkspaceService()

        # Malo by prejsť bez výnimky
        service._validate_workspace_name("Valid Name")
        service._validate_workspace_name("AB")  # Minimálna dĺžka
        service._validate_workspace_name("A" * 100)  # Maximálna dĺžka

    def test_validate_workspace_name_too_short(self):
        """Test validácie príliš krátkeho názvu"""
        service = WorkspaceService()

        with pytest.raises(ValidationError) as exc_info:
            service._validate_workspace_name("A")

        assert "at least 2 characters" in str(exc_info.value)

    def test_validate_workspace_name_too_long(self):
        """Test validácie príliš dlhého názvu"""
        service = WorkspaceService()

        with pytest.raises(ValidationError) as exc_info:
            service._validate_workspace_name("A" * 101)

        assert "at most 100 characters" in str(exc_info.value)

    def test_validate_workspace_name_empty(self):
        """Test validácie prázdneho názvu"""
        service = WorkspaceService()

        with pytest.raises(ValidationError) as exc_info:
            service._validate_workspace_name("   ")

        assert "at least 2 characters" in str(exc_info.value)

    def test_sync_owner_to_membership_success(self, test_user, test_workspace):
        """Test úspešnej synchronizácie vlastníka do členstva"""
        service = WorkspaceService()

        with patch.object(WorkspaceMembership.objects, "update_or_create") as mock_sync:
            service._sync_owner_to_membership(test_workspace, is_new=True)

        mock_sync.assert_called_once_with(
            workspace=test_workspace,
            user=test_workspace.owner,
            defaults={"role": "owner"},
        )

    def test_sync_owner_to_membership_error(self, test_user, test_workspace):
        """Test synchronizácie vlastníka s chybou"""
        service = WorkspaceService()

        with patch.object(WorkspaceMembership.objects, "update_or_create") as mock_sync:
            mock_sync.side_effect = Exception("Sync failed")

            with pytest.raises(Exception):
                service._sync_owner_to_membership(test_workspace, is_new=False)

    def test_can_change_ownership_owner(self, test_user, test_workspace):
        """Test oprávnenia vlastníka meniť vlastníctvo"""
        service = WorkspaceService()

        result = service._can_change_ownership(test_workspace, test_user)

        assert result is True

    def test_can_change_ownership_superuser(self, test_user, test_workspace):
        """Test oprávnenia superuser meniť vlastníctvo"""
        service = WorkspaceService()
        test_user.is_superuser = True

        result = service._can_change_ownership(test_workspace, test_user)

        assert result is True

    def test_can_change_ownership_admin(
        self, test_user, test_workspace, workspace_admin
    ):
        """Test oprávnenia admin meniť vlastníctvo"""
        service = WorkspaceService()

        with patch.object(WorkspaceAdmin.objects, "filter") as mock_filter:
            mock_filter.return_value.exists.return_value = True

            result = service._can_change_ownership(test_workspace, workspace_admin.user)

        assert result is True

    def test_can_change_ownership_denied(self, test_user, test_user2, test_workspace):
        """Test zamietnutia oprávnenia meniť vlastníctvo"""
        service = WorkspaceService()

        with patch.object(WorkspaceAdmin.objects, "filter") as mock_filter:
            mock_filter.return_value.exists.return_value = False

            result = service._can_change_ownership(test_workspace, test_user2)

        assert result is False

    def test_can_manage_workspace_owner(self, test_user, test_workspace):
        """Test oprávnenia vlastníka spravovať workspace"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "get_user_workspace_role"
        ) as mock_role:
            mock_role.return_value = "owner"

            result = service._can_manage_workspace(test_workspace, test_user)

        assert result is True

    def test_can_manage_workspace_admin(self, test_user, test_workspace):
        """Test oprávnenia admin spravovať workspace"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "get_user_workspace_role"
        ) as mock_role:
            mock_role.return_value = "admin"

            result = service._can_manage_workspace(test_workspace, test_user)

        assert result is True

    def test_can_manage_workspace_denied(self, test_user, test_workspace):
        """Test zamietnutia oprávnenia spravovať workspace"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "get_user_workspace_role"
        ) as mock_role:
            mock_role.return_value = "editor"

            result = service._can_manage_workspace(test_workspace, test_user)

        assert result is False

    def test_can_manage_workspace_superuser(self, test_user, test_workspace):
        """Test oprávnenia superuser spravovať workspace"""
        service = WorkspaceService()
        test_user.is_superuser = True

        result = service._can_manage_workspace(test_workspace, test_user)

        assert result is True

    def test_get_user_admin_privileges_superuser(self, test_user, test_workspace):
        """Test admin privilégií superuser"""
        service = WorkspaceService()
        test_user.is_superuser = True

        result = service._get_user_admin_privileges(test_user, test_workspace.id)

        assert result is True

    def test_get_user_admin_privileges_admin(self, test_user, test_workspace):
        """Test admin privilégií admin"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "is_workspace_admin"
        ) as mock_admin:
            mock_admin.return_value = True

            result = service._get_user_admin_privileges(test_user, test_workspace.id)

        assert result is True

    def test_get_user_admin_privileges_denied(self, test_user, test_workspace):
        """Test zamietnutia admin privilégií"""
        service = WorkspaceService()

        with patch.object(
            service.membership_service, "is_workspace_admin"
        ) as mock_admin:
            mock_admin.return_value = False

            result = service._get_user_admin_privileges(test_user, test_workspace.id)

        assert result is False


class TestWorkspaceServiceGetMembers:
    """Testy pre get_workspace_members_with_roles metódu"""

    def test_get_workspace_members_with_roles(self, test_workspace):
        """Test získania členov workspace s rolami"""
        service = WorkspaceService()

        with patch.object(
            test_workspace, "get_all_workspace_users_with_roles"
        ) as mock_get:
            mock_get.return_value = [
                {"user_id": 1, "role": "owner", "username": "testuser"}
            ]

            members = service.get_workspace_members_with_roles(test_workspace)

        assert len(members) == 1
        assert members[0]["role"] == "owner"
        mock_get.assert_called_once()


class TestWorkspaceServiceIntegration:
    """Integračné testy pre WorkspaceService"""

    def test_complete_workspace_lifecycle(self, test_user, test_user2):
        """Test kompletného lifecycle workspace"""
        service = WorkspaceService()

        # 1. Vytvorenie workspace
        with patch.object(Workspace.objects, "create") as mock_create:
            with patch.object(service, "_sync_owner_to_membership") as mock_sync:
                mock_workspace = Mock(id=1, name="Lifecycle Workspace", owner=test_user)
                mock_create.return_value = mock_workspace

                workspace = service.create_workspace(
                    "Lifecycle Workspace", "Test lifecycle", test_user
                )

        assert workspace.id == 1

        # 2. Zmena vlastníctva
        with patch.object(
            service.membership_service, "is_user_workspace_member"
        ) as mock_member:
            with patch.object(Workspace, "save"):
                with patch.object(WorkspaceMembership.objects, "filter"):
                    with patch.object(WorkspaceAdmin.objects, "filter"):
                        mock_member.return_value = True

                        updated_workspace = service.change_ownership(
                            workspace, test_user2.id, test_user, "editor"
                        )

        assert updated_workspace.owner == test_user2

        # 3. Soft delete
        with patch.object(service, "_can_manage_workspace") as mock_can_manage:
            with patch.object(Workspace, "save"):
                with patch.object(cache, "delete"):
                    mock_can_manage.return_value = True
                    workspace.is_active = True

                    soft_deleted = service.soft_delete_workspace(workspace, test_user2)

        assert soft_deleted.is_active is False

        # 4. Aktivácia
        with patch.object(service, "_can_manage_workspace") as mock_can_manage:
            with patch.object(Workspace, "save"):
                with patch.object(cache, "delete"):
                    mock_can_manage.return_value = True

                    activated = service.activate_workspace(workspace, test_user2)

        assert activated.is_active is True

    def test_workspace_ownership_workflow(self, test_user, test_user2, test_workspace):
        """Test workflowu zmeny vlastníctva"""
        service = WorkspaceService()

        # Overenie pôvodného stavu
        assert test_workspace.owner == test_user

        # Zmena vlastníctva
        with patch.object(
            service.membership_service, "is_user_workspace_member"
        ) as mock_member:
            with patch.object(Workspace, "save") as mock_save:
                with patch.object(
                    WorkspaceMembership.objects, "filter"
                ) as mock_membership:
                    with patch.object(WorkspaceAdmin.objects, "filter") as mock_admin:
                        with patch.object(
                            service.membership_service, "invalidate_user_cache"
                        ) as mock_invalidate:
                            mock_member.return_value = True
                            mock_membership.return_value.update.return_value = 1
                            mock_admin.return_value.update.return_value = 1

                            updated_workspace = service.change_ownership(
                                test_workspace, test_user2.id, test_user, "viewer"
                            )

        assert updated_workspace.owner == test_user2
        mock_save.assert_called_once()
        assert mock_invalidate.call_count == 2  # Pre oboch používateľov


class TestWorkspaceServiceEdgeCases:
    """Testy pre edge cases"""

    def test_hard_delete_confirmation_validation(self, test_user, test_workspace):
        """Test validácie potvrdenia pre hard delete"""
        service = WorkspaceService()

        # Neplatný typ confirmation_data
        with pytest.raises(ValidationError) as exc_info:
            service._validate_hard_delete_confirmation(
                test_workspace, "not_a_dict", False, test_user
            )

        assert "must be an object" in str(exc_info.value)

    def test_workspace_name_trimming(self, test_user):
        """Test orezávania medzier v názve workspace"""
        service = WorkspaceService()

        with patch.object(Workspace.objects, "create") as mock_create:
            with patch.object(service, "_sync_owner_to_membership"):
                mock_workspace = Mock(id=1, owner=test_user)
                mock_create.return_value = mock_workspace

                workspace = service.create_workspace(
                    "  Test Workspace  ", "Description", test_user
                )

        # Skontroluj že názov bol orezaný
        mock_create.assert_called_with(
            name="Test Workspace",  # Orezaný názov
            description="Description",
            owner=test_user,
        )

    def test_cache_invalidation_on_hard_delete(self, test_user, test_workspace):
        """Test invalidácie cache pri hard delete"""
        service = WorkspaceService()
        confirmation_data = {"standard": True, "workspace_name": test_workspace.name}

        with patch.object(service, "_get_user_admin_privileges") as mock_admin_priv:
            with patch.object(Transaction.objects, "filter"):
                with patch.object(Workspace, "delete"):
                    with patch.object(cache, "delete") as mock_cache_delete:
                        mock_admin_priv.return_value = False

                        service.hard_delete_workspace(
                            test_workspace, test_user, confirmation_data
                        )

        # Skontroluj že cache bola invalidovaná
        assert mock_cache_delete.call_count >= 1
        mock_cache_delete.assert_any_call(f"workspace_{test_workspace.id}")
