# finance/tests/unit/test_service_workspace_context.py
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from rest_framework.exceptions import PermissionDenied

from finance.models import Workspace, WorkspaceAdmin, WorkspaceMembership
from finance.services.impersonation_service import ImpersonationService
from finance.services.membership_cache_service import MembershipCacheService
from finance.services.membership_service import MembershipService
from finance.services.workspace_context_service import WorkspaceContextService


def create_mock_request(user=None, get_params=None, data=None, kwargs=None):
    """
    Helper funkcia pre vytvorenie správneho mock requestu.
    Použiteľná vo všetkých test classes.
    """
    request = MagicMock()

    if user and hasattr(user, "is_authenticated"):
        request.user = user
    else:
        request.user = MagicMock()
        request.user.is_authenticated = True
        request.user.is_superuser = False
        request.user.id = getattr(user, "id", 1)

    request.user_permissions = {
        "is_superuser": False,
        "is_workspace_admin": None,
        "workspace_role": None,
        "current_workspace_id": None,
        "workspace_exists": False,
    }

    request.GET = get_params or {}
    request.data = data or {}
    request.kwargs = kwargs or {}
    return request


class TestWorkspaceContextService:
    """Testy pre WorkspaceContextService"""

    _create_mock_request = staticmethod(create_mock_request)

    def test_build_request_context_anonymous_user(self):
        """Test kontextu pre neprihláseného používateľa"""
        service = WorkspaceContextService()
        request = self._create_mock_request()
        anonymous_user = AnonymousUser()
        request.user = anonymous_user

        service.build_request_context(request)

        assert request.target_user == anonymous_user
        assert request.is_admin_impersonation is False
        assert request.workspace is None

    def test_build_request_context_authenticated_no_params(self, test_user):
        """Test kontextu pre prihláseného používateľa bez parametrov"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)

        service.build_request_context(request)

        assert request.target_user == test_user
        assert request.is_admin_impersonation is False
        assert request.workspace is None

    def test_build_request_context_with_workspace_id(self, test_user, test_workspace):
        """Test kontextu s workspace ID"""
        service = WorkspaceContextService()
        request = self._create_mock_request(
            user=test_user, get_params={"workspace_id": str(test_workspace.id)}
        )

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_get.return_value = test_workspace

            service.build_request_context(request)

        assert request.workspace == test_workspace
        assert request.user_permissions["workspace_exists"] is True
        assert request.user_permissions["current_workspace_id"] == test_workspace.id

    def test_build_request_context_with_invalid_workspace_id(self, test_user):
        """Test kontextu s neplatným workspace ID"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.GET = {"workspace_id": "invalid"}

        service.build_request_context(request)

        assert request.workspace is None
        assert request.user_permissions["workspace_exists"] is False

    def test_build_request_context_with_nonexistent_workspace(self, test_user):
        """Test kontextu s neexistujúcim workspace"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.GET = {"workspace_id": "999"}

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_get.side_effect = Workspace.DoesNotExist

            service.build_request_context(request)

        assert request.workspace is None
        assert request.user_permissions["workspace_exists"] is False

    def test_build_request_context_with_user_id_param(self, test_user, test_user2):
        """Test kontextu s user_id parametrom pre impersonáciu"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.GET = {"user_id": str(test_user2.id)}

        with patch.object(
            service.impersonation_service, "check_rate_limit"
        ) as mock_rate:
            with patch.object(
                service.impersonation_service, "process_impersonation"
            ) as mock_impersonate:
                mock_rate.return_value = True
                mock_impersonate.return_value = (test_user2, True, "superuser", [1, 2])

                service.build_request_context(request)

        assert request.target_user == test_user2
        assert request.is_admin_impersonation is True
        assert request.impersonation_type == "superuser"

    def test_build_request_context_rate_limit_exceeded(self, test_user, test_user2):
        """Test kontextu s prekročením rate limitu pre impersonáciu"""
        service = WorkspaceContextService()
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.GET = {"user_id": str(test_user2.id)}

        with patch.object(
            service.impersonation_service, "check_rate_limit"
        ) as mock_rate:
            mock_rate.return_value = False

            service.build_request_context(request)

        assert request.target_user == test_user
        assert request.is_admin_impersonation is False

    def test_build_request_context_database_error(self, test_user):
        """Test kontextu s databázovou chybou"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)

        request.GET = {"workspace_id": "1"}

        with patch('finance.services.workspace_context_service.Workspace.objects') as mock_objects:
            mock_objects.select_related.return_value.get.side_effect = DatabaseError("Connection failed")

            with pytest.raises(DatabaseError):
                service.build_request_context(request)

    def test_initialize_request_defaults(self):
        """Test inicializácie predvolených hodnôt requestu"""
        service = WorkspaceContextService()
        request = self._create_mock_request()

        service._initialize_request_defaults(request)

        assert request.target_user == request.user
        assert request.is_admin_impersonation is False
        assert request.impersonation_type is None
        assert request.impersonation_workspace_ids == []
        assert request.workspace is None
        assert request.user_permissions["is_superuser"] is False

    def test_get_user_id_param_valid(self):
        """Test získania platného user_id parametra"""
        service = WorkspaceContextService()
        request = Mock()
        request.GET = {"user_id": "123"}
        request.data = {}

        result = service._get_user_id_param(request)

        assert result == 123

    def test_get_user_id_param_invalid(self):
        """Test získania neplatného user_id parametra"""
        service = WorkspaceContextService()
        request = Mock()
        request.GET = {"user_id": "invalid"}
        request.data = {}

        result = service._get_user_id_param(request)

        assert result is None

    def test_get_validated_workspace_id_from_view_kwargs(self, test_user):
        """Test získania workspace ID z view kwargs"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        view_kwargs = {"pk": "123"}

        with patch('finance.services.workspace_context_service.Workspace.objects') as mock_objects:
            mock_workspace = MagicMock()
            mock_workspace.id = 123
            mock_objects.select_related.return_value.get.return_value = mock_workspace

            result = service._get_validated_workspace_id(request, view_kwargs)

            assert result == 123
            mock_objects.select_related.return_value.get.assert_called_once_with(id=123)

    def test_get_validated_workspace_id_from_request_kwargs(self, test_user):
        """Test získania workspace ID z request kwargs"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.kwargs = {"pk": "456"}

        with patch('finance.services.workspace_context_service.Workspace.objects') as mock_objects:
            mock_workspace = MagicMock()
            mock_workspace.id = 456
            mock_objects.select_related.return_value.get.return_value = mock_workspace

            result = service._get_validated_workspace_id(request, None)

            assert result == 456
            mock_objects.select_related.return_value.get.assert_called_once_with(id=456)

    def test_get_validated_workspace_id_from_get_params(self, test_user):
        """Test získania workspace ID z GET parametrov"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user, get_params={"workspace_id": "789"})

        with patch('finance.services.workspace_context_service.Workspace.objects') as mock_objects:
            mock_workspace = MagicMock()
            mock_workspace.id = 789
            mock_objects.select_related.return_value.get.return_value = mock_workspace

            result = service._get_validated_workspace_id(request, None)

            assert result == 789
            mock_objects.select_related.return_value.get.assert_called_once_with(id=789)

    def test_get_validated_workspace_id_from_request_data(self, test_user):
        """Test získania workspace ID z request data"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user, data={"workspace_id": "101"})

        with patch('finance.services.workspace_context_service.Workspace.objects') as mock_objects:
            mock_workspace = MagicMock()
            mock_workspace.id = 101
            mock_objects.select_related.return_value.get.return_value = mock_workspace

            result = service._get_validated_workspace_id(request, None)

            assert result == 101
            mock_objects.select_related.return_value.get.assert_called_once_with(id=101)

    def test_extract_from_view_kwargs(self):
        """Test extrakcie workspace ID z view kwargs"""
        service = WorkspaceContextService()

        # Test s pk
        result = service._extract_from_view_kwargs({"pk": "123"})
        assert result == "123"

        # Test s workspace_pk
        result = service._extract_from_view_kwargs({"workspace_pk": "456"})
        assert result == "456"

        # Test s workspace_id
        result = service._extract_from_view_kwargs({"workspace_id": "789"})
        assert result == "789"
        
        # Test priority: workspace_pk should be prioritized over pk
        result = service._extract_from_view_kwargs({"pk": "123", "workspace_pk": "456"})
        assert result == "456"

        # Test bez kwargs
        result = service._extract_from_view_kwargs(None)
        assert result is None

    def test_extract_from_request_kwargs(self):
        """Test extrakcie workspace ID z request kwargs"""
        service = WorkspaceContextService()
        request = Mock()
        request.kwargs = {"pk": "123", "workspace_pk": "456"}

        result = service._extract_from_request_kwargs(request)
        assert result == "456"  # workspace_pk má prioritu

    def test_set_basic_permissions(self, test_user):
        """Test nastavenia základných oprávnení"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.user.is_superuser = True

        service._set_basic_permissions(request)

        assert request.user_permissions["is_superuser"] is True

    def test_reset_impersonation(self, test_user):
        """Test resetovania impersonácie"""
        service = WorkspaceContextService()
        request = Mock()
        request.user = test_user
        request.target_user = Mock()
        request.is_admin_impersonation = True
        request.impersonation_type = "superuser"
        request.impersonation_workspace_ids = [1, 2]

        service._reset_impersonation(request)

        assert request.target_user == test_user
        assert request.is_admin_impersonation is False
        assert request.impersonation_type is None
        assert request.impersonation_workspace_ids == []


    def test_process_workspace_context_user_is_member(self, test_user, test_workspace):
        """Test spracovania kontextu pre člena workspace"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.user_permissions["workspace_exists"] = True
        request.workspace = test_workspace

        with patch.object(service.membership_service, 'get_user_workspace_role') as mock_get_role, \
             patch.object(service.membership_service, 'is_workspace_admin') as mock_is_admin:
            mock_get_role.return_value = 'editor'
            mock_is_admin.return_value = False

            service._process_workspace_context(request, test_workspace.id)

            assert request.user_permissions['workspace_role'] == 'editor'
            assert request.user_permissions['is_workspace_admin'] is False
            mock_get_role.assert_called_once_with(request.user.id, test_workspace.id)
            mock_is_admin.assert_called_once_with(request.user.id, test_workspace.id)

    def test_process_workspace_context_user_is_admin_not_member(self, test_user, test_workspace):
        """Test spracovania kontextu pre admina, ktorý nie je členom workspace"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.user_permissions["workspace_exists"] = True
        request.workspace = test_workspace

        with patch.object(service.membership_service, 'get_user_workspace_role') as mock_get_role, \
             patch.object(service.membership_service, 'is_workspace_admin') as mock_is_admin:
            mock_get_role.return_value = None
            mock_is_admin.return_value = True

            service._process_workspace_context(request, test_workspace.id)

            assert request.user_permissions['workspace_role'] is None
            assert request.user_permissions['is_workspace_admin'] is True
            mock_get_role.assert_called_once_with(request.user.id, test_workspace.id)
            mock_is_admin.assert_called_once_with(request.user.id, test_workspace.id)

    def test_process_workspace_context_user_is_neither_member_nor_admin(self, test_user, test_workspace):
        """Test spracovania kontextu pre používateľa, ktorý nie je ani člen ani admin"""
        service = WorkspaceContextService()
        request = self._create_mock_request(user=test_user)
        request.user_permissions["workspace_exists"] = True
        request.workspace = test_workspace

        with patch.object(service.membership_service, 'get_user_workspace_role') as mock_get_role, \
             patch.object(service.membership_service, 'is_workspace_admin') as mock_is_admin:
            mock_get_role.return_value = None
            mock_is_admin.return_value = False

            service._process_workspace_context(request, test_workspace.id)

            assert request.user_permissions['workspace_role'] is None
            assert request.user_permissions['is_workspace_admin'] is False
            mock_get_role.assert_called_once_with(request.user.id, test_workspace.id)
            mock_is_admin.assert_called_once_with(request.user.id, test_workspace.id)


class TestImpersonationService:
    """Testy pre ImpersonationService"""

    def test_check_rate_limit_first_time(self):
        """Test rate limitu prvýkrát"""
        service = ImpersonationService()

        with patch.object(cache, "get") as mock_get:
            with patch.object(cache, "set") as mock_set:
                mock_get.return_value = 0

                result = service.check_rate_limit(123)

        assert result is True
        mock_set.assert_called_once()

    def test_check_rate_limit_exceeded(self):
        """Test prekročenia rate limitu"""
        service = ImpersonationService()

        with patch.object(cache, "get") as mock_get:
            mock_get.return_value = 15  # Nad limitom

            result = service.check_rate_limit(123)

        assert result is False

    def test_validate_impersonation_target_self(self, test_user):
        """Test validácie impersonácie seba samého"""
        service = ImpersonationService()

        result = service.validate_impersonation_target(test_user, test_user)

        assert result is False

    def test_validate_impersonation_target_superuser_non_superuser_admin(
        self, test_user, test_user2
    ):
        """Test validácie impersonácie superuser ne-superuser adminom"""
        service = ImpersonationService()
        test_user2.is_superuser = True
        test_user.is_superuser = False

        result = service.validate_impersonation_target(test_user, test_user2)

        assert result is False

    def test_validate_impersonation_target_valid(self, test_user, test_user2):
        """Test platnej validácie impersonácie"""
        service = ImpersonationService()
        test_user.is_superuser = True
        test_user2.is_superuser = False

        result = service.validate_impersonation_target(test_user, test_user2)

        assert result is True

    def test_process_superuser_impersonation_with_workspace(
        self, test_user, test_user2
    ):
        """Test superuser impersonácie s konkrétnym workspace"""
        service = ImpersonationService()

        with patch.object(
            service.membership_service, "is_user_workspace_member"
        ) as mock_member:
            mock_member.return_value = True

            result = service.process_superuser_impersonation(test_user, test_user2, 123)

        assert result == [123]

    def test_process_superuser_impersonation_without_workspace(
        self, test_user, test_user2
    ):
        """Test superuser impersonácie bez konkrétneho workspace"""
        service = ImpersonationService()

        with patch.object(
            service.membership_service, "get_comprehensive_user_data"
        ) as mock_data:
            mock_data.return_value = {"all_workspace_ids": [1, 2, 3]}

            result = service.process_superuser_impersonation(
                test_user, test_user2, None
            )

        assert result == [1, 2, 3]

    def test_process_workspace_admin_impersonation_with_workspace(
        self, test_user, test_user2
    ):
        """Test workspace admin impersonácie s konkrétnym workspace"""
        service = ImpersonationService()

        with patch.object(
            service.membership_service, "is_workspace_admin"
        ) as mock_admin:
            mock_admin.return_value = True

            result = service.process_workspace_admin_impersonation(
                test_user, test_user2, 123
            )

        assert result == [123]

    def test_process_workspace_admin_impersonation_without_workspace(
        self, test_user, test_user2
    ):
        """Test workspace admin impersonácie bez konkrétneho workspace"""
        service = ImpersonationService()

        with patch.object(
            service.membership_service, "get_comprehensive_user_data"
        ) as mock_data:
            mock_data.side_effect = [
                {"admin_workspaces": {1, 2}},  # Admin data
                {"all_workspace_ids": [2, 3]},  # Target data
            ]

            result = service.process_workspace_admin_impersonation(
                test_user, test_user2, None
            )

        assert result == [2]  # Len spoločné workspaces

    def test_process_impersonation_superuser(self, test_user, test_user2):
        """Test spracovania impersonácie pre superuser"""
        service = ImpersonationService()
        test_user.is_superuser = True

        with patch.object(service, "validate_impersonation_target") as mock_validate:
            with patch.object(
                service, "process_superuser_impersonation"
            ) as mock_process:
                mock_validate.return_value = True
                mock_process.return_value = [1, 2]

                result = service.process_impersonation(test_user, test_user2.id, None)

        assert result[0] == test_user2
        assert result[1] is True
        assert result[2] == "superuser"

    def test_process_impersonation_workspace_admin(self, test_user, test_user2):
        """Test spracovania impersonácie pre workspace admin"""
        service = ImpersonationService()
        test_user.is_superuser = False

        with patch.object(service, "validate_impersonation_target") as mock_validate:
            with patch.object(
                service, "process_workspace_admin_impersonation"
            ) as mock_process:
                mock_validate.return_value = True
                mock_process.return_value = [1, 2]

                result = service.process_impersonation(test_user, test_user2.id, None)

        assert result[0] == test_user2
        assert result[1] is True
        assert result[2] == "workspace_admin"

    def test_process_impersonation_user_not_found(self, test_user):
        """Test spracovania impersonácie s neexistujúcim používateľom"""
        service = ImpersonationService()

        result = service.process_impersonation(test_user, 999, None)

        assert result[0] == test_user
        assert result[1] is False

    def test_process_impersonation_validation_failed(self, test_user, test_user2):
        """Test spracovania impersonácie s neúspešnou validáciou"""
        service = ImpersonationService()

        with patch.object(service, "validate_impersonation_target") as mock_validate:
            mock_validate.return_value = False

            result = service.process_impersonation(test_user, test_user2.id, None)

        assert result[0] == test_user
        assert result[1] is False


class TestMembershipService:
    """Testy pre MembershipService"""

    def test_update_member_role_success(self, test_user, test_user2, test_workspace):
        """Test úspešnej zmeny roly člena"""
        service = MembershipService()

        with patch.object(service, "_can_manage_members") as mock_can_manage:
            with patch.object(WorkspaceMembership.objects, "get") as mock_get:
                # 🔧 POUŽI MAGICMOCK so save metódou
                mock_membership = MagicMock()
                mock_membership.role = "viewer"
                mock_membership.user = test_user2
                mock_membership.save = MagicMock()

                mock_can_manage.return_value = True
                mock_get.return_value = mock_membership

                with patch.object(
                    service.cache_service, "invalidate_user_cache"
                ) as mock_invalidate:

                    result = service.update_member_role(
                        test_workspace, test_user2.id, "editor", test_user
                    )

        assert result.role == "editor"
        mock_membership.save.assert_called_once()
        mock_invalidate.assert_called_once_with(test_user2.id)

    def test_update_member_role_permission_denied(
        self, test_user, test_user2, test_workspace
    ):
        """Test zmeny roly bez oprávnenia"""
        service = MembershipService()

        with patch.object(service, "_can_manage_members") as mock_can_manage:
            mock_can_manage.return_value = False

            with pytest.raises(PermissionDenied):
                service.update_member_role(
                    test_workspace, test_user2.id, "editor", test_user
                )

    def test_update_member_role_invalid_role(
        self, test_user, test_user2, test_workspace
    ):
        """Test zmeny roly na neplatnú rolu"""
        service = MembershipService()

        with patch.object(service, "_can_manage_members") as mock_can_manage:
            mock_can_manage.return_value = True

            with pytest.raises(ValidationError):
                service.update_member_role(
                    test_workspace, test_user2.id, "invalid_role", test_user
                )

    def test_update_member_role_user_not_member(
        self, test_user, test_user2, test_workspace
    ):
        """Test zmeny roly pre používateľa ktorý nie je členom"""
        service = MembershipService()

        with patch.object(service, "_can_manage_members") as mock_can_manage:
            with patch.object(WorkspaceMembership.objects, "get") as mock_get:
                mock_can_manage.return_value = True
                mock_get.side_effect = WorkspaceMembership.DoesNotExist()

                with pytest.raises(ValidationError):
                    service.update_member_role(
                        test_workspace, test_user2.id, "editor", test_user
                    )

    def test_remove_member_success(self, test_user, test_user2, test_workspace):
        """Test úspešného odstránenia člena"""
        service = MembershipService()

        with patch.object(service, "_can_manage_members") as mock_can_manage:
            with patch.object(WorkspaceMembership.objects, "get") as mock_get:
                with patch.object(
                    WorkspaceAdmin.objects, "filter"
                ) as mock_admin_filter:
                    with patch.object(
                        service.cache_service, "invalidate_user_cache"
                    ) as mock_invalidate:
                        mock_can_manage.return_value = True
                        mock_membership = Mock(role="editor", user=test_user2)
                        mock_get.return_value = mock_membership
                        mock_admin_filter.return_value.update.return_value = 1

                        result = service.remove_member(
                            test_workspace, test_user2.id, test_user
                        )

        assert result is True
        mock_invalidate.assert_called_once_with(test_user2.id)

    def test_remove_member_not_found(self, test_user, test_user2, test_workspace):
        """Test odstránenia neexistujúceho člena"""
        service = MembershipService()

        with patch.object(service, "_can_manage_members") as mock_can_manage:
            with patch.object(WorkspaceMembership.objects, "get") as mock_get:
                mock_can_manage.return_value = True
                mock_get.side_effect = WorkspaceMembership.DoesNotExist()

                result = service.remove_member(test_workspace, test_user2.id, test_user)

        assert result is False

    def test_remove_member_owner(self, test_user, test_workspace):
        """Test pokusu o odstránenie vlastníka"""
        service = MembershipService()

        with patch.object(service, "_can_manage_members") as mock_can_manage:
            mock_can_manage.return_value = True

            with pytest.raises(ValidationError):
                service.remove_member(test_workspace, test_user.id, test_user)

    def test_get_workspace_members_with_roles_success(self, test_user, test_workspace):
        """Test získania zoznamu členov s rolami"""
        service = MembershipService()

        # Create a mock user and membership
        mock_user = MagicMock()
        mock_user.id = 123
        mock_user.username = "testuser_editor"
        mock_user.email = "editor@example.com"

        mock_membership = MagicMock()
        mock_membership.user = mock_user
        mock_membership.role = "editor"
        mock_membership.joined_at = "2024-01-01T00:00:00Z"


        with patch.object(service, "_can_view_members") as mock_can_view:
            with patch('finance.services.membership_service.WorkspaceMembership.objects') as mock_wsm_objects:
                with patch.object(service.cache_service, "is_workspace_admin") as mock_is_admin:
                    mock_can_view.return_value = True
                    mock_wsm_objects.filter.return_value.select_related.return_value = [mock_membership]
                    mock_is_admin.return_value = False

                    result = service.get_workspace_members_with_roles(
                        test_workspace, test_user
                    )

        assert len(result) == 1
        member = result[0]
        assert member["username"] == "testuser_editor"
        assert member["role"] == "editor"
        assert member["email"] == "editor@example.com"

    def test_get_workspace_members_with_roles_permission_denied(
        self, test_user, test_workspace
    ):
        """Test získania zoznamu členov bez oprávnenia"""
        service = MembershipService()

        with patch.object(service, "_can_view_members") as mock_can_view:
            mock_can_view.return_value = False

            with pytest.raises(PermissionDenied):
                service.get_workspace_members_with_roles(test_workspace, test_user)

    def test_get_user_workspace_permissions_owner(self, test_user, test_workspace):
        """Test získania oprávnení pre vlastníka"""
        service = MembershipService()

        with patch.object(
            service.cache_service, "get_comprehensive_user_data"
        ) as mock_data:
            with patch.object(
                service.cache_service, "is_workspace_admin"
            ) as mock_is_admin:
                mock_data.return_value = {
                    "memberships": {test_workspace.id: {"role": "owner"}}
                }
                mock_is_admin.return_value = False

                permissions = service.get_user_workspace_permissions(
                    test_user, test_workspace
                )

        assert permissions["is_workspace_owner"] is True
        assert permissions["can_manage_members"] is True
        assert permissions["can_hard_delete"] is True

    def test_get_user_workspace_permissions_editor(self, test_user, test_workspace):
        """Test získania oprávnení pre editora"""
        service = MembershipService()

        with patch.object(
            service.cache_service, "get_comprehensive_user_data"
        ) as mock_data:
            with patch.object(
                service.cache_service, "is_workspace_admin"
            ) as mock_is_admin:
                mock_data.return_value = {
                    "memberships": {test_workspace.id: {"role": "editor"}}
                }
                mock_is_admin.return_value = False

                permissions = service.get_user_workspace_permissions(
                    test_user, test_workspace
                )

        assert permissions["workspace_role"] == "editor"
        assert permissions["can_create_transactions"] is True
        assert permissions["can_manage_members"] is False

    def test_get_user_workspace_permissions_viewer(self, test_user, test_workspace):
        """Test získania oprávnení pre prehliadača"""
        service = MembershipService()

        with patch.object(
            service.cache_service, "get_comprehensive_user_data"
        ) as mock_data:
            with patch.object(
                service.cache_service, "is_workspace_admin"
            ) as mock_is_admin:
                mock_data.return_value = {
                    "memberships": {test_workspace.id: {"role": "viewer"}}
                }
                mock_is_admin.return_value = False

                permissions = service.get_user_workspace_permissions(
                    test_user, test_workspace
                )

        assert permissions["workspace_role"] == "viewer"
        assert permissions["can_create_transactions"] is False
        assert permissions["can_view_transactions"] is True

    def test_get_user_workspace_permissions_admin(self, test_user, test_workspace):
        """Test získania oprávnení pre admina"""
        service = MembershipService()

        with patch.object(
            service.cache_service, "get_comprehensive_user_data"
        ) as mock_data:
            with patch.object(
                service.cache_service, "is_workspace_admin"
            ) as mock_is_admin:
                mock_data.return_value = {
                    "memberships": {
                        test_workspace.id: {
                            "role": "viewer"
                        }  # Môže byť aj viewer, ale je admin
                    }
                }
                mock_is_admin.return_value = True

                permissions = service.get_user_workspace_permissions(
                    test_user, test_workspace
                )

        assert permissions["is_workspace_admin"] is True
        assert permissions["can_manage_members"] is True
        assert permissions["can_manage_categories"] is True

    def test_can_manage_members_superuser(self, test_user, test_workspace):
        """Test oprávnenia superuser spravovať členov"""
        service = MembershipService()
        test_user.is_superuser = True

        result = service._can_manage_members(test_workspace, test_user)

        assert result is True

    def test_can_manage_members_owner(self, test_user, test_workspace):
        """Test oprávnenia vlastníka spravovať členov"""
        service = MembershipService()

        with patch.object(
            service.cache_service, "get_user_workspace_role"
        ) as mock_role:
            with patch.object(
                service.cache_service, "is_workspace_admin"
            ) as mock_admin:
                mock_role.return_value = "owner"
                mock_admin.return_value = False

                result = service._can_manage_members(test_workspace, test_user)

        assert result is True

    def test_can_manage_members_admin(self, test_user, test_workspace):
        """Test oprávnenia admin spravovať členov"""
        service = MembershipService()

        with patch.object(
            service.cache_service, "get_user_workspace_role"
        ) as mock_role:
            with patch.object(
                service.cache_service, "is_workspace_admin"
            ) as mock_admin:
                mock_role.return_value = "editor"  # Nie je owner
                mock_admin.return_value = True  # Ale je admin

                result = service._can_manage_members(test_workspace, test_user)

        assert result is True

    def test_can_view_members_superuser(self, test_user, test_workspace):
        """Test oprávnenia superuser prezerať členov"""
        service = MembershipService()
        test_user.is_superuser = True

        result = service._can_view_members(test_workspace, test_user)

        assert result is True

    def test_can_view_members_member(self, test_user, test_workspace):
        """Test oprávnenia člena prezerať členov"""
        service = MembershipService()

        with patch.object(
            service.cache_service, "is_user_workspace_member"
        ) as mock_member:
            mock_member.return_value = True

            result = service._can_view_members(test_workspace, test_user)

        assert result is True

    def test_calculate_permissions_inactive_workspace(self):
        """Test výpočtu oprávnení pre neaktívny workspace"""
        service = MembershipService()

        permissions = service._calculate_permissions(
            user_role="owner",
            is_owner=True,
            is_admin=False,
            is_superuser=False,
            workspace_active=False,
        )

        assert permissions["can_view"] is True  # Owner vidí aj neaktívne
        assert (
            permissions["can_create_transactions"] is False
        )  # Nemôže vytvárať transakcie

    def test_calculate_permissions_superuser_inactive(self):
        """Test výpočtu oprávnení pre superuser v neaktívnom workspace"""
        service = MembershipService()

        permissions = service._calculate_permissions(
            user_role="viewer",
            is_owner=False,
            is_admin=False,
            is_superuser=True,
            workspace_active=False,
        )

        assert permissions["can_view"] is True
        assert permissions["can_see_inactive"] is True

        # These should be False because workspace is inactive
        assert permissions["can_edit"] is False
        assert permissions["can_deactivate"] is False
        assert permissions["can_soft_delete"] is False
        assert permissions["can_manage_members"] is False
        assert permissions["can_invite"] is False
        assert permissions["can_create_transactions"] is False
        assert permissions["can_manage_categories"] is False
        assert permissions["can_transfer_ownership"] is False

        # This should be True - superuser can activate inactive workspace
        assert permissions["can_activate"] is True

        # Superuser flags
        assert permissions["is_superuser"] is True
        assert permissions["is_workspace_admin"] is False
        assert permissions["is_workspace_owner"] is False
        assert permissions["workspace_role"] == "viewer"


class TestMembershipCacheService:
    """Testy pre MembershipCacheService"""

    def test_get_comprehensive_user_data_cache_hit(self, test_user):
        """Test získania komplexných dát z cache"""
        service = MembershipCacheService()
        cached_data = {
            "memberships": {},
            "admin_workspaces": set(),
            "all_workspace_ids": [],
        }

        with patch.object(cache, "get") as mock_get:
            mock_get.return_value = cached_data

            result = service.get_comprehensive_user_data(test_user.id)

        assert result == cached_data

    def test_get_comprehensive_user_data_cache_miss(self, test_user):
        """Test získania komplexných dát z databázy"""
        service = MembershipCacheService()

        with patch.object(cache, "get") as mock_get:
            with patch.object(cache, "set") as mock_set:
                with patch.object(service, "_fetch_optimized_user_data") as mock_fetch:
                    mock_get.return_value = None
                    mock_fetch.return_value = {
                        "memberships": {},
                        "admin_workspaces": set(),
                        "all_workspace_ids": [],
                    }

                    result = service.get_comprehensive_user_data(test_user.id)

        assert result is not None
        mock_set.assert_called_once()

    def test_get_user_workspace_role_from_comprehensive_cache(self, test_user):
        """Test získania roly z komplexnej cache"""
        service = MembershipCacheService()
        cached_data = {
            "roles": {1: "editor"},
            "admin_workspaces": set(),
            "all_workspace_ids": [1],
        }

        with patch.object(cache, "get") as mock_get:
            mock_get.return_value = cached_data

            result = service.get_user_workspace_role(test_user.id, 1)

        assert result == "editor"

    def test_get_user_workspace_role_from_specific_cache(self, test_user):
        """Test získania roly zo špecifickej cache"""
        service = MembershipCacheService()

        with patch.object(cache, "get") as mock_get:
            with patch.object(cache, "set") as mock_set:
                with patch.object(WorkspaceMembership.objects, "filter") as mock_filter:
                    mock_get.side_effect = [
                        None,
                        "editor",
                    ]  # Comprehensive miss, specific hit
                    mock_filter.return_value.values.return_value.first.return_value = {
                        "role": "editor"
                    }

                    result = service.get_user_workspace_role(test_user.id, 1)

        assert result == "editor"

    def test_get_user_workspace_role_from_database(self, test_user):
        """Test získania roly z databázy"""
        service = MembershipCacheService()

        with patch.object(cache, "get") as mock_get:
            with patch.object(cache, "set") as mock_set:
                with patch.object(WorkspaceMembership.objects, "filter") as mock_filter:
                    mock_get.return_value = None  # Obe cache miss
                    mock_filter.return_value.values.return_value.first.return_value = {
                        "role": "owner"
                    }

                    result = service.get_user_workspace_role(test_user.id, 1)

        assert result == "owner"
        mock_set.assert_called_once()

    def test_is_workspace_admin_from_comprehensive_cache(self, test_user):
        """Test kontroly admin statusu z komplexnej cache"""
        service = MembershipCacheService()
        cached_data = {"admin_workspaces": {1, 2}}

        with patch.object(cache, "get") as mock_get:
            mock_get.return_value = cached_data

            result = service.is_workspace_admin(test_user.id, 1)
            result2 = service.is_workspace_admin(test_user.id, 3)

        assert result is True
        assert result2 is False

    def test_is_user_workspace_member_from_comprehensive_cache(self, test_user):
        """Test kontroly členstva z komplexnej cache"""
        service = MembershipCacheService()
        cached_data = {
            "roles": {1: "editor", 2: "viewer"},
            "admin_workspaces": set(),
            "all_workspace_ids": [1, 2],
        }

        with patch.object(cache, "get") as mock_get:
            mock_get.return_value = cached_data

            result = service.is_user_workspace_member(test_user.id, 1)
            result2 = service.is_user_workspace_member(test_user.id, 3)

        assert result is True
        assert result2 is False

    def test_invalidate_user_cache(self, test_user):
        """Test invalidácie user cache"""
        service = MembershipCacheService()

        with patch.object(cache, "delete") as mock_delete:
            service.invalidate_user_cache(test_user.id)

        mock_delete.assert_called_once_with(f"comprehensive_membership_{test_user.id}")

    def test_fetch_optimized_user_data(self, test_user):
        """Test optimalizovaného načítania user dát"""
        service = MembershipCacheService()

        with patch.object(WorkspaceMembership.objects, "filter") as mock_memberships:
            with patch.object(WorkspaceAdmin.objects, "filter") as mock_admins:
                mock_memberships.return_value.select_related.return_value.values.return_value = [
                    {
                        "workspace_id": 1,
                        "role": "editor",
                        "workspace__name": "Test",
                        "workspace__is_active": True,
                    }
                ]
                mock_admins.return_value.values_list.return_value = [1, 2]

                result = service._fetch_optimized_user_data(test_user.id)

        assert "roles" in result
        assert result["roles"][1] == "editor"
        assert len(result["roles"]) == 1
        assert result["admin_workspaces"] == {1, 2}
        assert result["all_workspace_ids"] == [1]


class TestIntegrationBetweenServices:
    """Integračné testy medzi službami"""

    _create_mock_request = staticmethod(create_mock_request)

    def test_complete_context_flow_with_impersonation(
        self, test_user, test_user2, test_workspace
    ):
        """Test kompletného toku kontextu s impersonáciou"""
        # Setup context service
        context_service = WorkspaceContextService()

        # Mock request
        request = self._create_mock_request(user=test_user)
        request.GET = {
            "user_id": str(test_user2.id),
            "workspace_id": str(test_workspace.id),
        }

        # Mock impersonation service
        with patch.object(
            context_service.impersonation_service, "check_rate_limit"
        ) as mock_rate:
            with patch.object(
                context_service.impersonation_service, "process_impersonation"
            ) as mock_impersonate:
                with patch.object(Workspace.objects, "get") as mock_get:
                    mock_rate.return_value = True
                    mock_impersonate.return_value = (
                        test_user2,
                        True,
                        "superuser",
                        [test_workspace.id],
                    )
                    mock_get.return_value = test_workspace

                    context_service.build_request_context(request)

        assert request.target_user == test_user2
        assert request.is_admin_impersonation is True
        assert request.workspace == test_workspace

    def test_membership_workflow_with_cache(
        self, test_user, test_user2, test_workspace
    ):
        """Test membership workflow s cache"""
        membership_service = MembershipService()

        # Test update role
        with patch.object(
            membership_service.cache_service, "get_user_workspace_role"
        ) as mock_role:
            with patch.object(
                membership_service.cache_service, "is_workspace_admin"
            ) as mock_admin:
                with patch.object(WorkspaceMembership.objects, "get") as mock_get:
                    mock_membership = MagicMock()
                    mock_membership.role = "viewer"
                    mock_membership.user = test_user2
                    mock_membership.save = MagicMock()

                    mock_role.return_value = "owner"
                    mock_admin.return_value = False
                    mock_get.return_value = mock_membership

                    with patch.object(
                        membership_service.cache_service,
                        "invalidate_user_cache",  # 👈 POUŽI MEMBERSHIP_SERVICE.CACHE_SERVICE
                    ) as mock_invalidate:

                        membership_service.update_member_role(
                            test_workspace, test_user2.id, "editor", test_user
                        )

        mock_invalidate.assert_called_once_with(test_user2.id)

    def test_permissions_calculation_flow(self, test_user, test_workspace):
        """Test toku výpočtu oprávnení"""
        membership_service = MembershipService()

        with patch.object(
            membership_service.cache_service, "get_comprehensive_user_data"
        ) as mock_data:
            with patch.object(
                membership_service.cache_service, "is_workspace_admin"
            ) as mock_admin:
                mock_data.return_value = {
                    "memberships": {test_workspace.id: {"role": "editor"}}
                }
                mock_admin.return_value = False

                permissions = membership_service.get_user_workspace_permissions(
                    test_user, test_workspace
                )

        assert permissions["workspace_role"] == "editor"
        assert permissions["can_create_transactions"] is True
        assert permissions["can_manage_members"] is False
