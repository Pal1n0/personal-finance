# tests/test_permissions.py
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase

from finance.models import Workspace, WorkspaceAdmin, WorkspaceMembership
from finance.permissions import (
    IsSuperuser,
    IsWorkspaceAdmin,
    IsWorkspaceEditor,
    IsWorkspaceMember,
    IsWorkspaceOwner,
)
from finance.services.membership_cache_service import MembershipCacheService
from finance.services.workspace_context_service import WorkspaceContextService

User = get_user_model()


class BasePermissionTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.context_service = WorkspaceContextService()
        self.membership_service = MembershipCacheService()

        # Create users
        self.superuser = User.objects.create_superuser(
            email="super@test.com", password="testpass123", username="superuser"
        )
        self.regular_user = User.objects.create_user(
            email="user@test.com", password="testpass123", username="regularuser"
        )
        self.admin_user = User.objects.create_user(
            email="admin@test.com", password="testpass123", username="adminuser"
        )
        self.workspace_owner = User.objects.create_user(
            email="owner@test.com", password="testpass123", username="workspaceowner"
        )

        # Create workspace
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.workspace_owner
        )

        # Create memberships
        WorkspaceMembership.objects.create(
            workspace=self.workspace, user=self.regular_user, role="viewer"
        )
        WorkspaceMembership.objects.create(
            workspace=self.workspace, user=self.admin_user, role="editor"
        )

        # Create workspace admin
        WorkspaceAdmin.objects.create(
            user=self.admin_user,
            workspace=self.workspace,
            assigned_by=self.superuser,
            is_active=True,
        )

    def create_request_with_context(self, user, workspace_id=None, view_kwargs=None):
        """Create request with REAL workspace context (simulates middleware)"""
        request = self.factory.get("/")
        request.user = user

        # Simulate WorkspaceContextMixin
        self.context_service.build_request_context(request, view_kwargs or {})

        return request

    def create_view_with_kwargs(self, **kwargs):
        view = Mock()
        view.kwargs = kwargs
        return view

    def mock_membership_service(self, role=None, is_admin=False, is_member=True):
        """Mock membership service to return specific values"""
        return patch.multiple(
            self.membership_service,
            get_user_workspace_role=Mock(return_value=role),
            is_workspace_admin=Mock(return_value=is_admin),
            is_user_workspace_member=Mock(return_value=is_member),
        )


class TestIsWorkspaceMember(BasePermissionTest):
    """Tests for IsWorkspaceMember with REAL context"""

    def test_superuser_has_access_with_workspace_context(self):
        permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.superuser, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        self.assertTrue(permission.has_permission(request, view))

    def test_workspace_member_has_access(self):
        permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.regular_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Mock that user has viewer role
        with self.mock_membership_service(role="viewer", is_member=True):
            self.assertTrue(permission.has_permission(request, view))

    def test_admin_role_has_member_access(self):
        permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(role="admin", is_member=True):
            self.assertTrue(permission.has_permission(request, view))

    def test_non_member_access_denied(self):
        permission = IsWorkspaceMember()
        non_member = User.objects.create_user(
            email="nonmember@test.com", password="testpass123", username="nonmember"
        )
        request = self.create_request_with_context(
            non_member, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Mock that user is not a member
        with self.mock_membership_service(role=None, is_member=False):
            self.assertFalse(permission.has_permission(request, view))

    def test_nonexistent_workspace_access_blocked(self):
        permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.regular_user,
            view_kwargs={"workspace_pk": 9999},  # Non-existent workspace
        )
        view = self.create_view_with_kwargs(workspace_pk=9999)

        self.assertFalse(permission.has_permission(request, view))

    def test_admin_impersonation_has_access(self):
        permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        request.is_admin_impersonation = True
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Mock admin status
        with self.mock_membership_service(is_admin=True):
            self.assertTrue(permission.has_permission(request, view))

    @patch("finance.permissions.logger")
    def test_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceMember()
        non_member = User.objects.create_user(
            email="nonmember@test.com", password="testpass123", username="nonmember"
        )
        request = self.create_request_with_context(
            non_member, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(role=None, is_member=False):
            permission.has_permission(request, view)

        mock_logger.warning.assert_called_once()


class TestIsWorkspaceEditor(BasePermissionTest):
    """Tests for IsWorkspaceEditor with REAL context"""

    def test_superuser_has_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.superuser, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        self.assertTrue(permission.has_permission(request, view))

    def test_editor_role_has_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(role="editor"):
            self.assertTrue(permission.has_permission(request, view))

    def test_owner_role_has_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.workspace_owner, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(role="owner"):
            self.assertTrue(permission.has_permission(request, view))

    def test_viewer_role_write_access_denied(self):
        permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.regular_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(role="viewer"):
            self.assertFalse(permission.has_permission(request, view))

    def test_admin_impersonation_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        request.is_admin_impersonation = True
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(is_admin=True):
            self.assertTrue(permission.has_permission(request, view))

    @patch("finance.permissions.logger")
    def test_write_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.regular_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(role="viewer"):
            permission.has_permission(request, view)

        mock_logger.warning.assert_called_once()


class TestIsWorkspaceOwner(BasePermissionTest):
    """Tests for IsWorkspaceOwner with REAL context"""

    def test_superuser_has_ownership_access(self):
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.superuser, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        self.assertTrue(permission.has_permission(request, view))

    def test_workspace_admin_has_ownership_access(self):
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(is_admin=True):
            self.assertTrue(permission.has_permission(request, view))

    def test_workspace_owner_has_access_via_role(self):
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.workspace_owner, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Owner access comes from workspace.owner relationship
        # The service should detect this and set appropriate permissions
        self.assertTrue(permission.has_permission(request, view))

    def test_editor_role_ownership_denied(self):
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        request.user_permissions["is_workspace_admin"] = False

        # Remove admin privileges, only editor role
        with self.mock_membership_service(role="editor", is_admin=False):
            self.assertFalse(permission.has_permission(request, view))

    def test_viewer_role_ownership_denied(self):
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.regular_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        self.assertFalse(permission.has_permission(request, view))

    def test_admin_impersonation_ownership_access(self):
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        request.is_admin_impersonation = True
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        with self.mock_membership_service(is_admin=True):
            self.assertTrue(permission.has_permission(request, view))

    @patch("finance.permissions.logger")
    def test_ownership_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.regular_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        permission.has_permission(request, view)

        mock_logger.warning.assert_called_once()

    def test_has_object_permission_defers_to_has_permission(self):
        """Object permission should defer to view-level permission"""
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.workspace_owner, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        obj = self.workspace

        # Mock has_permission to trace its usage
        with patch.object(
            permission, "has_permission", return_value=True
        ) as mock_has_permission:
            self.assertTrue(permission.has_object_permission(request, view, obj))
            mock_has_permission.assert_called_once_with(request, view)

        with patch.object(
            permission, "has_permission", return_value=False
        ) as mock_has_permission:
            self.assertFalse(permission.has_object_permission(request, view, obj))
            mock_has_permission.assert_called_once_with(request, view)


class TestIsWorkspaceAdmin(BasePermissionTest):
    """Tests for IsWorkspaceAdmin with REAL context"""

    def test_superuser_is_always_admin(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request_with_context(self.superuser)
        view = self.create_view_with_kwargs()

        self.assertTrue(permission.has_permission(request, view))

    def test_workspace_admin_has_access(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request_with_context(self.admin_user)
        view = self.create_view_with_kwargs()
        request.user_permissions["is_workspace_admin"] = True

        with self.mock_membership_service(is_admin=True):
            self.assertTrue(permission.has_permission(request, view))

    def test_regular_user_admin_access_denied(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request_with_context(self.regular_user)
        view = self.create_view_with_kwargs()

        with self.mock_membership_service(is_admin=False):
            self.assertFalse(permission.has_permission(request, view))

    @patch("finance.permissions.logger")
    def test_admin_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceAdmin()
        request = self.create_request_with_context(self.regular_user)
        view = self.create_view_with_kwargs()

        with self.mock_membership_service(is_admin=False):
            permission.has_permission(request, view)

        mock_logger.warning.assert_called_once()


class TestIsSuperuser(BasePermissionTest):
    """Tests for IsSuperuser permission"""

    def test_superuser_has_access(self):
        permission = IsSuperuser()
        request = self.create_request_with_context(self.superuser)
        view = self.create_view_with_kwargs()

        self.assertTrue(permission.has_permission(request, view))

    def test_regular_user_superuser_access_denied(self):
        permission = IsSuperuser()
        request = self.create_request_with_context(self.regular_user)
        view = self.create_view_with_kwargs()

        self.assertFalse(permission.has_permission(request, view))

    def test_anonymous_user_superuser_access_denied(self):
        permission = IsSuperuser()
        request = self.factory.get("/")
        request.user = AnonymousUser()
        view = self.create_view_with_kwargs()

        self.assertFalse(permission.has_permission(request, view))

    @patch("finance.permissions.logger")
    def test_superuser_access_granted_logging(self, mock_logger):
        permission = IsSuperuser()
        request = self.create_request_with_context(self.superuser)
        view = self.create_view_with_kwargs()

        permission.has_permission(request, view)

        mock_logger.debug.assert_called_once()

    @patch("finance.permissions.logger")
    def test_superuser_access_denied_logging(self, mock_logger):
        permission = IsSuperuser()
        request = self.create_request_with_context(self.regular_user)
        view = self.create_view_with_kwargs()

        permission.has_permission(request, view)

        mock_logger.warning.assert_called_once()


class TestPermissionHierarchy(BasePermissionTest):
    """Tests for permission hierarchy and inheritance"""

    def test_workspace_admin_inherits_owner_permissions(self):
        """WorkspaceAdmin should have ALL permissions including owner"""
        # Test IsWorkspaceOwner permission for admin
        owner_permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Admin has NO owner role but IS workspace admin
        with self.mock_membership_service(role="editor", is_admin=True):
            self.assertTrue(owner_permission.has_permission(request, view))

    def test_workspace_admin_inherits_editor_permissions(self):
        """WorkspaceAdmin should have editor permissions"""
        editor_permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Admin has NO editor role but IS workspace admin
        with self.mock_membership_service(role=None, is_admin=True):
            self.assertTrue(editor_permission.has_permission(request, view))

    def test_workspace_admin_inherits_member_permissions(self):
        """WorkspaceAdmin should have member permissions"""
        member_permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Admin is NOT direct member but IS workspace admin
        with self.mock_membership_service(role=None, is_member=False, is_admin=True):
            self.assertTrue(member_permission.has_permission(request, view))

    def test_workspace_owner_inherits_editor_permissions(self):
        """WorkspaceOwner should have editor permissions"""
        editor_permission = IsWorkspaceEditor()
        request = self.create_request_with_context(
            self.workspace_owner, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Owner automatically has editor permissions
        with self.mock_membership_service(role="owner"):
            self.assertTrue(editor_permission.has_permission(request, view))

    def test_workspace_owner_inherits_member_permissions(self):
        """WorkspaceOwner should have member permissions"""
        member_permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.workspace_owner, view_kwargs={"workspace_pk": self.workspace.id}
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Owner automatically has member permissions
        with self.mock_membership_service(role="owner"):
            self.assertTrue(member_permission.has_permission(request, view))

    def test_editor_inherits_member_permissions(self):
        """WorkspaceEditor should have member permissions"""
        member_permission = IsWorkspaceMember()
        request = self.create_request_with_context(
            self.admin_user,  # This user has editor role
            view_kwargs={"workspace_pk": self.workspace.id},
        )
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Editor automatically has member permissions
        with self.mock_membership_service(role="editor"):
            self.assertTrue(member_permission.has_permission(request, view))

    def test_superuser_inherits_all_permissions(self):
        """Superuser should have ALL permissions"""
        # Test all permission types
        permissions = [
            IsWorkspaceMember(),
            IsWorkspaceEditor(),
            IsWorkspaceOwner(),
            IsWorkspaceAdmin(),
            IsSuperuser(),
        ]

        for permission in permissions:
            request = self.create_request_with_context(
                self.superuser, view_kwargs={"workspace_pk": self.workspace.id}
            )
            view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

            self.assertTrue(permission.has_permission(request, view))

    def test_admin_without_membership_still_has_access(self):
        """WorkspaceAdmin without direct membership should still have access"""
        # Create admin user who is NOT workspace member
        admin_non_member = User.objects.create_user(
            email="admin_nonmember@test.com",
            password="testpass123",
            username="admin_nonmember",
        )

        # Make them workspace admin
        WorkspaceAdmin.objects.create(
            user=admin_non_member,
            workspace=self.workspace,
            assigned_by=self.superuser,
            is_active=True,
        )

        # Test all permissions for admin without membership
        permissions = [IsWorkspaceMember(), IsWorkspaceEditor(), IsWorkspaceOwner()]

        for permission in permissions:
            request = self.create_request_with_context(
                admin_non_member, view_kwargs={"workspace_pk": self.workspace.id}
            )
            request.is_admin_impersonation = True
            request.user_permissions["is_workspace_admin"] = True
            view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

            # Admin should have access despite not being member
            with self.mock_membership_service(
                role=None, is_member=False, is_admin=True
            ):
                self.assertTrue(permission.has_permission(request, view))


class TestEdgeCases(BasePermissionTest):
    """Tests for edge cases in permission hierarchy"""

    def test_admin_impersonation_hierarchy(self):
        """Admin impersonation should inherit the target's permissions + admin rights"""
        permission = IsWorkspaceOwner()
        request = self.create_request_with_context(
            self.admin_user, view_kwargs={"workspace_pk": self.workspace.id}
        )
        request.is_admin_impersonation = True
        request.target_user = self.regular_user  # Impersonating a viewer
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Admin impersonating viewer should have owner access
        with self.mock_membership_service(is_admin=True):
            self.assertTrue(permission.has_permission(request, view))

    def test_missing_user_permissions_graceful_failure(self):
        """Permissions should fail gracefully if user_permissions is missing"""
        request = self.factory.get("/")
        request.user = self.regular_user
        # Deliberately do not add user_permissions to the request

        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        permissions_to_test = [
            IsWorkspaceMember,
            IsWorkspaceEditor,
            IsWorkspaceOwner,
            IsWorkspaceAdmin,
        ]

        for perm_class in permissions_to_test:
            permission = perm_class()
            with self.subTest(permission=perm_class.__name__):
                self.assertFalse(permission.has_permission(request, view))
