import pytest
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from unittest.mock import Mock, patch
from rest_framework.exceptions import PermissionDenied

from finance.permissions import (
    IsWorkspaceMember, 
    IsWorkspaceEditor, 
    IsWorkspaceOwner, 
    IsWorkspaceAdmin
)
from finance.models import Workspace, WorkspaceMembership

User = get_user_model()


class BasePermissionTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.superuser = User.objects.create_superuser(
            email='super@test.com', 
            password='testpass123',
            username='superuser'
        )
        self.regular_user = User.objects.create_user(
            email='user@test.com',
            password='testpass123', 
            username='regularuser'
        )
        self.admin_user = User.objects.create_user(
            email='admin@test.com',
            password='testpass123',
            username='adminuser'
        )
        self.workspace_owner = User.objects.create_user(
            email='owner@test.com',
            password='testpass123',
            username='workspaceowner'
        )
        
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.workspace_owner
        )
        
        # Create memberships
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user=self.regular_user,
            role='viewer'
        )
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user=self.admin_user, 
            role='editor'
        )

    def create_request(self, user, workspace_id=None, is_impersonation=False, target_user=None):
        request = self.factory.get('/')
        request.user = user
        request.user_permissions = {
            'is_superuser': user.is_superuser,
            'is_workspace_admin': False,
            'workspace_role': None,
            'workspace_exists': True,
            'current_workspace_id': workspace_id
        }
        request.is_admin_impersonation = is_impersonation
        request.impersonation_workspace_ids = [workspace_id] if workspace_id else []
        if target_user:
            request.target_user = target_user
        return request

    def create_view_with_kwargs(self, **kwargs):
        view = Mock()
        view.kwargs = kwargs
        return view


class TestIsWorkspaceMember(BasePermissionTest):
    """Comprehensive tests for IsWorkspaceMember permission"""

    def test_superuser_has_access_to_any_workspace(self):
        permission = IsWorkspaceMember()
        request = self.create_request(self.superuser, workspace_id=999)
        view = self.create_view_with_kwargs(workspace_pk=999)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_authenticated_user_without_workspace_context(self):
        permission = IsWorkspaceMember()
        request = self.create_request(self.regular_user)
        view = self.create_view_with_kwargs()
        
        self.assertTrue(permission.has_permission(request, view))

    def test_workspace_member_has_access(self):
        permission = IsWorkspaceMember()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'viewer'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_non_member_access_denied(self):
        permission = IsWorkspaceMember()
        non_member = User.objects.create_user(
            email='nonmember@test.com',
            password='testpass123',
            username='nonmember'
        )
        request = self.create_request(non_member, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_nonexistent_workspace_access_blocked(self):
        permission = IsWorkspaceMember()
        request = self.create_request(self.regular_user, workspace_id=9999)
        request.user_permissions['workspace_exists'] = False
        view = self.create_view_with_kwargs(workspace_pk=9999)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_admin_impersonation_has_access(self):
        permission = IsWorkspaceMember()
        request = self.create_request(
            self.admin_user, 
            workspace_id=self.workspace.id,
            is_impersonation=True,
            target_user=self.regular_user
        )
        request.user_permissions['is_workspace_admin'] = True
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_invalid_workspace_id_format(self):
        permission = IsWorkspaceMember()
        request = self.create_request(self.regular_user)
        view = self.create_view_with_kwargs(workspace_pk='invalid_id')
        
        self.assertTrue(permission.has_permission(request, view))

    def test_workspace_id_extraction_from_different_kwargs(self):
        permission = IsWorkspaceMember()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'viewer'
        
        # Test workspace_pk
        view1 = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        self.assertTrue(permission.has_permission(request, view1))
        
        # Test workspace_id
        view2 = self.create_view_with_kwargs(workspace_id=self.workspace.id)
        self.assertTrue(permission.has_permission(request, view2))
        
        # Test pk
        view3 = self.create_view_with_kwargs(pk=self.workspace.id)
        self.assertTrue(permission.has_permission(request, view3))

    @patch('finance.permissions.logger')
    def test_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceMember()
        non_member = User.objects.create_user(
            email='nonmember@test.com',
            password='testpass123',
            username='nonmember'
        )
        request = self.create_request(non_member, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        permission.has_permission(request, view)
        
        mock_logger.warning.assert_called_once()


class TestIsWorkspaceEditor(BasePermissionTest):
    """Comprehensive tests for IsWorkspaceEditor permission"""

    def test_superuser_has_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request(self.superuser, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_editor_role_has_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request(self.admin_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'editor'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_owner_role_has_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'owner'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_viewer_role_write_access_denied(self):
        permission = IsWorkspaceEditor()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'viewer'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_no_role_write_access_denied(self):
        permission = IsWorkspaceEditor()
        non_member = User.objects.create_user(
            email='nonmember@test.com',
            password='testpass123',
            username='nonmember'
        )
        request = self.create_request(non_member, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_nonexistent_workspace_write_access_blocked(self):
        permission = IsWorkspaceEditor()
        request = self.create_request(self.admin_user, workspace_id=9999)
        request.user_permissions['workspace_exists'] = False
        view = self.create_view_with_kwargs(workspace_pk=9999)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_admin_impersonation_write_access(self):
        permission = IsWorkspaceEditor()
        request = self.create_request(
            self.admin_user,
            workspace_id=self.workspace.id,
            is_impersonation=True,
            target_user=self.regular_user
        )
        request.user_permissions['is_workspace_admin'] = True
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_write_roles_constant(self):
        permission = IsWorkspaceEditor()
        self.assertEqual(permission.WRITE_ROLES, ['editor', 'owner'])

    @patch('finance.permissions.logger')
    def test_write_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceEditor()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'viewer'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        permission.has_permission(request, view)
        
        mock_logger.warning.assert_called_once()


class TestIsWorkspaceOwner(BasePermissionTest):
    """Comprehensive tests for IsWorkspaceOwner permission"""

    def test_superuser_has_ownership_access(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.superuser, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_actual_workspace_owner_has_access(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_non_owner_access_denied(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'viewer'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_editor_role_ownership_denied(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.admin_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'editor'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_no_workspace_context_denied(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner)
        view = self.create_view_with_kwargs()
        
        self.assertFalse(permission.has_permission(request, view))

    def test_nonexistent_workspace_ownership_blocked(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=9999)
        request.user_permissions['workspace_exists'] = False
        view = self.create_view_with_kwargs(workspace_pk=9999)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_admin_impersonation_ownership_access(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(
            self.admin_user,
            workspace_id=self.workspace.id,
            is_impersonation=True,
            target_user=self.workspace_owner
        )
        request.user_permissions['is_workspace_admin'] = True
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    @patch('finance.permissions.cache')
    @patch('finance.permissions.Workspace')
    def test_ownership_check_with_caching(self, mock_workspace, mock_cache):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        # Test cache hit
        mock_cache.get.return_value = self.workspace_owner.id
        self.assertTrue(permission.has_permission(request, view))
        mock_cache.get.assert_called_once()

    @patch('finance.permissions.cache')
    @patch('finance.permissions.Workspace')
    def test_ownership_check_with_cache_miss(self, mock_workspace, mock_cache):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        # Test cache miss
        mock_cache.get.return_value = None
        mock_workspace.objects.filter.return_value.only.return_value.first.return_value = Mock(
            owner_id=self.workspace_owner.id
        )
        
        self.assertTrue(permission.has_permission(request, view))
        mock_cache.set.assert_called_once()

    @patch('finance.permissions.logger')
    def test_ownership_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'viewer'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        permission.has_permission(request, view)
        
        mock_logger.warning.assert_called_once()


class TestIsWorkspaceAdmin(BasePermissionTest):
    """Comprehensive tests for IsWorkspaceAdmin permission"""

    def test_superuser_is_always_admin(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request(self.superuser)
        view = self.create_view_with_kwargs()
        
        self.assertTrue(permission.has_permission(request, view))

    def test_workspace_admin_has_access(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request(self.admin_user)
        request.user_permissions['is_workspace_admin'] = True
        view = self.create_view_with_kwargs()
        
        self.assertTrue(permission.has_permission(request, view))

    def test_regular_user_admin_access_denied(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request(self.regular_user)
        request.user_permissions['is_workspace_admin'] = False
        view = self.create_view_with_kwargs()
        
        self.assertFalse(permission.has_permission(request, view))

    def test_workspace_admin_with_specific_workspace_access(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request(self.admin_user, workspace_id=self.workspace.id)
        request.user_permissions['is_workspace_admin'] = True
        request.impersonation_workspace_ids = [self.workspace.id]
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_workspace_admin_without_workspace_access_denied(self):
        permission = IsWorkspaceAdmin()
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.workspace_owner
        )
        request = self.create_request(self.admin_user, workspace_id=other_workspace.id)
        request.user_permissions['is_workspace_admin'] = True
        request.impersonation_workspace_ids = [self.workspace.id]  # No access to other_workspace
        view = self.create_view_with_kwargs(workspace_pk=other_workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))

    @patch('finance.permissions.logger')
    def test_admin_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceAdmin()
        request = self.create_request(self.regular_user)
        request.user_permissions['is_workspace_admin'] = False
        view = self.create_view_with_kwargs()
        
        permission.has_permission(request, view)
        
        mock_logger.warning.assert_called_once()

    def test_invalid_workspace_id_in_admin_permission(self):
        permission = IsWorkspaceAdmin()
        request = self.create_request(self.admin_user)
        request.user_permissions['is_workspace_admin'] = True
        view = self.create_view_with_kwargs(workspace_pk='invalid_id')
        
        # Should still return True because user is workspace admin
        self.assertTrue(permission.has_permission(request, view))