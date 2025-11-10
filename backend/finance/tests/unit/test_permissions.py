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
    """Comprehensive tests for IsWorkspaceOwner permission with cache optimization"""

    def test_superuser_has_ownership_access(self):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.superuser, workspace_id=self.workspace.id)
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertTrue(permission.has_permission(request, view))

    def test_actual_workspace_owner_has_access_via_role(self):
        """Test owner access via membership role (new primary method)"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'owner'  # ← Owner role from membership
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
    def test_ownership_fallback_cache_hit_owner(self, mock_workspace, mock_cache):
        """Test fallback check with cache hit for owner"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = None  # Simulate cache issue
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        # Cache hit with owner ID
        mock_cache.get.return_value = self.workspace_owner.id
        
        self.assertTrue(permission.has_permission(request, view))
        mock_cache.get.assert_called_once_with(f"workspace_owner_{self.workspace.id}")

    @patch('finance.permissions.cache')
    @patch('finance.permissions.Workspace')
    def test_ownership_fallback_cache_hit_non_owner(self, mock_workspace, mock_cache):
        """Test fallback check with cache hit for non-owner"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = None
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        # Cache hit with different owner ID
        mock_cache.get.return_value = self.workspace_owner.id  # Different user
        
        self.assertFalse(permission.has_permission(request, view))

    @patch('finance.permissions.cache')
    @patch('finance.permissions.Workspace')
    def test_ownership_fallback_cache_miss_owner(self, mock_workspace, mock_cache):
        """Test fallback check with cache miss for actual owner"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = None  # Simulate stale cache
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        # Cache miss
        mock_cache.get.return_value = None
        mock_workspace.objects.filter.return_value.only.return_value.first.return_value = Mock(
            owner_id=self.workspace_owner.id
        )
        
        self.assertTrue(permission.has_permission(request, view))
        mock_cache.set.assert_called_once_with(
            f"workspace_owner_{self.workspace.id}", 
            self.workspace_owner.id, 
            600
        )

    @patch('finance.permissions.cache')
    @patch('finance.permissions.Workspace')
    def test_ownership_fallback_cache_miss_non_owner(self, mock_workspace, mock_cache):
        """Test fallback check with cache miss for non-owner"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = None
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        # Cache miss with different owner
        mock_cache.get.return_value = None
        mock_workspace.objects.filter.return_value.only.return_value.first.return_value = Mock(
            owner_id=self.workspace_owner.id  # Different user
        )
        
        self.assertFalse(permission.has_permission(request, view))

    @patch('finance.permissions.cache')
    @patch('finance.permissions.Workspace')
    def test_ownership_fallback_workspace_not_found(self, mock_workspace, mock_cache):
        """Test fallback check when workspace doesn't exist"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=9999)
        request.user_permissions['workspace_role'] = None
        view = self.create_view_with_kwargs(workspace_pk=9999)
        
        mock_cache.get.return_value = None
        mock_workspace.objects.filter.return_value.only.return_value.first.return_value = None
        
        self.assertFalse(permission.has_permission(request, view))

    @patch('finance.permissions.logger')
    def test_ownership_access_denied_logging(self, mock_logger):
        permission = IsWorkspaceOwner()
        request = self.create_request(self.regular_user, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = 'viewer'
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        permission.has_permission(request, view)
        
        # Should log warning for denied access
        mock_logger.warning.assert_called()

    @patch('finance.permissions.logger')
    def test_stale_cache_detection_logging(self, mock_logger):
        """Test logging when stale cache is detected"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.workspace_owner, workspace_id=self.workspace.id)
        request.user_permissions['workspace_role'] = None  # Stale cache - no role
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)

        # Mock fallback to return True (user is actually owner)
        with patch.object(permission, '_check_owner_fallback', return_value=True):
            permission.has_permission(request, view)

            # Should log warning about stale cache
            mock_logger.warning.assert_called()
            
            # Find the stale cache warning in call arguments
            stale_cache_found = False
            for call in mock_logger.warning.call_args_list:
                call_kwargs = call[1]  # Get the kwargs from call
                if 'extra' in call_kwargs and 'action' in call_kwargs['extra']:
                    if 'stale' in call_kwargs['extra']['action'] or 'fallback' in call_kwargs['extra']['action']:
                        stale_cache_found = True
                        break
            
            self.assertTrue(stale_cache_found, "Stale cache warning not found in logs")

    def test_workspace_admin_without_impersonation_denied(self):
        """Test workspace admin without impersonation cannot access"""
        permission = IsWorkspaceOwner()
        request = self.create_request(self.admin_user, workspace_id=self.workspace.id)
        request.user_permissions['is_workspace_admin'] = True
        request.is_admin_impersonation = False  # No impersonation
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))

    def test_workspace_admin_impersonation_wrong_workspace_denied(self):
        """Test workspace admin impersonation denied for wrong workspace"""
        permission = IsWorkspaceOwner()
        request = self.create_request(
            self.admin_user,
            workspace_id=self.workspace.id,
            is_impersonation=True,
            target_user=self.workspace_owner
        )
        request.user_permissions['is_workspace_admin'] = True
        request.impersonation_workspace_ids = [9999]  # Different workspace
        view = self.create_view_with_kwargs(workspace_pk=self.workspace.id)
        
        self.assertFalse(permission.has_permission(request, view))


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