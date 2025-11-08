import pytest
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from unittest.mock import Mock, patch, MagicMock
from django.core.cache import cache
from django.db import DatabaseError

from finance.middleware import AdminImpersonationMiddleware
from finance.models import Workspace, WorkspaceMembership, WorkspaceAdmin

User = get_user_model()


class TestAdminImpersonationMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = AdminImpersonationMiddleware()
        
        self.superuser = User.objects.create_superuser(
            email='super@test.com',
            password='testpass123',
            username='superuser'
        )
        self.admin_user = User.objects.create_user(
            email='admin@test.com',
            password='testpass123', 
            username='adminuser'
        )
        self.regular_user = User.objects.create_user(
            email='user@test.com',
            password='testpass123',
            username='regularuser'
        )
        self.target_user = User.objects.create_user(
            email='target@test.com',
            password='testpass123',
            username='targetuser'
        )
        self.system_user = User.objects.create_user(
            email='system@admin.com',
            password='testpass123',
            username='systemuser'
        )
        
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.admin_user
        )
        
        # Create memberships
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user=self.regular_user,
            role='viewer'
        )
        WorkspaceMembership.objects.create(
            workspace=self.workspace, 
            user=self.target_user,
            role='editor'
        )
        
        # Create workspace admin
        WorkspaceAdmin.objects.create(
            user=self.admin_user,
            workspace=self.workspace,
            is_active=True
        )

    def create_request(self, user=None, method='GET', data=None, view_kwargs=None):
        request = self.factory.get('/', data or {})
        if user:
            request.user = user
        else:
            request.user = self.regular_user
        return request

    def test_initialization_sets_defaults(self):
        request = self.create_request()
        view_func = Mock()
        view_args = []
        view_kwargs = {}
        
        self.middleware.process_view(request, view_func, view_args, view_kwargs)
        
        self.assertEqual(request.target_user, request.user)
        self.assertFalse(request.is_admin_impersonation)
        self.assertIsNone(request.impersonation_type)
        self.assertEqual(request.impersonation_workspace_ids, [])
        self.assertIsInstance(request.user_permissions, dict)

    def test_unauthenticated_request_processing(self):
        request = self.create_request()
        request.user.is_authenticated = False
        view_func = Mock()
        
        result = self.middleware.process_view(request, view_func, [], {})
        
        self.assertIsNone(result)

    @patch('finance.middleware.cache')
    def test_impersonation_rate_limiting(self, mock_cache):
        request = self.create_request(self.admin_user)
        mock_cache.get.return_value = 15  # Over limit
        
        result = self.middleware._check_impersonation_rate_limit(request)
        
        self.assertFalse(result)
        mock_cache.get.assert_called_once()

    def test_user_id_parameter_extraction(self):
        request = self.create_request(data={'user_id': '123'})
        
        user_id = self.middleware._get_user_id_param(request)
        
        self.assertEqual(user_id, 123)

    def test_invalid_user_id_parameter(self):
        request = self.create_request(data={'user_id': 'invalid'})
        
        user_id = self.middleware._get_user_id_param(request)
        
        self.assertIsNone(user_id)

    def test_workspace_id_extraction_and_validation(self):
        request = self.create_request()
        view_kwargs = {'workspace_pk': str(self.workspace.id)}
        
        workspace_id = self.middleware._get_validated_workspace_id(request, view_kwargs)
        
        self.assertEqual(workspace_id, self.workspace.id)
        self.assertTrue(request.user_permissions['workspace_exists'])

    def test_nonexistent_workspace_id_validation(self):
        request = self.create_request()
        view_kwargs = {'workspace_pk': '9999'}
        
        workspace_id = self.middleware._get_validated_workspace_id(request, view_kwargs)
        
        self.assertIsNone(workspace_id)
        self.assertFalse(request.user_permissions['workspace_exists'])

    def test_invalid_workspace_id_format(self):
        request = self.create_request()
        view_kwargs = {'workspace_pk': 'invalid'}
        
        workspace_id = self.middleware._get_validated_workspace_id(request, view_kwargs)
        
        self.assertIsNone(workspace_id)

    def test_basic_permissions_set_for_superuser(self):
        request = self.create_request(self.superuser)
        
        self.middleware._set_basic_permissions(request)
        
        self.assertTrue(request.user_permissions['is_superuser'])

    def test_basic_permissions_set_for_regular_user(self):
        request = self.create_request(self.regular_user)
        
        self.middleware._set_basic_permissions(request)
        
        self.assertFalse(request.user_permissions['is_superuser'])

    def test_self_impersonation_validation_blocked(self):
        result = self.middleware._validate_impersonation_target(self.regular_user, self.regular_user)
        
        self.assertFalse(result)

    def test_superuser_impersonation_by_non_superuser_blocked(self):
        result = self.middleware._validate_impersonation_target(self.regular_user, self.superuser)
        
        self.assertFalse(result)

    def test_system_account_impersonation_blocked(self):
        result = self.middleware._validate_impersonation_target(self.admin_user, self.system_user)
        
        self.assertFalse(result)

    def test_valid_impersonation_target(self):
        result = self.middleware._validate_impersonation_target(self.admin_user, self.regular_user)
        
        self.assertTrue(result)

    @patch('finance.middleware.get_user_model')
    def test_superuser_impersonation_processing(self, mock_user_model):
        mock_user_model.return_value.objects.get.return_value = self.target_user
        request = self.create_request(self.superuser)
        request.user_permissions['is_superuser'] = True
        
        self.middleware._process_impersonation_request(request, self.target_user.id, self.workspace.id)
        
        self.assertTrue(request.is_admin_impersonation)
        self.assertEqual(request.impersonation_type, 'superuser')

    @patch('finance.middleware.get_user_model')
    def test_workspace_admin_impersonation_processing(self, mock_user_model):
        mock_user_model.return_value.objects.get.return_value = self.target_user
        request = self.create_request(self.admin_user)
        request.user_permissions['is_superuser'] = False
        
        with patch.object(self.middleware, '_can_admin_impersonate_in_workspace', return_value=True):
            self.middleware._process_impersonation_request(request, self.target_user.id, self.workspace.id)
            
            self.assertTrue(request.is_admin_impersonation)
            self.assertEqual(request.impersonation_type, 'workspace_admin')

    @patch('finance.middleware.get_user_model')
    def test_impersonation_user_not_found(self, mock_user_model):
        mock_user_model.return_value.objects.get.side_effect = User.DoesNotExist
        request = self.create_request(self.admin_user)
        
        self.middleware._process_impersonation_request(request, 9999, self.workspace.id)
        
        self.assertFalse(request.is_admin_impersonation)

    def test_workspace_access_processing_for_member(self):
        request = self.create_request(self.regular_user)
        request.user_permissions['workspace_exists'] = True
        
        with patch.object(self.middleware, '_get_user_workspace_role', return_value='viewer'):
            self.middleware._process_workspace_access(request, self.workspace.id)
            
            self.assertEqual(request.user_permissions['workspace_role'], 'viewer')

    def test_workspace_access_processing_for_non_member(self):
        request = self.create_request(self.admin_user)  # Not a member of this workspace
        request.user_permissions['workspace_exists'] = True
        
        with patch.object(self.middleware, '_get_user_workspace_role', return_value=None):
            self.middleware._process_workspace_access(request, self.workspace.id)
            
            self.assertIsNone(request.user_permissions['workspace_role'])

    def test_workspace_access_to_nonexistent_workspace(self):
        request = self.create_request(self.regular_user)
        request.user_permissions['workspace_exists'] = False
        
        self.middleware._process_workspace_access(request, 9999)
        
        # Should not crash and should not set any role

    def test_workspace_admin_check_with_caching(self):
        request = self.create_request(self.admin_user)
        
        with patch.object(cache, 'get', return_value=True):
            result = self.middleware._is_workspace_admin(self.admin_user, self.workspace.id)
            
            self.assertTrue(result)

    def test_workspace_membership_check_with_caching(self):
        request = self.create_request(self.regular_user)
        
        with patch.object(cache, 'get', return_value=True):
            result = self.middleware._is_user_workspace_member(self.regular_user, self.workspace.id)
            
            self.assertTrue(result)

    def test_user_workspace_role_retrieval(self):
        with patch.object(cache, 'get', return_value='viewer'):
            role = self.middleware._get_user_workspace_role(self.regular_user, self.workspace.id)
            
            self.assertEqual(role, 'viewer')

    def test_user_workspace_ids_retrieval(self):
        with patch.object(cache, 'get', return_value=[self.workspace.id]):
            workspace_ids = self.middleware._get_user_workspace_ids(self.regular_user)
            
            self.assertEqual(workspace_ids, [self.workspace.id])

    def test_common_admin_workspaces_calculation(self):
        admin_workspaces = [self.workspace.id]
        target_workspaces = [self.workspace.id]
        
        with patch.object(self.middleware, '_get_user_workspace_ids', side_effect=[admin_workspaces, target_workspaces]):
            common = self.middleware._get_common_admin_workspaces(self.admin_user, self.target_user)
            
            self.assertEqual(common, [self.workspace.id])

    def test_single_workspace_impersonation_grant(self):
        request = self.create_request(self.admin_user)
        
        self.middleware._grant_workspace_impersonation(request, self.target_user, self.workspace.id)
        
        self.assertTrue(request.is_admin_impersonation)
        self.assertEqual(request.impersonation_type, 'workspace_admin')
        self.assertEqual(request.impersonation_workspace_ids, [self.workspace.id])
        self.assertTrue(request.user_permissions['is_workspace_admin'])

    def test_multiple_workspaces_impersonation_grant(self):
        request = self.create_request(self.admin_user)
        workspace_ids = [self.workspace.id, 2, 3]
        
        self.middleware._grant_multiple_workspaces_impersonation(request, self.target_user, workspace_ids)
        
        self.assertTrue(request.is_admin_impersonation)
        self.assertEqual(request.impersonation_workspace_ids, workspace_ids)

    def test_impersonation_reset(self):
        request = self.create_request(self.admin_user)
        request.target_user = self.target_user
        request.is_admin_impersonation = True
        request.impersonation_type = 'workspace_admin'
        request.impersonation_workspace_ids = [self.workspace.id]
        
        self.middleware._reset_impersonation(request)
        
        self.assertEqual(request.target_user, request.user)
        self.assertFalse(request.is_admin_impersonation)
        self.assertIsNone(request.impersonation_type)
        self.assertEqual(request.impersonation_workspace_ids, [])

    @patch('finance.middleware.logger')
    def test_database_error_handling(self, mock_logger):
        request = self.create_request(self.admin_user)
        view_func = Mock()
        
        with patch.object(self.middleware, '_initialize_request_defaults') as mock_init:
            mock_init.side_effect = DatabaseError("DB connection failed")
            
            result = self.middleware.process_view(request, view_func, [], {})
            
            self.assertIsNone(result)
            mock_logger.error.assert_called_once()

    @patch('finance.middleware.logger')
    def test_general_exception_handling(self, mock_logger):
        request = self.create_request(self.admin_user)
        view_func = Mock()
        
        with patch.object(self.middleware, '_initialize_request_defaults') as mock_init:
            mock_init.side_effect = Exception("Unexpected error")
            
            result = self.middleware.process_view(request, view_func, [], {})
            
            self.assertIsNone(result)
            mock_logger.error.assert_called_once()

    def test_complete_impersonation_flow(self):
        request = self.create_request(self.superuser, data={'user_id': str(self.target_user.id)})
        view_func = Mock()
        view_kwargs = {'workspace_pk': str(self.workspace.id)}
        
        with patch.object(self.middleware, '_check_impersonation_rate_limit', return_value=True):
            with patch.object(self.middleware, '_validate_impersonation_target', return_value=True):
                with patch.object(self.middleware, '_is_user_workspace_member', return_value=True):
                    result = self.middleware.process_view(request, view_func, [], view_kwargs)
                    
                    self.assertIsNone(result)
                    self.assertTrue(request.is_admin_impersonation)
                    self.assertEqual(request.target_user, self.target_user)

    def test_workspace_access_without_impersonation(self):
        request = self.create_request(self.regular_user)
        view_func = Mock()
        view_kwargs = {'workspace_pk': str(self.workspace.id)}
        
        result = self.middleware.process_view(request, view_func, [], view_kwargs)
        
        self.assertIsNone(result)
        self.assertFalse(request.is_admin_impersonation)