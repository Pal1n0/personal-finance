import pytest
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from unittest.mock import Mock, patch, MagicMock
from rest_framework.exceptions import ValidationError as DRFValidationError

from finance.mixins import TargetUserMixin, WorkspaceMembershipMixin, CategoryWorkspaceMixin
from finance.models import Workspace, WorkspaceMembership, ExpenseCategoryVersion, IncomeCategoryVersion

User = get_user_model()


class TestTargetUserMixin(TestCase):
    def setUp(self):
        self.mixin = TargetUserMixin()
        self.factory = RequestFactory()
        
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
        self.admin_user = User.objects.create_user(
            email='admin@test.com',
            password='testpass123',
            username='adminuser'
        )

    def create_request(self, user=None, target_user=None, is_impersonation=False):
        request = self.factory.get('/')
        if user:
            request.user = user
        else:
            request.user = self.regular_user
        if target_user:
            request.target_user = target_user
        request.is_admin_impersonation = is_impersonation
        return request

    def test_validate_sets_user_from_target_user(self):
        """Test that user is correctly set from request.target_user"""
        request = self.create_request(user=self.admin_user, target_user=self.target_user)
        context = {'request': request}
        
        # Create a mock parent class with validate method
        class TestSerializer(TargetUserMixin):
            def validate(self, attrs):
                return super().validate(attrs)
                
        serializer = TestSerializer()
        serializer.context = context
        
        initial_attrs = {'some_field': 'some_value'}
        result_attrs = serializer.validate(initial_attrs)
        
        self.assertEqual(result_attrs['user'], self.target_user)
        self.assertEqual(result_attrs['some_field'], 'some_value')

    def test_validate_preserves_original_attrs(self):
        """Test that original attributes are preserved when setting user"""
        request = self.create_request(user=self.admin_user, target_user=self.target_user)
        context = {'request': request}
        
        class TestSerializer(TargetUserMixin):
            def validate(self, attrs):
                return super().validate(attrs)
                
        serializer = TestSerializer()
        serializer.context = context
        
        initial_attrs = {
            'field1': 'value1',
            'field2': 'value2',
            'user': self.regular_user  # Should be overwritten
        }
        result_attrs = serializer.validate(initial_attrs)
        
        self.assertEqual(result_attrs['user'], self.target_user)
        self.assertEqual(result_attrs['field1'], 'value1')
        self.assertEqual(result_attrs['field2'], 'value2')

    def test_validate_without_request_context(self):
        """Test that mixin works without request context"""
        class TestSerializer(TargetUserMixin):
            def validate(self, attrs):
                return super().validate(attrs)
                
        serializer = TestSerializer()
        serializer.context = {}  # No request
        
        initial_attrs = {'field': 'value'}
        result_attrs = serializer.validate(initial_attrs)
        
        self.assertEqual(result_attrs, initial_attrs)

    def test_validate_without_target_user(self):
        """Test that mixin works when request has no target_user"""
        request = self.create_request(user=self.admin_user)  # No target_user
        context = {'request': request}
        
        class TestSerializer(TargetUserMixin):
            def validate(self, attrs):
                return super().validate(attrs)
                
        serializer = TestSerializer()
        serializer.context = context
        
        initial_attrs = {'field': 'value'}
        result_attrs = serializer.validate(initial_attrs)
        
        self.assertEqual(result_attrs, initial_attrs)

    @patch('finance.mixins.logger')
    def test_validate_logging_on_success(self, mock_logger):
        """Test that successful user assignment is logged"""
        request = self.create_request(
            user=self.admin_user, 
            target_user=self.target_user,
            is_impersonation=True
        )
        context = {'request': request}
        
        class TestSerializer(TargetUserMixin):
            def validate(self, attrs):
                return super().validate(attrs)
                
        serializer = TestSerializer()
        serializer.context = context
        
        serializer.validate({})
        
        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args
        self.assertEqual(call_args[1]['extra']['target_user_id'], self.target_user.id)
        self.assertEqual(call_args[1]['extra']['impersonation_active'], True)
        self.assertEqual(call_args[1]['extra']['action'], 'target_user_assignment')
        self.assertEqual(call_args[1]['extra']['component'], 'TargetUserMixin')

    def test_inheritance_behavior(self):
        """Test that mixin works correctly with parent class validation"""
        class ParentSerializer:
            def validate(self, attrs):
                attrs['parent_validated'] = True
                return attrs
                
        class TestSerializer(TargetUserMixin, ParentSerializer):
            def validate(self, attrs):
                attrs = super().validate(attrs)
                attrs['child_validated'] = True
                return attrs
                
        request = self.create_request(user=self.admin_user, target_user=self.target_user)
        context = {'request': request}
        
        serializer = TestSerializer()
        serializer.context = context
        
        result_attrs = serializer.validate({'original': 'value'})
        
        self.assertEqual(result_attrs['user'], self.target_user)
        self.assertEqual(result_attrs['parent_validated'], True)
        self.assertEqual(result_attrs['child_validated'], True)
        self.assertEqual(result_attrs['original'], 'value')


class TestWorkspaceMembershipMixin(TestCase):
    def setUp(self):
        self.mixin = WorkspaceMembershipMixin()
        self.factory = RequestFactory()
        
        self.user = User.objects.create_user(
            email='user@test.com',
            password='testpass123',
            username='testuser'
        )
        self.other_user = User.objects.create_user(
            email='other@test.com',
            password='testpass123',
            username='otheruser'
        )
        
        self.workspace1 = Workspace.objects.create(
            name='Workspace 1',
            owner=self.user
        )
        self.workspace2 = Workspace.objects.create(
            name='Workspace 2', 
            owner=self.other_user
        )
        
        # Create memberships
        self.membership1 = WorkspaceMembership.objects.create(
            workspace=self.workspace1,
            user=self.user,
            role='admin'
        )
        self.membership2 = WorkspaceMembership.objects.create(
            workspace=self.workspace2,
            user=self.user,
            role='viewer'
        )

    def create_request(self, user=None):
        request = self.factory.get('/')
        if user:
            request.user = user
        else:
            request.user = self.user
        return request

    def test_get_user_memberships_initial_cache_creation(self):
        """Test that cache is created on first access"""
        request = self.create_request()
        
        # Ensure cache doesn't exist initially
        self.assertFalse(hasattr(request, '_cached_user_memberships'))
        
        memberships = self.mixin._get_user_memberships(request)
        
        # Cache should be created
        self.assertTrue(hasattr(request, '_cached_user_memberships'))
        self.assertEqual(len(memberships), 2)
        self.assertEqual(memberships[self.workspace1.id], 'admin')
        self.assertEqual(memberships[self.workspace2.id], 'viewer')

    def test_get_user_memberships_cache_reuse(self):
        """Test that cache is reused on subsequent calls"""
        request = self.create_request()
        
        # First call - should hit database
        with self.assertNumQueries(1):
            memberships1 = self.mixin._get_user_memberships(request)
        
        # Second call - should use cache (no database queries)
        with self.assertNumQueries(0):
            memberships2 = self.mixin._get_user_memberships(request)
        
        self.assertEqual(memberships1, memberships2)

    def test_get_user_memberships_select_related_optimization(self):
        """Test that select_related is used for optimization"""
        request = self.create_request()
        
        with self.assertNumQueries(1):
            memberships = self.mixin._get_user_memberships(request)
        
        # Verify the structure is correct
        self.assertIsInstance(memberships, dict)
        self.assertEqual(memberships[self.workspace1.id], 'admin')

    @patch('finance.mixins.logger')
    def test_get_user_memberships_logging(self, mock_logger):
        """Test that cache initialization is logged"""
        request = self.create_request()
        
        self.mixin._get_user_memberships(request)
        
        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args
        self.assertEqual(call_args[1]['extra']['user_id'], self.user.id)
        self.assertEqual(call_args[1]['extra']['cached_workspaces_count'], 2)
        self.assertEqual(call_args[1]['extra']['action'], 'membership_cache_initialized')
        self.assertEqual(call_args[1]['extra']['component'], 'WorkspaceMembershipMixin')

    def test_get_membership_for_workspace_existing_membership(self):
        """Test getting role for workspace where user is a member"""
        request = self.create_request()
        
        role = self.mixin._get_membership_for_workspace(self.workspace1, request)
        
        self.assertEqual(role, 'admin')

    def test_get_membership_for_workspace_no_membership(self):
        """Test getting role for workspace where user is not a member"""
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.other_user
        )
        request = self.create_request()
        
        role = self.mixin._get_membership_for_workspace(other_workspace, request)
        
        self.assertIsNone(role)

    def test_get_membership_for_workspace_uses_cache(self):
        """Test that workspace role retrieval uses existing cache"""
        request = self.create_request()
        
        # Prime the cache
        self.mixin._get_user_memberships(request)
        
        # Should use cache, no additional queries
        with self.assertNumQueries(0):
            role = self.mixin._get_membership_for_workspace(self.workspace1, request)
        
        self.assertEqual(role, 'admin')

    @patch('finance.mixins.logger')
    def test_get_membership_for_workspace_logging_on_cache_hit(self, mock_logger):
        """Test that cache hits are logged"""
        request = self.create_request()
        
        # Prime the cache
        self.mixin._get_user_memberships(request)
        
        # This should log a cache hit
        self.mixin._get_membership_for_workspace(self.workspace1, request)
        
        mock_logger.debug.assert_called()
        # Find the cache hit log call
        cache_hit_call = None
        for call in mock_logger.debug.call_args_list:
            if call[1]['extra'].get('action') == 'workspace_role_cache_hit':
                cache_hit_call = call
                break
        
        self.assertIsNotNone(cache_hit_call)
        self.assertEqual(cache_hit_call[1]['extra']['user_id'], self.user.id)
        self.assertEqual(cache_hit_call[1]['extra']['workspace_id'], self.workspace1.id)
        self.assertEqual(cache_hit_call[1]['extra']['user_role'], 'admin')

    def test_get_membership_for_workspace_no_logging_on_cache_miss(self):
        """Test that cache misses are not logged"""
        request = self.create_request()
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.other_user
        )
        
        with patch('finance.mixins.logger') as mock_logger:
            role = self.mixin._get_membership_for_workspace(other_workspace, request)
            
            # Should not log for cache misses
            cache_hit_calls = [
                call for call in mock_logger.debug.call_args_list
                if call[1]['extra'].get('action') == 'workspace_role_cache_hit'
            ]
            self.assertEqual(len(cache_hit_calls), 0)

    def test_multiple_users_independent_caches(self):
        """Test that different users have independent caches"""
        request1 = self.create_request(user=self.user)
        request2 = self.create_request(user=self.other_user)
        
        # Prime cache for user1
        memberships1 = self.mixin._get_user_memberships(request1)
        
        # Prime cache for user2 (who has no memberships)
        memberships2 = self.mixin._get_user_memberships(request2)
        
        self.assertEqual(len(memberships1), 2)
        self.assertEqual(len(memberships2), 0)
        self.assertNotEqual(id(request1._cached_user_memberships), id(request2._cached_user_memberships))

    def test_integration_with_serializer(self):
        """Test integration with a real serializer scenario"""
        class TestSerializer(WorkspaceMembershipMixin):
            def __init__(self, context=None):
                self.context = context or {}
            
            def get_user_role(self, obj):
                request = self.context.get('request')
                if request:
                    return self._get_membership_for_workspace(obj, request)
                return None
        
        request = self.create_request()
        context = {'request': request}
        serializer = TestSerializer(context=context)
        
        role = serializer.get_user_role(self.workspace1)
        self.assertEqual(role, 'admin')


class TestCategoryWorkspaceMixin(TestCase):
    def setUp(self):
        self.mixin = CategoryWorkspaceMixin()
        self.factory = RequestFactory()
        
        self.user = User.objects.create_user(
            email='user@test.com',
            password='testpass123',
            username='testuser'
        )
        self.workspace1 = Workspace.objects.create(
            name='Workspace 1',
            owner=self.user
        )
        self.workspace2 = Workspace.objects.create(
            name='Workspace 2',
            owner=self.user
        )
        
        self.expense_version1 = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace1,
            name='Expense Version 1',
            created_by=self.user
        )
        self.expense_version2 = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace2,
            name='Expense Version 2',
            created_by=self.user
        )
        
        self.income_version1 = IncomeCategoryVersion.objects.create(
            workspace=self.workspace1,
            name='Income Version 1',
            created_by=self.user
        )

    def create_request(self, workspace=None, is_impersonation=False):
        request = self.factory.get('/')
        request.user = self.user
        if workspace:
            request.workspace = workspace
        request.is_admin_impersonation = is_impersonation
        return request

    def test_validate_same_workspace_allowed(self):
        """Test that category version from same workspace is allowed"""
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context)
        data = {'version': self.expense_version1}
        
        # Should not raise exception
        result_data = serializer.validate(data)
        self.assertEqual(result_data, data)

    def test_validate_different_workspace_blocked(self):
        """Test that category version from different workspace is blocked"""
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context)
        data = {'version': self.expense_version2}  # From workspace2
        
        with self.assertRaises(DRFValidationError) as context:
            serializer.validate(data)
        
        self.assertIn('Category version does not belong to this workspace', str(context.exception))

    def test_validate_with_instance_same_workspace(self):
        """Test validation with instance from same workspace"""
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        class MockInstance:
            def __init__(self, version):
                self.version = version
        
        instance = MockInstance(self.expense_version1)
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context, instance=instance)
        data = {}  # No version in data, should use instance version
        
        # Should not raise exception
        result_data = serializer.validate(data)
        self.assertEqual(result_data, data)

    def test_validate_with_instance_different_workspace(self):
        """Test validation with instance from different workspace"""
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        class MockInstance:
            def __init__(self, version):
                self.version = version
        
        instance = MockInstance(self.expense_version2)  # From workspace2
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context, instance=instance)
        data = {}  # No version in data, should use instance version
        
        with self.assertRaises(DRFValidationError) as context:
            serializer.validate(data)
        
        self.assertIn('Category version does not belong to this workspace', str(context.exception))

    def test_validate_data_version_overrides_instance(self):
        """Test that data version takes precedence over instance version"""
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        class MockInstance:
            def __init__(self, version):
                self.version = version
        
        instance = MockInstance(self.expense_version2)  # Wrong workspace
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context, instance=instance)
        data = {'version': self.expense_version1}  # Correct workspace
        
        # Should not raise exception because data version is correct
        result_data = serializer.validate(data)
        self.assertEqual(result_data, data)

    def test_validate_no_request_context(self):
        """Test validation without request context"""
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context={})  # No request
        data = {'version': self.expense_version1}
        
        # Should not raise exception without request context
        result_data = serializer.validate(data)
        self.assertEqual(result_data, data)

    def test_validate_no_workspace_in_request(self):
        """Test validation when request has no workspace"""
        request = self.create_request()  # No workspace
        context = {'request': request}
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context)
        data = {'version': self.expense_version1}
        
        # Should not raise exception without workspace in request
        result_data = serializer.validate(data)
        self.assertEqual(result_data, data)

    def test_validate_no_version_in_data_or_instance(self):
        """Test validation when no version is provided"""
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context)
        data = {'other_field': 'value'}  # No version
        
        # Should not raise exception without version
        result_data = serializer.validate(data)
        self.assertEqual(result_data, data)

    @patch('finance.mixins.logger')
    def test_cross_workspace_access_logging(self, mock_logger):
        """Test that cross-workspace access attempts are logged"""
        request = self.create_request(workspace=self.workspace1, is_impersonation=True)
        context = {'request': request}
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context)
        data = {'version': self.expense_version2}  # From different workspace
        
        try:
            serializer.validate(data)
        except DRFValidationError:
            pass  # Expected to fail
        
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        self.assertEqual(call_args[1]['extra']['category_version_id'], self.expense_version2.id)
        self.assertEqual(call_args[1]['extra']['version_workspace_id'], self.workspace2.id)
        self.assertEqual(call_args[1]['extra']['request_workspace_id'], self.workspace1.id)
        self.assertEqual(call_args[1]['extra']['impersonation_active'], True)
        self.assertEqual(call_args[1]['extra']['action'], 'cross_workspace_access_blocked')
        self.assertEqual(call_args[1]['extra']['component'], 'CategoryWorkspaceMixin')
        self.assertEqual(call_args[1]['extra']['severity'], 'high')

    def test_income_category_validation(self):
        """Test that income category versions are also validated"""
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        class TestSerializer(CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        serializer = TestSerializer(context=context)
        data = {'version': self.income_version1}  # From same workspace
        
        # Should not raise exception
        result_data = serializer.validate(data)
        self.assertEqual(result_data, data)

    def test_inheritance_behavior_with_parent_validation(self):
        """Test that mixin works correctly with parent validation logic"""
        class ParentSerializer:
            def validate(self, attrs):
                attrs['parent_validated'] = True
                return attrs
                
        class TestSerializer(CategoryWorkspaceMixin, ParentSerializer):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                data = super().validate(data)
                data['child_validated'] = True
                return data
        
        request = self.create_request(workspace=self.workspace1)
        context = {'request': request}
        
        serializer = TestSerializer(context=context)
        data = {'version': self.expense_version1}
        
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data['version'], self.expense_version1)
        self.assertEqual(result_data['parent_validated'], True)
        self.assertEqual(result_data['child_validated'], True)


class TestMixinsIntegration(TestCase):
    """Integration tests for multiple mixins working together"""
    
    def setUp(self):
        self.factory = RequestFactory()
        
        self.user = User.objects.create_user(
            email='user@test.com',
            password='testpass123',
            username='testuser'
        )
        self.target_user = User.objects.create_user(
            email='target@test.com',
            password='testpass123',
            username='targetuser'
        )
        
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.user
        )
        
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user=self.user,
            role='admin'
        )
        
        self.category_version = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace,
            name='Test Version',
            created_by=self.user
        )

    def test_all_mixins_together(self):
        """Test integration of all three mixins"""
        class IntegratedSerializer(TargetUserMixin, WorkspaceMembershipMixin, CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
            
            def get_user_role(self, obj):
                request = self.context.get('request')
                if request:
                    return self._get_membership_for_workspace(obj, request)
                return None
        
        # Create request with all necessary attributes
        request = self.factory.get('/')
        request.user = self.user
        request.target_user = self.target_user
        request.workspace = self.workspace
        request.is_admin_impersonation = True
        
        context = {'request': request}
        serializer = IntegratedSerializer(context=context)
        
        # Test TargetUserMixin
        data_with_user = serializer.validate({'version': self.category_version})
        self.assertEqual(data_with_user['user'], self.target_user)
        
        # Test WorkspaceMembershipMixin
        role = serializer.get_user_role(self.workspace)
        self.assertEqual(role, 'admin')
        
        # Test CategoryWorkspaceMixin
        # Should not raise exception for same workspace
        result_data = serializer.validate({'version': self.category_version})
        self.assertEqual(result_data['version'], self.category_version)

    @patch('finance.mixins.logger')
    def test_comprehensive_logging_integration(self, mock_logger):
        """Test that all mixins log appropriately when used together"""
        class LoggingSerializer(TargetUserMixin, WorkspaceMembershipMixin, CategoryWorkspaceMixin):
            def __init__(self, context=None, instance=None):
                self.context = context or {}
                self.instance = instance
            
            def validate(self, data):
                return super().validate(data)
        
        request = self.factory.get('/')
        request.user = self.user
        request.target_user = self.target_user
        request.workspace = self.workspace
        request.is_admin_impersonation = True
        
        context = {'request': request}
        serializer = LoggingSerializer(context=context)
        
        # Trigger all mixins
        serializer._get_user_memberships(request)  # WorkspaceMembershipMixin cache init
        serializer.validate({'version': self.category_version})  # TargetUserMixin + CategoryWorkspaceMixin
        
        # Verify logging calls
        debug_calls = [call for call in mock_logger.debug.call_args_list]
        warning_calls = [call for call in mock_logger.warning.call_args_list]
        
        # Should have at least: cache initialization + target user assignment
        self.assertGreaterEqual(len(debug_calls), 2)
        
        # Find specific log calls
        cache_init_call = next(
            (call for call in debug_calls 
             if call[1]['extra'].get('action') == 'membership_cache_initialized'),
            None
        )
        target_user_call = next(
            (call for call in debug_calls 
             if call[1]['extra'].get('action') == 'target_user_assignment'),
            None
        )
        
        self.assertIsNotNone(cache_init_call)
        self.assertIsNotNone(target_user_call)