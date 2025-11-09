import pytest
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from unittest.mock import Mock, patch, MagicMock
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework import serializers

from finance.mixins import TargetUserMixin, WorkspaceMembershipMixin, CategoryWorkspaceMixin
from finance.models import Workspace, WorkspaceMembership, ExpenseCategoryVersion, IncomeCategoryVersion

User = get_user_model()


class BaseTestMixin:
    """Base class for mixin tests that provides proper serializer context."""
    
    def create_test_serializer(self, mixin_class, context=None, instance=None):
        """Create a proper serializer with the mixin for testing."""
        class TestSerializer(mixin_class, serializers.Serializer):
            class Meta:
                fields = '__all__'
                
        serializer = TestSerializer(context=context or {})
        if instance:
            serializer.instance = instance
        return serializer


class TestTargetUserMixin(TestCase, BaseTestMixin):
    """Tests for TargetUserMixin user assignment functionality."""
    
    def setUp(self):
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
        """Test user assignment from request.target_user."""
        request = self.create_request(user=self.admin_user, target_user=self.target_user)
        
        serializer = self.create_test_serializer(TargetUserMixin, context={'request': request})
        
        initial_attrs = {'some_field': 'some_value'}
        result_attrs = serializer.validate(initial_attrs)
        
        self.assertEqual(result_attrs['user'], self.target_user)
        self.assertEqual(result_attrs['some_field'], 'some_value')

    def test_validate_preserves_original_attrs(self):
        """Test original attributes preservation when setting user."""
        request = self.create_request(user=self.admin_user, target_user=self.target_user)
        
        serializer = self.create_test_serializer(TargetUserMixin, context={'request': request})
        
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
        """Test mixin behavior without request context."""
        serializer = self.create_test_serializer(TargetUserMixin, context={})
        
        initial_attrs = {'field': 'value'}
        result_attrs = serializer.validate(initial_attrs)
        
        self.assertEqual(result_attrs, initial_attrs)

    def test_validate_without_target_user(self):
        """Test mixin behavior when request has no target_user."""
        request = self.create_request(user=self.admin_user)  # No target_user
        
        serializer = self.create_test_serializer(TargetUserMixin, context={'request': request})
        
        initial_attrs = {'field': 'value'}
        result_attrs = serializer.validate(initial_attrs)
        
        self.assertEqual(result_attrs, initial_attrs)

    @patch('finance.mixins.logger')
    def test_validate_logging_on_success(self, mock_logger):
        """Test logging for successful user assignment."""
        request = self.create_request(
            user=self.admin_user, 
            target_user=self.target_user,
            is_impersonation=True
        )
        
        serializer = self.create_test_serializer(TargetUserMixin, context={'request': request})
        serializer.validate({})
        
        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args
        self.assertEqual(call_args[1]['extra']['target_user_id'], self.target_user.id)
        self.assertEqual(call_args[1]['extra']['impersonation_active'], True)
        self.assertEqual(call_args[1]['extra']['action'], 'target_user_assignment')
        self.assertEqual(call_args[1]['extra']['component'], 'TargetUserMixin')

    def test_inheritance_behavior(self):
        """Test mixin integration with parent class validation."""
        class ParentSerializer(serializers.Serializer):
            def validate(self, attrs):
                attrs['parent_validated'] = True
                return super().validate(attrs)
                
        class TestSerializer(TargetUserMixin, ParentSerializer):
            def validate(self, attrs):
                attrs = super().validate(attrs)
                attrs['child_validated'] = True
                return attrs
                
        request = self.create_request(user=self.admin_user, target_user=self.target_user)
        
        serializer = TestSerializer(context={'request': request})
        result_attrs = serializer.validate({'original': 'value'})
        
        self.assertEqual(result_attrs['user'], self.target_user)
        self.assertEqual(result_attrs['parent_validated'], True)
        self.assertEqual(result_attrs['child_validated'], True)
        self.assertEqual(result_attrs['original'], 'value')


class TestWorkspaceMembershipMixin(TestCase, BaseTestMixin):
    """Tests for WorkspaceMembershipMixin caching functionality."""
    
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
        self.workspace3 = Workspace.objects.create(  # ← PRIDAJ Tretí workspace
            name='Workspace 3',
            owner=self.other_user
        )

        WorkspaceMembership.objects.filter(user=self.user).delete()
        WorkspaceMembership.objects.filter(user=self.other_user).delete()
        
        # Create memberships - user má 2 memberships, other_user má 1
        self.membership1 = WorkspaceMembership.objects.create(
            workspace=self.workspace1,
            user=self.other_user,
            role='admin'
        )
        self.membership2 = WorkspaceMembership.objects.create(
            workspace=self.workspace2,
            user=self.user,
            role='viewer'
        )
        self.membership3 = WorkspaceMembership.objects.create(  # ← PRIDAJ Druhý membership pre usera
            workspace=self.workspace3,
            user=self.user,
            role='editor'
        )

    def create_request(self, user=None):
        request = self.factory.get('/')
        if user:
            request.user = user
        else:
            request.user = self.user
        return request

    def test_get_user_memberships_initial_cache_creation(self):
        """Test cache creation on first access."""
        request = self.create_request(user=self.user)
        
        self.assertFalse(hasattr(request, '_cached_user_memberships'))
        
        memberships = self.mixin._get_user_memberships(request)
        
        self.assertTrue(hasattr(request, '_cached_user_memberships'))
        self.assertEqual(len(memberships), 2)  # user má 2 memberships
        self.assertEqual(memberships[self.workspace2.id], 'viewer')
        self.assertEqual(memberships[self.workspace3.id], 'editor')

    def test_get_user_memberships_cache_reuse(self):
        """Test cache reuse on subsequent calls."""
        request = self.create_request(user=self.user)
        
        with self.assertNumQueries(1):
            memberships1 = self.mixin._get_user_memberships(request)
        
        with self.assertNumQueries(0):
            memberships2 = self.mixin._get_user_memberships(request)
        
        self.assertEqual(memberships1, memberships2)
        self.assertEqual(len(memberships1), 2)  # user má 2 memberships

    def test_get_user_memberships_select_related_optimization(self):
        """Test select_related optimization."""
        request = self.create_request(user=self.user)
        
        with self.assertNumQueries(1):
            memberships = self.mixin._get_user_memberships(request)
        
        self.assertIsInstance(memberships, dict)
        self.assertEqual(len(memberships), 2)  # user má 2 memberships

    @patch('finance.mixins.logger')
    def test_get_user_memberships_logging(self, mock_logger):
        """Test cache initialization logging."""
        request = self.create_request(user=self.user)
        
        self.mixin._get_user_memberships(request)
        
        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args
        self.assertEqual(call_args[1]['extra']['user_id'], self.user.id)
        self.assertEqual(call_args[1]['extra']['cached_workspaces_count'], 2)  # user má 2 memberships

    def test_get_membership_for_workspace_existing_membership(self):
        """Test role retrieval for workspace membership."""
        request = self.create_request(user=self.other_user)
        
        role = self.mixin._get_membership_for_workspace(self.workspace1, request)
        
        self.assertEqual(role, 'admin')

    def test_get_membership_for_workspace_no_membership(self):
        """Test role retrieval for non-member workspace."""
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.other_user
        )
        request = self.create_request(user=self.user)
        
        role = self.mixin._get_membership_for_workspace(other_workspace, request)
        
        self.assertIsNone(role)

    def test_get_membership_for_workspace_uses_cache(self):
        """Test cache usage in workspace role retrieval."""
        request = self.create_request(user=self.other_user)
        
        self.mixin._get_user_memberships(request)
        
        with self.assertNumQueries(0):
            role = self.mixin._get_membership_for_workspace(self.workspace1, request)
        
        self.assertEqual(role, 'admin')

    @patch('finance.mixins.logger')
    def test_get_membership_for_workspace_logging_on_cache_hit(self, mock_logger):
        """Test logging for cache hits."""
        request = self.create_request(user=self.other_user)
        
        self.mixin._get_user_memberships(request)
        self.mixin._get_membership_for_workspace(self.workspace1, request)
        
        mock_logger.debug.assert_called()
        cache_hit_call = None
        for call in mock_logger.debug.call_args_list:
            if call[1]['extra'].get('action') == 'workspace_role_cache_hit':
                cache_hit_call = call
                break
        
        self.assertIsNotNone(cache_hit_call)
        self.assertEqual(cache_hit_call[1]['extra']['user_id'], self.other_user.id)
        self.assertEqual(cache_hit_call[1]['extra']['workspace_id'], self.workspace1.id)

    def test_get_membership_for_workspace_no_logging_on_cache_miss(self):
        """Test no logging for cache misses."""
        request = self.create_request(user=self.user)
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.other_user
        )
        
        with patch('finance.mixins.logger') as mock_logger:
            role = self.mixin._get_membership_for_workspace(other_workspace, request)
            
            cache_hit_calls = [
                call for call in mock_logger.debug.call_args_list
                if call[1]['extra'].get('action') == 'workspace_role_cache_hit'
            ]
            self.assertEqual(len(cache_hit_calls), 0)

    def test_multiple_users_independent_caches(self):
        """Test independent caches for different users."""
        request1 = self.create_request(user=self.user)
        request2 = self.create_request(user=self.other_user)
        
        memberships1 = self.mixin._get_user_memberships(request1)
        memberships2 = self.mixin._get_user_memberships(request2)
        
        self.assertEqual(len(memberships1), 2)  # user má 2 memberships
        self.assertEqual(len(memberships2), 1)  # other_user má 1 membership
        self.assertNotEqual(id(request1._cached_user_memberships), id(request2._cached_user_memberships))

    def test_integration_with_serializer(self):
        """Test mixin integration with serializer."""
        class TestSerializer(WorkspaceMembershipMixin, serializers.Serializer):
            def get_user_role(self, obj):
                request = self.context.get('request')
                if request:
                    return self._get_membership_for_workspace(obj, request)
                return None
        
        request = self.create_request(user=self.other_user)
        context = {'request': request}
        serializer = TestSerializer(context=context)
        
        role = serializer.get_user_role(self.workspace1)
        self.assertEqual(role, 'admin')


class TestCategoryWorkspaceMixin(TestCase, BaseTestMixin):
    """Tests for CategoryWorkspaceMixin security validation."""
    
    def setUp(self):
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
        """Test same workspace category validation."""
        request = self.create_request(workspace=self.workspace1)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request})
        
        data = {'version': self.expense_version1}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data, data)

    def test_validate_different_workspace_blocked(self):
        """Test cross-workspace category validation blocking."""
        request = self.create_request(workspace=self.workspace1)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request})
        
        data = {'version': self.expense_version2}
        
        with self.assertRaises(DRFValidationError) as context:
            serializer.validate(data)
        
        self.assertIn('Category version does not belong to this workspace', str(context.exception))

    def test_validate_with_instance_same_workspace(self):
        """Test validation with instance from same workspace."""
        request = self.create_request(workspace=self.workspace1)
        
        class MockInstance:
            def __init__(self, version):
                self.version = version
        
        instance = MockInstance(self.expense_version1)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request}, instance=instance)
        
        data = {}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data, data)

    def test_validate_with_instance_different_workspace(self):
        """Test validation with instance from different workspace."""
        request = self.create_request(workspace=self.workspace1)
        
        class MockInstance:
            def __init__(self, version):
                self.version = version
        
        instance = MockInstance(self.expense_version2)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request}, instance=instance)
        
        data = {}
        
        with self.assertRaises(DRFValidationError) as context:
            serializer.validate(data)
        
        self.assertIn('Category version does not belong to this workspace', str(context.exception))

    def test_validate_data_version_overrides_instance(self):
        """Test data version precedence over instance version."""
        request = self.create_request(workspace=self.workspace1)
        
        class MockInstance:
            def __init__(self, version):
                self.version = version
        
        instance = MockInstance(self.expense_version2)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request}, instance=instance)
        
        data = {'version': self.expense_version1}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data, data)

    def test_validate_no_request_context(self):
        """Test validation without request context."""
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={})
        
        data = {'version': self.expense_version1}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data, data)

    def test_validate_no_workspace_in_request(self):
        """Test validation without workspace in request."""
        request = self.create_request()
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request})
        
        data = {'version': self.expense_version1}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data, data)

    def test_validate_no_version_in_data_or_instance(self):
        """Test validation without version data."""
        request = self.create_request(workspace=self.workspace1)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request})
        
        data = {'other_field': 'value'}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data, data)

    @patch('finance.mixins.logger')
    def test_cross_workspace_access_logging(self, mock_logger):
        """Test logging for cross-workspace access attempts."""
        request = self.create_request(workspace=self.workspace1, is_impersonation=True)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request})
        
        data = {'version': self.expense_version2}
        
        try:
            serializer.validate(data)
        except DRFValidationError:
            pass
        
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        self.assertEqual(call_args[1]['extra']['category_version_id'], self.expense_version2.id)
        self.assertEqual(call_args[1]['extra']['version_workspace_id'], self.workspace2.id)

    def test_income_category_validation(self):
        """Test income category version validation."""
        request = self.create_request(workspace=self.workspace1)
        
        serializer = self.create_test_serializer(CategoryWorkspaceMixin, context={'request': request})
        
        data = {'version': self.income_version1}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data, data)

    def test_inheritance_behavior_with_parent_validation(self):
        """Test mixin integration with parent validation."""
        class ParentSerializer:
            # NEPOUŽÍVAJ serializers.Serializer - to má svoj validate()
            def validate(self, attrs):
                attrs['parent_validated'] = True
                return attrs  # ← Len vráť attrs bez super()
                    
        class TestSerializer(CategoryWorkspaceMixin, ParentSerializer):
            def validate(self, data):
                # Volaj parent explicitne
                data = ParentSerializer.validate(self, data)
                # Potom mixin
                data = CategoryWorkspaceMixin.validate(self, data)
                data['child_validated'] = True
                return data
        
        request = self.create_request(workspace=self.workspace1)
        
        serializer = TestSerializer()
        serializer.context = {'request': request}
        
        data = {'version': self.expense_version1}
        result_data = serializer.validate(data)
        
        self.assertEqual(result_data['version'], self.expense_version1)
        self.assertEqual(result_data['parent_validated'], True)  # ← Teraz funguje
        self.assertEqual(result_data['child_validated'], True)


class TestMixinsIntegration(TestCase, BaseTestMixin):
    """Integration tests for multiple mixins."""
    
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
        
        WorkspaceMembership.objects.all().delete()

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
        """Test integration of all three mixins."""
        class IntegratedSerializer(TargetUserMixin, WorkspaceMembershipMixin, CategoryWorkspaceMixin, serializers.Serializer):
            def get_user_role(self, obj):
                request = self.context.get('request')
                if request:
                    return self._get_membership_for_workspace(obj, request)
                return None
        
        request = self.factory.get('/')
        request.user = self.user
        request.target_user = self.target_user
        request.workspace = self.workspace
        request.is_admin_impersonation = True
        
        context = {'request': request}
        serializer = IntegratedSerializer(context=context)
        
        data_with_user = serializer.validate({'version': self.category_version})
        self.assertEqual(data_with_user['user'], self.target_user)
        
        role = serializer.get_user_role(self.workspace)
        self.assertEqual(role, 'owner')
        
        result_data = serializer.validate({'version': self.category_version})
        self.assertEqual(result_data['version'], self.category_version)

    @patch('finance.mixins.logger')
    def test_comprehensive_logging_integration(self, mock_logger):
        """Test logging integration across all mixins."""
        class LoggingSerializer(TargetUserMixin, WorkspaceMembershipMixin, CategoryWorkspaceMixin, serializers.Serializer):
            pass
        
        request = self.factory.get('/')
        request.user = self.user
        request.target_user = self.target_user
        request.workspace = self.workspace
        request.is_admin_impersonation = True
        
        context = {'request': request}
        serializer = LoggingSerializer(context=context)
        
        serializer._get_user_memberships(request)
        serializer.validate({'version': self.category_version})
        
        debug_calls = [call for call in mock_logger.debug.call_args_list]
        self.assertGreaterEqual(len(debug_calls), 2)
        
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