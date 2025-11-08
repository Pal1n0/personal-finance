import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import Mock, patch
from rest_framework.exceptions import ValidationError as DRFValidationError

from finance.serializers import (
    UserSettingsSerializer,
    WorkspaceSerializer,
    WorkspaceMembershipSerializer,
    WorkspaceSettingsSerializer,
    TransactionSerializer,
    TransactionListSerializer,
    ExpenseCategorySerializer,
    IncomeCategorySerializer
)
from finance.models import (
    UserSettings, Workspace, WorkspaceMembership, WorkspaceSettings,
    Transaction, ExpenseCategory, IncomeCategory, ExpenseCategoryVersion,
    IncomeCategoryVersion
)

User = get_user_model()


class TestUserSettingsSerializer(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@test.com',
            password='testpass123',
            username='testuser'
        )
        self.user_settings = UserSettings.objects.create(
            user=self.user,
            language='en'
        )

    def test_valid_serialization(self):
        serializer = UserSettingsSerializer(instance=self.user_settings)
        
        self.assertEqual(serializer.data['language'], 'en')
        self.assertEqual(serializer.data['user'], self.user.id)

    def test_valid_language_validation(self):
        serializer = UserSettingsSerializer(data={'language': 'en'})
        
        self.assertTrue(serializer.is_valid())

    @patch('finance.serializers.settings')
    def test_invalid_language_validation(self, mock_settings):
        mock_settings.LANGUAGES = [('en', 'English'), ('sk', 'Slovak')]
        serializer = UserSettingsSerializer(data={'language': 'invalid'})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('language', serializer.errors)


class TestWorkspaceSerializer(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email='owner@test.com',
            password='testpass123',
            username='owner'
        )
        self.member = User.objects.create_user(
            email='member@test.com',
            password='testpass123',
            username='member'
        )
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.owner
        )
        self.membership = WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user=self.member,
            role='editor'
        )
        
        self.request = Mock()
        self.request.user = self.member

    def test_serialization_with_membership_data(self):
        serializer = WorkspaceSerializer(
            instance=self.workspace,
            context={'request': self.request}
        )
        
        data = serializer.data
        self.assertEqual(data['name'], 'Test Workspace')
        self.assertEqual(data['owner_username'], 'owner')

    def test_user_role_retrieval(self):
        serializer = WorkspaceSerializer(
            instance=self.workspace,
            context={'request': self.request}
        )
        
        role = serializer.get_user_role(self.workspace)
        self.assertEqual(role, 'editor')

    def test_member_count_calculation(self):
        serializer = WorkspaceSerializer(
            instance=self.workspace,
            context={'request': self.request}
        )
        
        count = serializer.get_member_count(self.workspace)
        self.assertEqual(count, 2)  # owner + member

    def test_ownership_check_for_owner(self):
        self.request.user = self.owner
        serializer = WorkspaceSerializer(
            instance=self.workspace,
            context={'request': self.request}
        )
        
        is_owner = serializer.get_is_owner(self.workspace)
        self.assertTrue(is_owner)

    def test_ownership_check_for_non_owner(self):
        serializer = WorkspaceSerializer(
            instance=self.workspace,
            context={'request': self.request}
        )
        
        is_owner = serializer.get_is_owner(self.workspace)
        self.assertFalse(is_owner)

    def test_user_permissions_calculation(self):
        serializer = WorkspaceSerializer(
            instance=self.workspace,
            context={'request': self.request}
        )
        
        permissions = serializer.get_user_permissions(self.workspace)
        self.assertTrue(permissions['can_view'])
        self.assertTrue(permissions['can_create_transactions'])
        self.assertFalse(permissions['can_manage_members'])

    def test_anonymous_user_permissions(self):
        serializer = WorkspaceSerializer(instance=self.workspace)
        
        permissions = serializer.get_user_permissions(self.workspace)
        self.assertFalse(permissions['can_view'])
        self.assertFalse(permissions['can_create_transactions'])

    def test_valid_name_validation(self):
        serializer = WorkspaceSerializer(data={'name': 'Valid Name'})
        
        self.assertTrue(serializer.is_valid())

    def test_name_too_short_validation(self):
        serializer = WorkspaceSerializer(data={'name': 'A'})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('name', serializer.errors)

    def test_name_too_long_validation(self):
        long_name = 'A' * 101
        serializer = WorkspaceSerializer(data={'name': long_name})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('name', serializer.errors)

    def test_name_stripping_validation(self):
        serializer = WorkspaceSerializer(data={'name': '  Test Workspace  '})
        
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['name'], 'Test Workspace')

    @patch('finance.serializers.logger')
    def test_workspace_creation(self, mock_logger):
        self.request.user = self.owner
        serializer = WorkspaceSerializer(
            data={'name': 'New Workspace'},
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())
        workspace = serializer.save()
        
        self.assertEqual(workspace.name, 'New Workspace')
        self.assertEqual(workspace.owner, self.owner)
        
        # Check that membership was created
        membership = WorkspaceMembership.objects.get(
            workspace=workspace,
            user=self.owner
        )
        self.assertEqual(membership.role, 'admin')


class TestWorkspaceMembershipSerializer(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email='owner@test.com',
            password='testpass123',
            username='owner'
        )
        self.admin = User.objects.create_user(
            email='admin@test.com',
            password='testpass123',
            username='admin'
        )
        self.member = User.objects.create_user(
            email='member@test.com',
            password='testpass123',
            username='member'
        )
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.owner
        )
        
        # Create admin membership
        WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user=self.admin,
            role='admin'
        )
        
        # Create regular membership to update
        self.membership = WorkspaceMembership.objects.create(
            workspace=self.workspace,
            user=self.member,
            role='viewer'
        )
        
        self.request = Mock()
        self.request.user = self.admin

    def test_serialization_with_user_data(self):
        serializer = WorkspaceMembershipSerializer(instance=self.membership)
        
        data = serializer.data
        self.assertEqual(data['user_username'], 'member')
        self.assertEqual(data['workspace_name'], 'Test Workspace')

    def test_ownership_check(self):
        owner_membership = WorkspaceMembership.objects.get(
            workspace=self.workspace,
            user=self.owner
        )
        serializer = WorkspaceMembershipSerializer(instance=owner_membership)
        
        is_owner = serializer.get_is_workspace_owner(owner_membership)
        self.assertTrue(is_owner)

    def test_valid_role_validation(self):
        serializer = WorkspaceMembershipSerializer(
            instance=self.membership,
            data={'role': 'editor'},
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())

    def test_invalid_role_validation(self):
        serializer = WorkspaceMembershipSerializer(
            instance=self.membership,
            data={'role': 'invalid_role'},
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('role', serializer.errors)

    def test_owner_role_change_blocked(self):
        owner_membership = WorkspaceMembership.objects.get(
            workspace=self.workspace,
            user=self.owner
        )
        serializer = WorkspaceMembershipSerializer(
            instance=owner_membership,
            data={'role': 'viewer'},
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('role', serializer.errors)

    def test_regular_user_cannot_change_roles(self):
        self.request.user = self.member
        serializer = WorkspaceMembershipSerializer(
            instance=self.membership,
            data={'role': 'editor'},
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('role', serializer.errors)


class TestWorkspaceSettingsSerializer(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email='owner@test.com',
            password='testpass123',
            username='owner'
        )
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.owner
        )
        self.settings = WorkspaceSettings.objects.create(
            workspace=self.workspace,
            domestic_currency='EUR',
            fiscal_year_start=1,
            display_mode='light',
            accounting_mode='accrual'
        )

    def test_valid_serialization(self):
        serializer = WorkspaceSettingsSerializer(instance=self.settings)
        
        data = serializer.data
        self.assertEqual(data['domestic_currency'], 'EUR')
        self.assertEqual(data['fiscal_year_start'], 1)

    def test_valid_currency_validation(self):
        serializer = WorkspaceSettingsSerializer(data={'domestic_currency': 'USD'})
        
        self.assertTrue(serializer.is_valid())

    def test_invalid_currency_validation(self):
        serializer = WorkspaceSettingsSerializer(data={'domestic_currency': 'INVALID'})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('domestic_currency', serializer.errors)

    def test_valid_fiscal_year_start_validation(self):
        serializer = WorkspaceSettingsSerializer(data={'fiscal_year_start': 6})
        
        self.assertTrue(serializer.is_valid())

    def test_invalid_fiscal_year_start_validation(self):
        serializer = WorkspaceSettingsSerializer(data={'fiscal_year_start': 13})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('fiscal_year_start', serializer.errors)


class TestTransactionSerializer(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email='owner@test.com',
            password='testpass123',
            username='owner'
        )
        self.user = User.objects.create_user(
            email='user@test.com',
            password='testpass123',
            username='user'
        )
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.owner
        )
        
        # Create category versions
        self.expense_version = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace,
            name='Expense Version',
            created_by=self.owner
        )
        self.income_version = IncomeCategoryVersion.objects.create(
            workspace=self.workspace,
            name='Income Version', 
            created_by=self.owner
        )
        
        # Create categories
        self.expense_category = ExpenseCategory.objects.create(
            name='Office Supplies',
            version=self.expense_version,
            level=1
        )
        self.income_category = IncomeCategory.objects.create(
            name='Sales',
            version=self.income_version,
            level=1
        )
        
        self.request = Mock()
        self.request.workspace = self.workspace
        self.request.user = self.user

    def test_serializer_initialization_with_workspace(self):
        serializer = TransactionSerializer(context={'request': self.request})
        
        self.assertEqual(
            serializer.fields['expense_category'].queryset.model,
            ExpenseCategory
        )
        self.assertEqual(
            serializer.fields['income_category'].queryset.model, 
            IncomeCategory
        )

    def test_target_user_mixin_functionality(self):
        self.request.target_user = self.user
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': 100.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)

    def test_valid_expense_transaction(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': 100.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())

    def test_valid_income_transaction(self):
        serializer = TransactionSerializer(
            data={
                'type': 'income',
                'income_category': self.income_category.id, 
                'original_amount': 200.00,
                'original_currency': 'USD'
            },
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())

    def test_both_categories_provided_validation_error(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'income_category': self.income_category.id,
                'original_amount': 100.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_no_category_provided_validation_error(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'original_amount': 100.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_expense_with_income_category_validation_error(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'income_category': self.income_category.id,
                'original_amount': 100.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_income_with_expense_category_validation_error(self):
        serializer = TransactionSerializer(
            data={
                'type': 'income',
                'expense_category': self.expense_category.id,
                'original_amount': 200.00,
                'original_currency': 'USD'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_cross_workspace_category_access_blocked(self):
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.owner
        )
        other_version = ExpenseCategoryVersion.objects.create(
            workspace=other_workspace,
            name='Other Version',
            created_by=self.owner
        )
        other_category = ExpenseCategory.objects.create(
            name='Other Category',
            version=other_version,
            level=1
        )
        
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': other_category.id,
                'original_amount': 100.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_invalid_amount_validation(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': 0,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_negative_amount_validation(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': -50.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_valid_currency_validation(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': 100.00,
                'original_currency': 'USD'
            },
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())

    def test_invalid_currency_validation(self):
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': 100.00,
                'original_currency': 'INVALID'
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('original_currency', serializer.errors)

    @patch('finance.serializers.logger')
    def test_security_violation_logging(self, mock_logger):
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.owner
        )
        other_version = ExpenseCategoryVersion.objects.create(
            workspace=other_workspace,
            name='Other Version',
            created_by=self.owner
        )
        other_category = ExpenseCategory.objects.create(
            name='Other Category',
            version=other_version,
            level=1
        )
        
        serializer = TransactionSerializer(
            data={
                'type': 'expense',
                'expense_category': other_category.id,
                'original_amount': 100.00,
                'original_currency': 'EUR'
            },
            context={'request': self.request}
        )
        
        serializer.is_valid()
        
        mock_logger.warning.assert_called()


class TestTransactionListSerializer(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email='owner@test.com',
            password='testpass123',
            username='owner'
        )
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.owner
        )
        self.transaction = Transaction.objects.create(
            user=self.owner,
            workspace=self.workspace,
            type='expense',
            original_amount=100.00,
            original_currency='EUR',
            amount_domestic=100.00
        )

    def test_lightweight_serialization(self):
        serializer = TransactionListSerializer(instance=self.transaction)
        
        data = serializer.data
        self.assertEqual(data['type'], 'expense')
        self.assertEqual(data['original_amount'], '100.00')
        self.assertEqual(data['workspace'], self.workspace.id)

    def test_category_name_for_expense(self):
        self.transaction.expense_category_id = 1
        serializer = TransactionListSerializer(instance=self.transaction)
        
        category_name = serializer.get_category_name(self.transaction)
        self.assertEqual(category_name, 'Expense Category #1')

    def test_category_name_for_income(self):
        self.transaction.income_category_id = 2
        serializer = TransactionListSerializer(instance=self.transaction)
        
        category_name = serializer.get_category_name(self.transaction)
        self.assertEqual(category_name, 'Income Category #2')

    def test_category_name_when_no_category(self):
        serializer = TransactionListSerializer(instance=self.transaction)
        
        category_name = serializer.get_category_name(self.transaction)
        self.assertIsNone(category_name)

    def test_all_fields_are_read_only(self):
        serializer = TransactionListSerializer()
        
        for field_name, field in serializer.fields.items():
            self.assertTrue(field.read_only, f"Field {field_name} should be read-only")


class TestCategorySerializers(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email='owner@test.com',
            password='testpass123',
            username='owner'
        )
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            owner=self.owner
        )
        self.expense_version = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace,
            name='Expense Version',
            created_by=self.owner
        )
        self.income_version = IncomeCategoryVersion.objects.create(
            workspace=self.workspace,
            name='Income Version',
            created_by=self.owner
        )
        self.expense_category = ExpenseCategory.objects.create(
            name='Test Expense',
            version=self.expense_version,
            level=1
        )
        self.income_category = IncomeCategory.objects.create(
            name='Test Income',
            version=self.income_version, 
            level=1
        )
        
        self.request = Mock()
        self.request.workspace = self.workspace

    def test_expense_category_serialization(self):
        serializer = ExpenseCategorySerializer(instance=self.expense_category)
        
        data = serializer.data
        self.assertEqual(data['name'], 'Test Expense')
        self.assertEqual(data['level'], 1)

    def test_income_category_serialization(self):
        serializer = IncomeCategorySerializer(instance=self.income_category)
        
        data = serializer.data
        self.assertEqual(data['name'], 'Test Income')
        self.assertEqual(data['level'], 1)

    def test_expense_category_validation(self):
        serializer = ExpenseCategorySerializer(
            data={'name': '  New Expense  '},
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['name'], 'New Expense')

    def test_income_category_validation(self):
        serializer = IncomeCategorySerializer(
            data={'name': '  New Income  '},
            context={'request': self.request}
        )
        
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['name'], 'New Income')

    def test_category_name_too_short_validation(self):
        serializer = ExpenseCategorySerializer(
            data={'name': 'A'},
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('name', serializer.errors)

    def test_workspace_validation_in_category_mixin(self):
        other_workspace = Workspace.objects.create(
            name='Other Workspace',
            owner=self.owner
        )
        other_version = ExpenseCategoryVersion.objects.create(
            workspace=other_workspace,
            name='Other Version',
            created_by=self.owner
        )
        
        serializer = ExpenseCategorySerializer(
            data={
                'name': 'Test Category',
                'version': other_version.id
            },
            context={'request': self.request}
        )
        
        self.assertFalse(serializer.is_valid())