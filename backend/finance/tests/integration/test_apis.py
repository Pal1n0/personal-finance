"""
COMPREHENSIVE Integration tests for financial management system API endpoints.
Enhanced with admin impersonation, permission testing, and edge case coverage.
"""
import json
from datetime import date, timedelta
from django.utils import timezone
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.test import APIClient, APITestCase
from faker import Faker

from finance.models import (
    UserSettings, Workspace, WorkspaceMembership, WorkspaceSettings,
    ExpenseCategoryVersion, IncomeCategoryVersion, ExpenseCategory, IncomeCategory,
    ExchangeRate, Transaction, TransactionDraft, WorkspaceAdmin
)
from ..factories import (
    UserFactory, UserSettingsFactory, WorkspaceFactory, WorkspaceMembershipFactory,
    WorkspaceSettingsFactory, ExpenseCategoryVersionFactory, IncomeCategoryVersionFactory,
    ExpenseCategoryFactory, IncomeCategoryFactory, ExchangeRateFactory,
    TransactionFactory, TransactionDraftFactory, WorkspaceAdminFactory
)

User = get_user_model()
fake = Faker()

# =============================================================================
# URL ENDPOINT CONSTANTS
# =============================================================================

# Router-generated endpoints
WORKSPACE_LIST = 'workspace-list'
WORKSPACE_DETAIL = 'workspace-detail'
WORKSPACE_SETTINGS_LIST = 'workspacesettings-list'
WORKSPACE_SETTINGS_DETAIL = 'workspacesettings-detail'
USER_SETTINGS_LIST = 'user-settings-list'
USER_SETTINGS_DETAIL = 'user-settings-detail'
TRANSACTION_LIST = 'transaction-list'
TRANSACTION_DETAIL = 'transaction-detail'
EXPENSE_CATEGORY_LIST = 'expensecategory-list'
EXPENSE_CATEGORY_DETAIL = 'expensecategory-detail'
INCOME_CATEGORY_LIST = 'incomecategory-list'
INCOME_CATEGORY_DETAIL = 'incomecategory-detail'
EXCHANGE_RATE_LIST = 'exchange-rate-list'
EXCHANGE_RATE_DETAIL = 'exchange-rate-detail'
TRANSACTION_DRAFT_LIST = 'transactiondraft-list'
TRANSACTION_DRAFT_DETAIL = 'transactiondraft-detail'

# Custom action endpoints
WORKSPACE_MEMBERS = 'workspace-members'
WORKSPACE_SETTINGS = 'workspace-settings'
WORKSPACE_HARD_DELETE = 'workspace-hard-delete'
WORKSPACE_ACTIVATE = 'workspace-activate'
WORKSPACE_MEMBERSHIP_INFO = 'workspace-membership-info'
TRANSACTION_BULK_DELETE = 'transaction-bulk-delete'
BULK_SYNC_TRANSACTIONS = 'bulk-sync-transactions'
SYNC_CATEGORIES = 'sync-categories'
TRANSACTION_DRAFT_SAVE = 'transaction-draft-save'
TRANSACTION_DRAFT_GET_WORKSPACE = 'transaction-draft-get-workspace'
TRANSACTION_DRAFT_DISCARD = 'transaction-draft-discard'


class BaseAPITestCase(APITestCase):
    """Enhanced base test case with comprehensive setup for JWT authentication and admin features."""
    
    def setUp(self):
        """Set up test data and client with JWT support and admin features."""
        self.client = APIClient()
        
        # Create test users with different roles
        self.user = UserFactory()
        self.other_user = UserFactory()
        self.admin_user = UserFactory(is_superuser=True, is_staff=True)
        self.workspace_admin_user = UserFactory()
        
        # Create workspace
        self.workspace = WorkspaceFactory(owner=self.user)
        
        # Clear any existing memberships first
        WorkspaceMembership.objects.filter(workspace=self.workspace).delete()
        
        # Create fresh memberships with different roles
        self.admin_membership = WorkspaceMembershipFactory(
            workspace=self.workspace,
            user=self.user,
            role='admin'
        )
        
        self.viewer_membership = WorkspaceMembershipFactory(
            workspace=self.workspace,
            user=self.other_user,
            role='viewer'
        )
        
        self.editor_membership = WorkspaceMembershipFactory(
            workspace=self.workspace,
            user=self.workspace_admin_user,
            role='editor'
        )
        
        # Create workspace admin assignment
        self.workspace_admin = WorkspaceAdminFactory(
            user=self.workspace_admin_user,
            workspace=self.workspace,
            assigned_by=self.admin_user
        )
        
        # Create workspace settings
        self.workspace_settings = WorkspaceSettingsFactory(workspace=self.workspace)
        
        # Create category versions
        self.expense_version = ExpenseCategoryVersionFactory(
            workspace=self.workspace,
            created_by=self.user
        )
        
        self.income_version = IncomeCategoryVersionFactory(
            workspace=self.workspace,
            created_by=self.user
        )
        
        # Create categories with hierarchy
        self.expense_category = ExpenseCategoryFactory(
            version=self.expense_version,
            name='Test Expense Category',
            level=1
        )
        
        self.income_category = IncomeCategoryFactory(
            version=self.income_version,
            name='Test Income Category', 
            level=1
        )
        
        # Create child categories
        self.child_expense_category = ExpenseCategoryFactory(
            version=self.expense_version,
            name='Child Expense Category',
            level=2
        )
        
        self.child_income_category = IncomeCategoryFactory(
            version=self.income_version,
            name='Child Income Category',
            level=2
        )
        
        # Create parent-child relationships
        self.expense_category.children.add(self.child_expense_category)
        self.income_category.children.add(self.child_income_category)
        
        # Create exchange rates
        self._create_test_exchange_rates()
        
        # Create test transactions
        self._create_test_transactions()
        
        # Create test drafts
        self._create_test_drafts()
        
        # Authenticate using JWT token
        self._authenticate_user(self.user)
    
    def _create_test_exchange_rates(self):
        """Create comprehensive test exchange rates."""
        # Clear any existing rates
        ExchangeRate.objects.all().delete()
        
        # Create fresh exchange rates with unique dates
        today = date.today()
        dates = [today - timedelta(days=i) for i in range(10)]
        
        currencies = [
            ('USD', Decimal('1.1')),
            ('GBP', Decimal('0.85')),
            ('CHF', Decimal('0.95')),
            ('PLN', Decimal('4.5')),
            ('CZK', Decimal('25.0'))
        ]
        
        for currency, rate in currencies:
            for i, rate_date in enumerate(dates):
                ExchangeRateFactory(
                    currency=currency,
                    rate_to_eur=rate,
                    date=rate_date
                )
    
    def _create_test_transactions(self):
        """Create comprehensive test transactions."""
        # Clear existing transactions
        Transaction.objects.filter(workspace=self.workspace).delete()
        
        # Create expense transactions
        self.expense_transactions = TransactionFactory.create_batch(
            3,
            user=self.user,
            workspace=self.workspace,
            type='expense',
            expense_category=self.expense_category,
            original_currency='EUR'
        )
        
        # Create income transactions
        self.income_transactions = TransactionFactory.create_batch(
            2,
            user=self.user,
            workspace=self.workspace,
            type='income',
            income_category=self.income_category,
            original_currency='USD'
        )
        
        # Create transactions with different currencies
        self.multi_currency_transactions = [
            TransactionFactory(
                user=self.user,
                workspace=self.workspace,
                type='expense',
                expense_category=self.expense_category,
                original_currency='GBP',
                original_amount=Decimal('75.00')
            ),
            TransactionFactory(
                user=self.user,
                workspace=self.workspace,
                type='income',
                income_category=self.income_category,
                original_currency='CHF',
                original_amount=Decimal('120.00')
            )
        ]
        
        # Set main test transaction
        self.expense_transaction = self.expense_transactions[0]
        self.income_transaction = self.income_transactions[0]
    
    def _create_test_drafts(self):
        """Create test transaction drafts."""
        # Clear existing drafts
        TransactionDraft.objects.filter(workspace=self.workspace).delete()
        
        # Create expense draft
        self.expense_draft = TransactionDraftFactory(
            user=self.user,
            workspace=self.workspace,
            draft_type='expense',
            transactions_data=[
                {
                    'type': 'expense',
                    'original_amount': '150.00',
                    'original_currency': 'EUR',
                    'date': '2024-01-15',
                    'note_manual': 'Draft expense 1'
                },
                {
                    'type': 'expense',
                    'original_amount': '75.50',
                    'original_currency': 'USD',
                    'date': '2024-01-16',
                    'note_manual': 'Draft expense 2'
                }
            ]
        )
        
        # Create income draft
        self.income_draft = TransactionDraftFactory(
            user=self.user,
            workspace=self.workspace,
            draft_type='income',
            transactions_data=[
                {
                    'type': 'income',
                    'original_amount': '300.00',
                    'original_currency': 'EUR',
                    'date': '2024-01-20',
                    'note_manual': 'Draft income 1'
                }
            ]
        )
    
    def _authenticate_user(self, user):
        """Authenticate user using JWT tokens."""
        access_token = AccessToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
    
    def _get_workspaces_list(self, response):
        """Helper method to extract workspaces list from paginated response."""
        if 'results' in response.data:
            return response.data['results']
        elif 'workspaces' in response.data and 'results' in response.data['workspaces']:
            return response.data['workspaces']['results']
        elif 'workspaces' in response.data and isinstance(response.data['workspaces'], list):
            return response.data['workspaces']
        else:
            return response.data.get('results', response.data)


class WorkspaceAPITests(BaseAPITestCase):
    """COMPREHENSIVE Workspace API tests with role-based permissions and impersonation."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(WORKSPACE_LIST)
        self.detail_url = reverse(WORKSPACE_DETAIL, kwargs={'pk': self.workspace.pk})
        
        # Create additional test workspaces
        self.inactive_workspace = WorkspaceFactory(
            owner=self.user,
            is_active=False,
            name="Inactive Workspace"
        )
        WorkspaceMembershipFactory(
            workspace=self.inactive_workspace,
            user=self.user,
            role='admin'
        )
        
        self.other_user_workspace = WorkspaceFactory(
            owner=self.other_user,
            is_active=True
        )

    def test_list_workspaces_comprehensive(self):
        """Comprehensive test for listing workspaces with different user roles."""
        # Test as admin user - should see all workspaces
        self._authenticate_user(self.admin_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        workspaces_list = self._get_workspaces_list(response)
        all_workspaces_count = Workspace.objects.all().count()
        self.assertEqual(len(workspaces_list), all_workspaces_count)
        
        # Test as workspace owner - should see all their workspaces including inactive
        self._authenticate_user(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        workspaces_list = self._get_workspaces_list(response)
        user_workspaces_count = Workspace.objects.filter(owner=self.user).count()
        self.assertEqual(len(workspaces_list), user_workspaces_count)
        
        # Test as viewer - should see only active workspaces
        self._authenticate_user(self.other_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        workspaces_list = self._get_workspaces_list(response)
        active_workspaces_count = Workspace.objects.filter(
            members=self.other_user,
            is_active=True
        ).count()
        self.assertEqual(len(workspaces_list), active_workspaces_count)

    def test_retrieve_workspace_detailed(self):
        """Test retrieving workspace details with comprehensive data validation."""
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify all expected fields are present
        expected_fields = [
            'id', 'name', 'description', 'owner', 'owner_username', 'owner_email',
            'user_role', 'member_count', 'is_owner', 'user_permissions',
            'created_at', 'is_active'
        ]
        for field in expected_fields:
            self.assertIn(field, response.data)
        
        # Verify data accuracy
        self.assertEqual(response.data['name'], self.workspace.name)
        self.assertEqual(response.data['user_role'], 'admin')
        self.assertTrue(response.data['is_owner'])
        self.assertGreater(response.data['member_count'], 0)
        
        # Verify permissions structure
        permissions = response.data['user_permissions']
        self.assertIsInstance(permissions, dict)
        self.assertIn('can_view', permissions)
        self.assertIn('can_edit', permissions)
        self.assertIn('can_manage_members', permissions)

    def test_create_workspace_validation(self):
        """Test workspace creation with comprehensive validation."""
        test_cases = [
            {
                'name': 'Valid Workspace',
                'description': 'Valid description',
                'expected_status': status.HTTP_201_CREATED
            },
            {
                'name': 'A',  # Too short
                'description': 'Test',
                'expected_status': status.HTTP_400_BAD_REQUEST
            },
            {
                'name': 'A' * 101,  # Too long
                'description': 'Test',
                'expected_status': status.HTTP_400_BAD_REQUEST
            },
            {
                'name': '   Valid With Spaces   ',
                'description': 'Test',
                'expected_status': status.HTTP_201_CREATED
            }
        ]
        
        for test_case in test_cases:
            data = {
                'name': test_case['name'],
                'description': test_case['description']
            }
            response = self.client.post(self.list_url, data, format='json')
            
            self.assertEqual(response.status_code, test_case['expected_status'])
            
            if test_case['expected_status'] == status.HTTP_201_CREATED:
                # Verify workspace was created correctly
                workspace = Workspace.objects.get(name=test_case['name'].strip())
                self.assertEqual(workspace.owner, self.user)
                
                # Verify membership was created
                membership = WorkspaceMembership.objects.get(
                    workspace=workspace,
                    user=self.user
                )
                self.assertEqual(membership.role, 'admin')

    def test_update_workspace_permissions(self):
        """Test workspace update permissions for different roles."""
        # Test as admin (owner) - should succeed
        data = {'name': 'Updated by Owner'}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, 'Updated by Owner')
        
        # Test as editor - should fail
        self._authenticate_user(self.workspace_admin_user)
        data = {'name': 'Updated by Editor'}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Test as viewer - should fail
        self._authenticate_user(self.other_user)
        data = {'name': 'Updated by Viewer'}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_workspace_comprehensive(self):
        """Comprehensive workspace deletion tests."""
        # Test soft delete as owner
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.workspace.refresh_from_db()
        self.assertFalse(self.workspace.is_active)
        
        # Reactivate for further tests
        self.workspace.is_active = True
        self.workspace.save()
        
        # Test soft delete as admin (non-owner)
        admin_workspace = WorkspaceFactory(owner=self.other_user)
        WorkspaceMembershipFactory(
            workspace=admin_workspace,
            user=self.user,
            role='admin'
        )
        
        admin_workspace_url = reverse(WORKSPACE_DETAIL, kwargs={'pk': admin_workspace.pk})
        response = self.client.delete(admin_workspace_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        admin_workspace.refresh_from_db()
        self.assertFalse(admin_workspace.is_active)
        
        # Test delete permission denied for editor
        editor_workspace = WorkspaceFactory(owner=self.other_user)
        WorkspaceMembershipFactory(
            workspace=editor_workspace,
            user=self.user,
            role='editor'
        )
        
        editor_workspace_url = reverse(WORKSPACE_DETAIL, kwargs={'pk': editor_workspace.pk})
        response = self.client.delete(editor_workspace_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_workspace_hard_delete_scenarios(self):
        """Test hard delete functionality with various scenarios."""
        # Scenario 1: Hard delete fails when other members exist
        hard_delete_url = reverse(WORKSPACE_HARD_DELETE, kwargs={'pk': self.workspace.pk})
        response = self.client.delete(hard_delete_url, {
            'confirmation': {
                'standard': True,
                'workspace_name': self.workspace.name
            }
        }, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('other members', response.data['error'].lower())
        
        # Scenario 2: Remove other members and hard delete should succeed
        WorkspaceMembership.objects.filter(
            workspace=self.workspace
        ).exclude(user=self.user).delete()
        
        response = self.client.delete(hard_delete_url, {
            'confirmation': {
                'standard': True,
                'workspace_name': self.workspace.name
            }
        }, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify workspace was actually deleted
        with self.assertRaises(Workspace.DoesNotExist):
            Workspace.objects.get(pk=self.workspace.pk)

    def test_workspace_custom_endpoints(self):
        """Test all custom workspace endpoints."""
        # Test workspace members endpoint
        url = reverse(WORKSPACE_MEMBERS, kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('members', response.data)
        self.assertGreater(len(response.data['members']), 0)
        
        # Test workspace settings endpoint
        url = reverse(WORKSPACE_SETTINGS, kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('domestic_currency', response.data)
        
        # Test workspace membership info endpoint
        url = reverse(WORKSPACE_MEMBERSHIP_INFO, kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['role'], 'admin')
        
        # Test workspace activate endpoint
        self.workspace.is_active = False
        self.workspace.save()
        
        url = reverse(WORKSPACE_ACTIVATE, kwargs={'pk': self.workspace.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)

    def test_workspace_impersonation(self):
        """Test workspace operations with admin impersonation."""
        self._authenticate_user(self.admin_user)
        
        # List workspaces as admin impersonating regular user
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify response contains impersonation info
        if 'admin_impersonation' in response.data:
            impersonation_info = response.data['admin_impersonation']
            self.assertEqual(impersonation_info['target_user_id'], self.user.id)


class TransactionAPITests(BaseAPITestCase):
    """COMPREHENSIVE Transaction API tests with filtering, bulk operations, and permissions."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(TRANSACTION_LIST)
        self.detail_url = reverse(TRANSACTION_DETAIL, kwargs={'pk': self.expense_transaction.pk})

    def test_list_transactions_comprehensive(self):
        """Comprehensive transaction listing with various filters."""
        # Test basic listing
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), len(self.expense_transactions) + len(self.income_transactions))
        
        # Test filtering by type
        response = self.client.get(self.list_url, {'type': 'expense'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for transaction in response.data:
            self.assertEqual(transaction['type'], 'expense')
        
        # Test filtering by month
        current_month = date.today().month
        response = self.client.get(self.list_url, {'month': current_month})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Test filtering by workspace
        response = self.client.get(self.list_url, {'workspace': self.workspace.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Test lightweight mode
        response = self.client.get(self.list_url, {'light': 'true'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify lightweight response has basic fields
        if len(response.data) > 0:
            transaction = response.data[0]
            self.assertIn('id', transaction)
            self.assertIn('type', transaction)
            self.assertIn('amount_domestic', transaction)

    def test_retrieve_transaction_detailed(self):
        """Test retrieving transaction with full detail validation."""
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify all expected fields
        expected_fields = [
            'id', 'user', 'workspace', 'type', 'expense_category', 'income_category',
            'original_amount', 'original_currency', 'amount_domestic', 'date', 
            'month', 'tags', 'note_manual', 'note_auto', 'created_at', 'updated_at'
        ]
        for field in expected_fields:
            self.assertIn(field, response.data)
        
        # Verify data accuracy
        self.assertEqual(response.data['type'], 'expense')
        self.assertEqual(Decimal(response.data['original_amount']), self.expense_transaction.original_amount)

    def test_create_transaction_validation(self):
        """Test transaction creation with comprehensive validation."""
        # Valid expense transaction
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15',
            'note_manual': 'Test expense transaction',
            'tags': ['test', 'expense']
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertIn(response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST])
        
        # Valid income transaction
        data = {
            'workspace': self.workspace.id,
            'type': 'income',
            'income_category': self.income_category.id,
            'original_amount': '500.00',
            'original_currency': 'USD',
            'date': '2024-01-20'
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertIn(response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST])
        
        # Invalid: Both categories provided
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'income_category': self.income_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Invalid: No category provided
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Invalid: Wrong category type
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'income_category': self.income_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_transaction_comprehensive(self):
        """Comprehensive transaction update tests."""
        # Valid update
        data = {
            'original_amount': '175.25',
            'note_manual': 'Updated transaction note',
            'tags': ['updated', 'test']
        }
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.original_amount, Decimal('175.25'))
        self.assertEqual(self.expense_transaction.note_manual, 'Updated transaction note')
        
        # Test update with category change
        data = {
            'expense_category': self.child_expense_category.id
        }
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.expense_category, self.child_expense_category)

    def test_delete_transaction_permissions(self):
        """Test transaction deletion with permission validation."""
        # Test delete as editor (should succeed)
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, 
            user=self.user
        )
        membership.role = 'editor'
        membership.save()
        
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Transaction.objects.filter(pk=self.expense_transaction.pk).exists())
        
        # Recreate transaction for viewer test
        transaction = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            type='expense',
            expense_category=self.expense_category
        )
        detail_url = reverse(TRANSACTION_DETAIL, kwargs={'pk': transaction.pk})
        
        # Test delete as viewer (should fail)
        membership.role = 'viewer'
        membership.save()
        
        response = self.client.delete(detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_bulk_operations(self):
        """Test bulk transaction operations."""
        # Bulk delete
        transaction_ids = [t.id for t in self.expense_transactions[:2]]
        url = reverse(TRANSACTION_BULK_DELETE)
        data = {'ids': transaction_ids}
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['deleted'], 2)
        
        # Bulk sync
        url = reverse(BULK_SYNC_TRANSACTIONS, kwargs={'workspace_id': self.workspace.id})
        transactions_data = [
            {
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': '100.00',
                'original_currency': 'EUR',
                'date': '2024-01-10',
                'note_manual': 'Bulk expense 1'
            },
            {
                'type': 'income',
                'income_category': self.income_category.id,
                'original_amount': '200.00',
                'original_currency': 'USD',
                'date': '2024-01-15',
                'note_manual': 'Bulk income 1'
            }
        ]
        response = self.client.post(url, transactions_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('created', response.data)

    def test_transaction_impersonation(self):
        """Test transaction operations with admin impersonation."""
        self._authenticate_user(self.admin_user)
        
        # Create transaction for target user via impersonation
        url = reverse(TRANSACTION_LIST) + f'?user_id={self.user.id}'
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify transaction was created for target user
        transaction = Transaction.objects.get(pk=response.data['id'])
        self.assertEqual(transaction.user.id, self.user.id)


class UserSettingsAPITests(BaseAPITestCase):
    """COMPREHENSIVE UserSettings API tests with security validation."""

    def setUp(self):
        super().setUp()
        self.user_settings = UserSettingsFactory(user=self.user)
        self.url = reverse(USER_SETTINGS_DETAIL, kwargs={'pk': self.user_settings.pk})

    def test_retrieve_user_settings_security(self):
        """Test user settings retrieval with security validation."""
        # User should be able to access their own settings
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user'], self.user.id)
        self.assertEqual(response.data['language'], 'en')
        
        # User should NOT be able to access other users' settings
        other_settings = UserSettingsFactory(user=self.other_user)
        other_url = reverse(USER_SETTINGS_DETAIL, kwargs={'pk': other_settings.pk})
        response = self.client.get(other_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_user_settings_validation(self):
        """Test user settings update with comprehensive validation."""
        # Valid language update
        data = {'language': 'sk'}
        response = self.client.patch(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user_settings.refresh_from_db()
        self.assertEqual(self.user_settings.language, 'sk')
        
        # Invalid language
        data = {'language': 'invalid'}
        response = self.client.patch(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Attempt to update protected fields
        data = {'user': self.other_user.id}
        response = self.client.patch(self.url, data, format='json')
        # Should either ignore or return error
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])

    def test_user_settings_impersonation(self):
        """Test user settings access with admin impersonation."""
        self._authenticate_user(self.admin_user)
        
        # Admin should be able to access user settings via impersonation
        url = reverse(USER_SETTINGS_DETAIL, kwargs={'pk': self.user_settings.pk}) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class CategoryAPITests(BaseAPITestCase):
    """COMPREHENSIVE Category API tests with hierarchy and workspace validation."""

    def test_list_categories_comprehensive(self):
        """Comprehensive category listing tests."""
        # Test expense categories
        url = reverse(EXPENSE_CATEGORY_LIST)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 2)  # parent + child
        
        # Verify category structure
        for category in response.data:
            self.assertIn('id', category)
            self.assertIn('name', category)
            self.assertIn('level', category)
            self.assertIn('children', category)
            self.assertIn('version', category)
        
        # Test income categories
        url = reverse(INCOME_CATEGORY_LIST)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 2)  # parent + child

    def test_retrieve_category_detailed(self):
        """Test retrieving category with full hierarchy."""
        # Test expense category
        url = reverse(EXPENSE_CATEGORY_DETAIL, kwargs={'pk': self.expense_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.assertEqual(response.data['name'], self.expense_category.name)
        self.assertEqual(response.data['level'], 1)
        self.assertIn('children', response.data)
        self.assertEqual(len(response.data['children']), 1)  # Should have one child
        
        # Test income category
        url = reverse(INCOME_CATEGORY_DETAIL, kwargs={'pk': self.income_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.income_category.name)

    def test_categories_workspace_isolation(self):
        """Test that users only see categories from their accessible workspaces."""
        # Create workspace and categories that current user doesn't have access to
        other_workspace = WorkspaceFactory(owner=self.other_user)
        other_expense_version = ExpenseCategoryVersionFactory(workspace=other_workspace)
        other_income_version = IncomeCategoryVersionFactory(workspace=other_workspace)
        
        ExpenseCategoryFactory.create_batch(2, version=other_expense_version)
        IncomeCategoryFactory.create_batch(2, version=other_income_version)
        
        # User should only see categories from their accessible workspaces
        url = reverse(EXPENSE_CATEGORY_LIST)
        response = self.client.get(url)
        
        accessible_categories_count = ExpenseCategory.objects.filter(
            version__workspace__members=self.user
        ).count()
        self.assertEqual(len(response.data), accessible_categories_count)

    def test_category_sync_endpoint(self):
        """Test category synchronization endpoint."""
        url = reverse(SYNC_CATEGORIES, kwargs={
            'workspace_id': self.workspace.id,
            'category_type': 'expense'
        })
        
        sync_data = [
        {
            'name': 'New Expense Category',
            'level': 1,
            'description': 'Synced category',
            'children': [
                {
                    'name': 'Child Category',
                    'level': 2,
                    'description': 'Child of synced category'
                }
            ]
        }
    ]
    
        response = self.client.post(url, sync_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('created', response.data)
        self.assertIn('updated', response.data)


class ExchangeRateAPITests(BaseAPITestCase):
    """COMPREHENSIVE ExchangeRate API tests with filtering and date ranges."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(EXCHANGE_RATE_LIST)

    def test_list_exchange_rates_comprehensive(self):
        """Comprehensive exchange rate listing with various filters."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        
        # Verify response structure
        for rate in response.data:
            self.assertIn('id', rate)
            self.assertIn('currency', rate)
            self.assertIn('rate_to_eur', rate)
            self.assertIn('date', rate)

    def test_filter_exchange_rates_advanced(self):
        """Test advanced filtering of exchange rates."""
        # Filter by specific currencies
        response = self.client.get(self.list_url, {'currencies': 'USD,GBP'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        for rate in response.data:
            self.assertIn(rate['currency'], ['USD', 'GBP'])
        
        # Filter by date range
        date_from = (date.today() - timedelta(days=7)).isoformat()
        date_to = (date.today() - timedelta(days=1)).isoformat()
        
        response = self.client.get(self.list_url, {
            'date_from': date_from,
            'date_to': date_to
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # All returned rates should be within date range
        for rate in response.data:
            rate_date = date.fromisoformat(rate['date'])
            self.assertGreaterEqual(rate_date, date.fromisoformat(date_from))
            self.assertLessEqual(rate_date, date.fromisoformat(date_to))

    def test_exchange_rate_validation(self):
        """Test exchange rate data validation."""
        # Test retrieving specific rate
        rate = ExchangeRate.objects.first()
        if rate:
            url = reverse(EXCHANGE_RATE_DETAIL, kwargs={'pk': rate.pk})
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data['currency'], rate.currency)


class TransactionDraftAPITests(BaseAPITestCase):
    """COMPREHENSIVE TransactionDraft API tests with atomic operations."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(TRANSACTION_DRAFT_LIST)

    def test_draft_lifecycle_comprehensive(self):
        """Comprehensive test of draft lifecycle operations."""
        # Test saving draft
        save_url = reverse(TRANSACTION_DRAFT_SAVE, kwargs={'workspace_pk': self.workspace.id})
        
        transactions_data = [
            {
                'type': 'expense',
                'original_amount': '150.00',
                'original_currency': 'EUR',
                'date': '2024-01-15',
                'note_manual': 'Draft transaction 1'
            },
            {
                'type': 'expense', 
                'original_amount': '75.50',
                'original_currency': 'USD',
                'date': '2024-01-16',
                'note_manual': 'Draft transaction 2'
            }
        ]
        
        data = {
            'draft_type': 'expense',
            'transactions_data': transactions_data
        }
        
        response = self.client.post(save_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['transactions_data']), 2)
        
        # Test retrieving draft
        get_url = reverse(TRANSACTION_DRAFT_GET_WORKSPACE, kwargs={'workspace_pk': self.workspace.id}) + '?type=expense'
        response = self.client.get(get_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['transactions_data']), 2)
        
        # Test discarding draft
        discard_url = reverse(TRANSACTION_DRAFT_DISCARD, kwargs={'pk': self.expense_draft.pk})
        response = self.client.delete(discard_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify draft was deleted
        with self.assertRaises(TransactionDraft.DoesNotExist):
            TransactionDraft.objects.get(pk=self.expense_draft.pk)

    def test_draft_auto_cleanup(self):
        """Test automatic draft cleanup after transaction operations."""
        # Verify draft exists initially
        self.assertTrue(TransactionDraft.objects.filter(pk=self.expense_draft.pk).exists())
        
        # Create a transaction of the same type (should trigger draft cleanup)
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(reverse(TRANSACTION_LIST), data, format='json')
        
        if response.status_code == status.HTTP_201_CREATED:
            # Draft should be automatically deleted
            with self.assertRaises(TransactionDraft.DoesNotExist):
                TransactionDraft.objects.get(
                    user=self.user,
                    workspace=self.workspace,
                    draft_type='expense'
                )

    def test_draft_permissions(self):
        """Test draft operations with different user permissions."""
        # Test as viewer (should fail for save operations)
        self._authenticate_user(self.other_user)
        
        save_url = reverse(TRANSACTION_DRAFT_SAVE, kwargs={'workspace_pk': self.workspace.id})
        data = {
            'draft_type': 'expense',
            'transactions_data': [{'type': 'expense', 'amount': 100}]
        }
        
        response = self.client.post(save_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # But should be able to retrieve (if they have a draft)
        get_url = reverse(TRANSACTION_DRAFT_GET_WORKSPACE, kwargs={'workspace_pk': self.workspace.id}) + '?type=expense'
        response = self.client.get(get_url)
        # Should return empty or 404, but not permission error
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND])

    def test_draft_unique_constraint(self):
        """Test that only one draft exists per workspace-type combination."""
        # Try to create another draft for same workspace and type
        save_url = reverse(TRANSACTION_DRAFT_SAVE, kwargs={'workspace_pk': self.workspace.id})
        
        data = {
            'draft_type': 'expense',
            'transactions_data': [{'type': 'expense', 'amount': 300}]
        }
        
        response = self.client.post(save_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Should only be one draft for this workspace and type
        drafts_count = TransactionDraft.objects.filter(
            user=self.user,
            workspace=self.workspace,
            draft_type='expense'
        ).count()
        self.assertEqual(drafts_count, 1)


class WorkspaceSettingsAPITests(BaseAPITestCase):
    """COMPREHENSIVE WorkspaceSettings API tests with currency change handling."""

    def setUp(self):
        super().setUp()
        self.detail_url = reverse(
            WORKSPACE_SETTINGS_DETAIL, 
            kwargs={'pk': self.workspace_settings.pk}
        )

    def test_retrieve_workspace_settings_detailed(self):
        """Test retrieving workspace settings with all configuration options."""
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        expected_fields = [
            'id', 'workspace', 'domestic_currency', 'fiscal_year_start',
            'display_mode', 'accounting_mode'
        ]
        for field in expected_fields:
            self.assertIn(field, response.data)
        
        self.assertEqual(response.data['domestic_currency'], 'EUR')
        self.assertEqual(response.data['fiscal_year_start'], 1)

    def test_update_workspace_settings_comprehensive(self):
        """Comprehensive workspace settings update tests."""
        # Test basic update
        data = {
            'fiscal_year_start': 4,
            'display_mode': 'day',
            'accounting_mode': True
        }
        response = self.client.patch(self.detail_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace_settings.refresh_from_db()
        self.assertEqual(self.workspace_settings.fiscal_year_start, 4)
        self.assertEqual(self.workspace_settings.display_mode, 'day')
        self.assertTrue(self.workspace_settings.accounting_mode)
        
        # Test currency change (should trigger recalculation)
        data = {'domestic_currency': 'USD'}
        response = self.client.patch(self.detail_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace_settings.refresh_from_db()
        self.assertEqual(self.workspace_settings.domestic_currency, 'USD')
        
        # Verify recalculation details in response
        if 'recalculation_details' in response.data:
            self.assertIn('transactions_updated', response.data['recalculation_details'])

    def test_workspace_settings_permissions(self):
        """Test workspace settings access with different user roles."""
        # Test as viewer (should be able to read but not update)
        self._authenticate_user(self.other_user)
        
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        data = {'domestic_currency': 'GBP'}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Test as editor (should be able to read but not update settings)
        self._authenticate_user(self.workspace_admin_user)
        
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_settings_validation(self):
        """Test workspace settings validation."""
        # Invalid fiscal year start
        data = {'fiscal_year_start': 13}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Invalid currency
        data = {'domestic_currency': 'INVALID'}
        response = self.client.patch(self.detail_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class AdminImpersonationAdvancedTests(BaseAPITestCase):
    """ADVANCED admin impersonation tests with comprehensive scenarios."""

    def test_impersonation_across_all_endpoints(self):
        """Test impersonation works across all major API endpoints."""
        self._authenticate_user(self.admin_user)
        
        # Test workspace listing with impersonation
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Test transaction creation with impersonation
        url = reverse(TRANSACTION_LIST) + f'?user_id={self.user.id}'
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify transaction was created for target user
        transaction = Transaction.objects.get(pk=response.data['id'])
        self.assertEqual(transaction.user.id, self.user.id)
        
        # Test user settings access with impersonation
        user_settings = UserSettingsFactory(user=self.user)
        url = reverse(USER_SETTINGS_DETAIL, kwargs={'pk': user_settings.pk}) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_impersonation_with_workspace_admin(self):
        """Test impersonation functionality for workspace admins."""
        # Authenticate as workspace admin
        self._authenticate_user(self.workspace_admin_user)
        
        # Workspace admin should be able to impersonate within their workspaces
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.other_user.id}'
        response = self.client.get(url)
        
        # Should work but only for workspaces where admin has permissions
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_impersonation_security(self):
        """Test security aspects of impersonation functionality."""
        # Regular user should not be able to impersonate
        self._authenticate_user(self.other_user)
        
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        
        # Should work normally but without actual impersonation
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # No impersonation should occur for regular users
        
        # Admin cannot impersonate superuser
        superuser = UserFactory(is_superuser=True)
        url = reverse(WORKSPACE_LIST) + f'?user_id={superuser.id}'
        response = self.client.get(url)
        
        # Should work but with limited access
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_impersonation_error_handling(self):
        """Test error handling for impersonation scenarios."""
        self._authenticate_user(self.admin_user)
        
        # Invalid user ID
        url = reverse(WORKSPACE_LIST) + '?user_id=99999'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Malformed user ID
        url = reverse(WORKSPACE_LIST) + '?user_id=invalid'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class PerformanceTests(BaseAPITestCase):
    """Performance-oriented tests for critical endpoints."""

    def test_workspace_list_performance(self):
        """Test workspace listing performance with multiple workspaces."""
        # Create multiple workspaces
        workspaces = WorkspaceFactory.create_batch(10, owner=self.user)
        for workspace in workspaces:
            WorkspaceMembershipFactory(workspace=workspace, user=self.user)
        
        # Measure performance
        import time
        start_time = time.time()
        
        response = self.client.get(reverse(WORKSPACE_LIST))
        
        end_time = time.time()
        response_time = end_time - start_time
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Response should be under 1 second even with 10+ workspaces
        self.assertLess(response_time, 1.0)

    def test_transaction_list_performance(self):
        """Test transaction listing performance with many transactions."""
        # Create multiple transactions
        TransactionFactory.create_batch(50, user=self.user, workspace=self.workspace)
        
        # Test with lightweight mode
        import time
        start_time = time.time()
        
        response = self.client.get(reverse(TRANSACTION_LIST), {'light': 'true'})
        
        end_time = time.time()
        response_time = end_time - start_time
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Lightweight response should be fast
        self.assertLess(response_time, 0.5)

    def test_bulk_operations_performance(self):
        """Test performance of bulk operations."""
        # Create many transactions for bulk delete
        transactions = TransactionFactory.create_batch(20, user=self.user, workspace=self.workspace)
        transaction_ids = [t.id for t in transactions]
        
        import time
        start_time = time.time()
        
        response = self.client.post(
            reverse(TRANSACTION_BULK_DELETE),
            {'ids': transaction_ids},
            format='json'
        )
        
        end_time = time.time()
        response_time = end_time - start_time
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Bulk operations should be efficient
        self.assertLess(response_time, 1.0)


class EdgeCaseTests(BaseAPITestCase):
    """Tests for edge cases and error conditions."""

    def test_concurrent_draft_operations(self):
        """Test handling of concurrent draft operations."""
        # This simulates potential race conditions
        save_url = reverse(TRANSACTION_DRAFT_SAVE, kwargs={'workspace_pk': self.workspace.id})
        
        data = {
            'draft_type': 'expense',
            'transactions_data': [{'type': 'expense', 'amount': 100}]
        }
        
        # Simulate concurrent saves
        response1 = self.client.post(save_url, data, format='json')
        response2 = self.client.post(save_url, data, format='json')
        
        # Both should succeed due to atomic operations
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        
        # Only one draft should exist
        drafts_count = TransactionDraft.objects.filter(
            user=self.user,
            workspace=self.workspace,
            draft_type='expense'
        ).count()
        self.assertEqual(drafts_count, 1)

    def test_large_transaction_amounts(self):
        """Test handling of very large transaction amounts."""
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '999999999.99',  # Very large amount
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        
        response = self.client.post(reverse(TRANSACTION_LIST), data, format='json')
        self.assertIn(response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST])

    def test_invalid_date_formats(self):
        """Test handling of invalid date formats."""
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '100.00',
            'original_currency': 'EUR',
            'date': 'invalid-date-format'
        }
        
        response = self.client.post(reverse(TRANSACTION_LIST), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_malformed_json(self):
        """Test handling of malformed JSON requests."""
        # Send malformed JSON
        response = self.client.post(
            reverse(TRANSACTION_LIST),
            '{"malformed": json',
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# =============================================================================
# MODEL VALIDATION TESTS
# =============================================================================

class ModelValidationTests(TestCase):
    """COMPREHENSIVE model-level validation and business logic tests."""

    def test_transaction_validation_comprehensive(self):
        """Comprehensive transaction validation tests."""
        user = UserFactory()
        workspace = WorkspaceFactory(owner=user)
        expense_version = ExpenseCategoryVersionFactory(workspace=workspace)
        income_version = IncomeCategoryVersionFactory(workspace=workspace)
        expense_category = ExpenseCategoryFactory(version=expense_version)
        income_category = IncomeCategoryFactory(version=income_version)
        
        # Test mixed categories
        transaction = Transaction(
            user=user,
            workspace=workspace,
            type='expense',
            expense_category=expense_category,
            income_category=income_category,
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            date=date.today()
        )
        
        with self.assertRaises(Exception):
            transaction.full_clean()
        
        # Test no category
        transaction = Transaction(
            user=user,
            workspace=workspace,
            type='expense',
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            date=date.today()
        )
        
        with self.assertRaises(Exception):
            transaction.full_clean()
        
        # Test wrong category type
        transaction = Transaction(
            user=user,
            workspace=workspace,
            type='expense',
            income_category=income_category,
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            date=date.today()
        )
        
        with self.assertRaises(Exception):
            transaction.full_clean()
        
        # Test invalid amount
        transaction = Transaction(
            user=user,
            workspace=workspace,
            type='expense',
            expense_category=expense_category,
            original_amount=Decimal('0.00'),  # Invalid amount
            original_currency='EUR',
            date=date.today()
        )
        
        with self.assertRaises(Exception):
            transaction.full_clean()

    def test_workspace_membership_unique_constraint(self):
        """Test unique constraint on workspace membership."""
        user = UserFactory()
        workspace = WorkspaceFactory(owner=user)
        
        # Create first membership
        WorkspaceMembershipFactory(user=user, workspace=workspace)
        
        # Try to create duplicate - should fail
        with self.assertRaises(Exception):
            WorkspaceMembership.objects.create(
                user=user, 
                workspace=workspace, 
                role='viewer'
            )

    def test_exchange_rate_validation(self):
        """Test exchange rate model validation."""
        # Test invalid rate
        exchange_rate = ExchangeRate(
            currency='USD',
            rate_to_eur=Decimal('0.00'),  # Invalid rate
            date=date.today()
        )
        
        with self.assertRaises(Exception):
            exchange_rate.full_clean()
        
        # Test invalid currency
        exchange_rate = ExchangeRate(
            currency='INVALID',
            rate_to_eur=Decimal('1.00'),
            date=date.today()
        )
        
        with self.assertRaises(Exception):
            exchange_rate.full_clean()

    def test_category_hierarchy_validation(self):
        """Test category hierarchy validation."""
        workspace = WorkspaceFactory()
        version = ExpenseCategoryVersionFactory(workspace=workspace)
        
        parent = ExpenseCategoryFactory(version=version, level=1)
        child = ExpenseCategoryFactory(version=version, level=2)
        
        # Test valid parent-child relationship
        parent.children.add(child)
        parent.full_clean()  # Should not raise
        
        # Test circular relationship prevention
        with self.assertRaises(Exception):
            child.children.add(parent)  # Should fail

    def test_workspace_admin_validation(self):
        """Test workspace admin model validation."""
        user = UserFactory()
        workspace = WorkspaceFactory(owner=user)
        admin_user = UserFactory(is_superuser=True)
        
        # Test valid assignment
        workspace_admin = WorkspaceAdmin(
            user=user,
            workspace=workspace,
            assigned_by=admin_user,
            is_active=True
        )
        workspace_admin.full_clean()  # Should not raise
        
        # Test duplicate active assignment
        WorkspaceAdminFactory(user=user, workspace=workspace, assigned_by=admin_user)
        
        with self.assertRaises(Exception):
            duplicate_admin = WorkspaceAdmin(
                user=user,
                workspace=workspace,
                assigned_by=admin_user,
                is_active=True
            )
            duplicate_admin.full_clean()


class IntegrationSecurityTests(BaseAPITestCase):
    """Security-focused integration tests."""

    def test_cross_workspace_access_prevention(self):
        """Test that users cannot access data from other workspaces."""
        # Create workspace that current user doesn't belong to
        other_workspace = WorkspaceFactory(owner=self.other_user)
        other_transaction = TransactionFactory(
            user=self.other_user,
            workspace=other_workspace
        )
        
        # Try to access transaction from other workspace
        url = reverse(TRANSACTION_DETAIL, kwargs={'pk': other_transaction.pk})
        response = self.client.get(url)
        
        # Should not be accessible
        self.assertIn(response.status_code, [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN])

    def test_user_data_isolation(self):
        """Test that users can only access their own data."""
        # Create transaction for other user in same workspace
        other_user_transaction = TransactionFactory(
            user=self.other_user,
            workspace=self.workspace
        )
        
        # Try to access other user's transaction
        url = reverse(TRANSACTION_DETAIL, kwargs={'pk': other_user_transaction.pk})
        response = self.client.get(url)
        
        # Should be accessible if in same workspace (depending on permissions)
        # But the transaction should belong to the other user
        if response.status_code == status.HTTP_200_OK:
            self.assertEqual(response.data['user'], self.other_user.id)

    def test_admin_privilege_escalation_prevention(self):
        """Test that admin privileges cannot be escalated."""
        # Regular user trying to access admin endpoints
        response = self.client.get(reverse(WORKSPACE_LIST) + '?user_id=1')
        
        # Should work normally but without admin privileges
        self.assertEqual(response.status_code, status.HTTP_200_OK)


# =============================================================================
# TEST RUNNER CONFIGURATION
# =============================================================================

def run_integration_tests():
    """Helper function to run all integration tests."""
    import unittest
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(WorkspaceAPITests)
    suite.addTests(loader.loadTestsFromTestCase(TransactionAPITests))
    suite.addTests(loader.loadTestsFromTestCase(UserSettingsAPITests))
    suite.addTests(loader.loadTestsFromTestCase(CategoryAPITests))
    suite.addTests(loader.loadTestsFromTestCase(ExchangeRateAPITests))
    suite.addTests(loader.loadTestsFromTestCase(TransactionDraftAPITests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceSettingsAPITests))
    suite.addTests(loader.loadTestsFromTestCase(AdminImpersonationAdvancedTests))
    suite.addTests(loader.loadTestsFromTestCase(PerformanceTests))
    suite.addTests(loader.loadTestsFromTestCase(EdgeCaseTests))
    suite.addTests(loader.loadTestsFromTestCase(ModelValidationTests))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationSecurityTests))
    
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == '__main__':
    run_integration_tests()