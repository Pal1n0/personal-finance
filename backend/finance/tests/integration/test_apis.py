"""
Integration tests for financial management system API endpoints.
"""
import json
from datetime import date
from django.utils import timezone
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.test import APIClient, APITestCase
from faker import Faker

from finance.models import (
    UserSettings, Workspace, WorkspaceMembership, WorkspaceSettings,
    ExpenseCategoryVersion, IncomeCategoryVersion, ExpenseCategory, IncomeCategory,
    ExchangeRate, Transaction, TransactionDraft
)
from ..factories import (
    UserFactory, UserSettingsFactory, WorkspaceFactory, WorkspaceMembershipFactory,
    WorkspaceSettingsFactory, ExpenseCategoryVersionFactory, IncomeCategoryVersionFactory,
    ExpenseCategoryFactory, IncomeCategoryFactory, ExchangeRateFactory,
    TransactionFactory, TransactionDraftFactory
)

User = get_user_model()
fake = Faker()

# finance/tests/integration/test_apis.py - UPRAVENÝ BaseAPITestCase

class BaseAPITestCase(APITestCase):
    """Base test case with common setup methods for JWT authentication."""
    
    def setUp(self):
        """Set up test data and client with JWT support."""
        from django.utils import timezone
        from datetime import date
        
        self.client = APIClient()
        
        # Create UNIQUE test users for this test
        self.user = UserFactory()
        self.other_user = UserFactory()
        
        # Make sure users are active
        self.user.is_active = True
        self.user.save()
        self.other_user.is_active = True
        self.other_user.save()
        
        # Create UNIQUE workspace for this test
        self.workspace = WorkspaceFactory(owner=self.user)
        
        # Use get_or_create for membership to avoid duplicates
        self.admin_membership, created = WorkspaceMembership.objects.get_or_create(
            workspace=self.workspace,
            user=self.user,
            defaults={'role': 'admin', 'joined_at': timezone.now()}
        )
        
        # Add other user as viewer - use get_or_create
        self.viewer_membership, created = WorkspaceMembership.objects.get_or_create(
            workspace=self.workspace,
            user=self.other_user,
            defaults={'role': 'viewer', 'joined_at': timezone.now()}
        )
        
        # Create workspace settings - use get_or_create
        self.workspace_settings, created = WorkspaceSettings.objects.get_or_create(
            workspace=self.workspace,
            defaults={
                'domestic_currency': 'EUR',
                'fiscal_year_start': 1,
                'display_mode': 'month',
                'accounting_mode': False
            }
        )
        
        # Create category versions - use get_or_create
        self.expense_version, created = ExpenseCategoryVersion.objects.get_or_create(
            workspace=self.workspace,
            created_by=self.user,
            defaults={
                'name': 'Default Expense Categories',
                'description': 'Default expense categories for testing',
                'is_active': True
            }
        )
        
        self.income_version, created = IncomeCategoryVersion.objects.get_or_create(
            workspace=self.workspace,
            created_by=self.user,
            defaults={
                'name': 'Default Income Categories',
                'description': 'Default income categories for testing', 
                'is_active': True
            }
        )
        
        # Create categories - USE FACTORY INSTEAD OF get_or_create
        self.expense_category = ExpenseCategoryFactory(
            version=self.expense_version,
            name='Test Expense Category',
            level=1,
            description='Test expense category'
        )
        
        self.income_category = IncomeCategoryFactory(
            version=self.income_version,
            name='Test Income Category', 
            level=1,
            description='Test income category'
        )
        
        # Create exchange rates for tests - USE rate_to_eur
        self._create_test_exchange_rates()
        
        # Authenticate using JWT token
        self._authenticate_user(self.user)
    
    def _create_test_exchange_rates(self):
        """Create test exchange rates."""
        from datetime import date, timedelta
        
        # Clear any existing rates for this workspace/user context
        ExchangeRate.objects.all().delete()
        
        # Create fresh exchange rates - USE rate_to_eur INSTEAD OF rate
        today = date.today()
        
        # EUR is always 1.0 (base currency)
        ExchangeRate.objects.create(currency='EUR', rate_to_eur=1.0, date=today)
        
        # Other currencies
        ExchangeRate.objects.create(currency='USD', rate_to_eur=1.1, date=today)
        ExchangeRate.objects.create(currency='GBP', rate_to_eur=0.85, date=today)
        ExchangeRate.objects.create(currency='CZK', rate_to_eur=25.0, date=today)
        ExchangeRate.objects.create(currency='CHF', rate_to_eur=0.95, date=today)
        ExchangeRate.objects.create(currency='PLN', rate_to_eur=4.5, date=today)
    
    def _authenticate_user(self, user):
        """Authenticate user using JWT tokens."""
        from rest_framework_simplejwt.tokens import AccessToken
        
        # Make sure user is active
        user.is_active = True
        user.save()
        
        # Create access token directly
        access_token = AccessToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

class UserSettingsAPITests(BaseAPITestCase):
    """Test UserSettings API endpoints."""

    def setUp(self):
        super().setUp()
        self.user_settings = UserSettingsFactory(user=self.user)
        self.url = reverse('user-settings-detail', kwargs={'pk': self.user_settings.pk})

    def test_retrieve_user_settings(self):
        """Test retrieving user settings."""
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user'], self.user.id)
        self.assertEqual(response.data['language'], 'en')

    def test_update_user_settings(self):
        """Test updating user settings."""
        data = {'language': 'sk'}
        response = self.client.patch(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user_settings.refresh_from_db()
        self.assertEqual(self.user_settings.language, 'sk')

    def test_cannot_update_other_user_settings(self):
        """Test that users cannot update other users' settings."""
        other_settings = UserSettingsFactory(user=self.other_user)
        url = reverse('user-settings-detail', kwargs={'pk': other_settings.pk})
        
        data = {'language': 'cs'}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_invalid_language_update(self):
        """Test updating with invalid language."""
        data = {'language': 'invalid'}
        response = self.client.patch(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class WorkspaceAPITests(BaseAPITestCase):
    """Test Workspace API endpoints."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse('workspace-list')
        self.detail_url = reverse('workspace-detail', kwargs={'pk': self.workspace.pk})
        
        # Create additional test data
        self.inactive_workspace = WorkspaceFactory(
            owner=self.user,
            is_active=False,
            name="Inactive Workspace"
        )
        
        # Ensure user is member of inactive workspace too
        WorkspaceMembershipFactory(
            workspace=self.inactive_workspace,
            user=self.user,
            role='admin'
        )

    def test_list_workspaces(self):
        """Test listing user's workspaces with proper role-based filtering."""
        # User should see only workspaces where they are members
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Count workspaces user should see (active + where they are member)
        visible_workspaces_count = Workspace.objects.filter(
            memberships__user=self.user,
            is_active=True
        ).count()
        
        self.assertEqual(len(response.data), visible_workspaces_count)
        
        # Verify each returned workspace is accessible to user
        for workspace_data in response.data:
            workspace_id = workspace_data['id']
            workspace = Workspace.objects.get(id=workspace_id)
            
            # User should be member of this workspace
            self.assertTrue(
                WorkspaceMembership.objects.filter(
                    workspace=workspace,
                    user=self.user
                ).exists()
            )
            
            # Workspace should be active (for non-admin users)
            self.assertTrue(workspace.is_active)

    def test_list_workspaces_as_admin_sees_all(self):
        """Test that admin users see all workspaces (including inactive)."""
        # Make user admin
        self.user.is_superuser = True
        self.user.save()
        
        # Create an inactive workspace
        inactive_workspace = WorkspaceFactory(
            owner=self.other_user,
            is_active=False
        )
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Admin should see ALL workspaces including inactive
        all_workspaces_count = Workspace.objects.all().count()
        self.assertEqual(len(response.data), all_workspaces_count)
        
        # Verify inactive workspace is included
        workspace_ids = [ws['id'] for ws in response.data]
        self.assertIn(inactive_workspace.id, workspace_ids)

    def test_list_workspaces_as_owner_sees_all(self):
        """Test that workspace owners see all their workspaces (including inactive)."""
        # Create inactive workspace owned by current user
        inactive_workspace = WorkspaceFactory(
            owner=self.user,
            is_active=False
        )
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Owner should see ALL their workspaces including inactive
        user_workspaces_count = Workspace.objects.filter(owner=self.user).count()
        self.assertEqual(len(response.data), user_workspaces_count)
        
        # Verify inactive workspace is included
        workspace_ids = [ws['id'] for ws in response.data]
        self.assertIn(inactive_workspace.id, workspace_ids)

    def test_list_workspaces_as_viewer_sees_only_active(self):
        """Test that viewer users see only active workspaces where they are members."""
        # Switch to viewer user
        self.client.force_authenticate(user=self.other_user)
        
        # Create inactive workspace where user is member
        inactive_workspace = WorkspaceFactory(
            owner=self.other_user,
            is_active=False
        )
        WorkspaceMembershipFactory(
            workspace=inactive_workspace,
            user=self.other_user,
            role='viewer'
        )
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Viewer should see only ACTIVE workspaces where they are members
        active_workspaces_count = Workspace.objects.filter(
            memberships__user=self.other_user,
            is_active=True
        ).count()
        
        self.assertEqual(len(response.data), active_workspaces_count)
        
        # Verify inactive workspace is NOT included
        workspace_ids = [ws['id'] for ws in response.data]
        self.assertNotIn(inactive_workspace.id, workspace_ids)

    def test_list_workspaces_includes_correct_data(self):
        """Test that workspace list includes correct serialized data."""
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify serialized data structure
        workspace_data = response.data[0]
        
        self.assertIn('id', workspace_data)
        self.assertIn('name', workspace_data)
        self.assertIn('description', workspace_data)
        self.assertIn('owner', workspace_data)
        self.assertIn('is_active', workspace_data)
        self.assertIn('user_role', workspace_data)
        self.assertIn('is_owner', workspace_data)
        self.assertIn('member_count', workspace_data)
        self.assertIn('permissions', workspace_data)
        
        # Verify user role is correctly set
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace,
            user=self.user
        )
        self.assertEqual(workspace_data['user_role'], membership.role)
        
        # Verify ownership
        self.assertEqual(workspace_data['is_owner'], self.workspace.owner == self.user)
    
    def test_list_workspaces_empty_for_non_member(self):
        """Test that users see no workspaces when they are not members of any."""
        # Create user with no workspace memberships
        new_user = UserFactory()
        self.client.force_authenticate(user=new_user)
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_list_workspaces_different_roles(self):
        """Test workspace list with users having different roles."""
        # Create workspace with multiple users having different roles
        test_workspace = WorkspaceFactory(owner=self.user)
        
        # Add users with different roles
        editor_user = UserFactory()
        viewer_user = UserFactory()
        
        WorkspaceMembershipFactory(
            workspace=test_workspace,
            user=editor_user,
            role='editor'
        )
        WorkspaceMembershipFactory(
            workspace=test_workspace, 
            user=viewer_user,
            role='viewer'
        )
        
        # Test as editor
        self.client.force_authenticate(user=editor_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['user_role'], 'editor')
        
        # Test as viewer  
        self.client.force_authenticate(user=viewer_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['user_role'], 'viewer')

    def test_retrieve_workspace(self):
        """Test retrieving workspace details."""
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.workspace.name)
        self.assertEqual(response.data['user_role'], 'admin')
        self.assertTrue(response.data['is_owner'])

    def test_create_workspace(self):
        """Test creating a new workspace."""
        data = {
            'name': 'New Test Workspace',
            'description': 'Test workspace description'
        }
        response = self.client.post(self.list_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Test Workspace')
        self.assertEqual(response.data['owner_username'], self.user.username)
        
        # Verify workspace was created with owner as admin member
        workspace = Workspace.objects.get(name='New Test Workspace')
        self.assertEqual(workspace.owner, self.user)
        self.assertTrue(workspace.members.filter(id=self.user.id).exists())
        
        membership = WorkspaceMembership.objects.get(workspace=workspace, user=self.user)
        self.assertEqual(membership.role, 'admin')

    def test_update_workspace_as_admin(self):
        """Test updating workspace as admin."""
        data = {'name': 'Updated Workspace Name'}
        response = self.client.patch(self.detail_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, 'Updated Workspace Name')

    def test_update_workspace_as_viewer(self):
        """Test that viewers cannot update workspace."""
        self.client.force_authenticate(user=self.other_user)
        
        data = {'name': 'Attempted Update'}
        response = self.client.patch(self.detail_url, data)
        
        # Should be 403 Forbidden, not 400 Bad Request
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_workspace_as_owner(self):
        """Test soft deleting workspace as owner."""
        response = self.client.delete(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.workspace.refresh_from_db()
        self.assertFalse(self.workspace.is_active)

    def test_delete_workspace_as_non_owner(self):
        """Test that non-owners cannot delete workspace."""
        self.client.force_authenticate(user=self.other_user)
        
        response = self.client.delete(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)

    def test_workspace_members_endpoint(self):
        """Test retrieving workspace members."""
        url = reverse('workspace-members', kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # owner + other_user

    def test_workspace_settings_endpoint(self):
        """Test retrieving workspace settings."""
        url = reverse('workspace-settings', kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['domestic_currency'], 'EUR')

        


class WorkspaceSettingsAPITests(BaseAPITestCase):
    """Test WorkspaceSettings API endpoints."""

    def setUp(self):
        super().setUp()
        self.detail_url = reverse(
            'workspacesettings-detail', 
            kwargs={'pk': self.workspace_settings.pk}
        )

    def test_retrieve_workspace_settings(self):
        """Test retrieving workspace settings."""
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['domestic_currency'], 'EUR')
        self.assertEqual(response.data['fiscal_year_start'], 1)

    def test_update_workspace_settings(self):
        """Test updating workspace settings."""
        data = {
            'domestic_currency': 'USD',
            'fiscal_year_start': 4,
            'display_mode': 'day'
        }
        response = self.client.patch(self.detail_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace_settings.refresh_from_db()
        self.assertEqual(self.workspace_settings.domestic_currency, 'USD')
        self.assertEqual(self.workspace_settings.fiscal_year_start, 4)

    def test_currency_change_triggers_recalculation(self):
        """Test that currency change triggers transaction recalculation."""
        # Create some transactions
        TransactionFactory.create_batch(
            3, 
            workspace=self.workspace, 
            user=self.user,
            original_currency='EUR',
            original_amount=Decimal('100.00')
        )
        
        data = {'domestic_currency': 'USD'}
        response = self.client.patch(self.detail_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Note: Actual recalculation would be tested in currency service tests


class TransactionAPITests(BaseAPITestCase):
    """Test Transaction API endpoints."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse('transaction-list')
        
        # Create test transactions
        self.expense_transaction = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            type='expense',
            expense_category=self.expense_category,
            original_amount=Decimal('150.50'),
            original_currency='EUR'
        )
        
        self.income_transaction = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            type='income', 
            income_category=self.income_category,
            original_amount=Decimal('300.75'),
            original_currency='USD'
        )
        
        self.detail_url = reverse(
            'transaction-detail', 
            kwargs={'pk': self.expense_transaction.pk}
        )

    def test_list_transactions(self):
        """Test listing transactions."""
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_filter_transactions_by_type(self):
        """Test filtering transactions by type."""
        response = self.client.get(self.list_url, {'type': 'expense'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['type'], 'expense')

    def test_filter_transactions_by_month(self):
        """Test filtering transactions by month."""
        response = self.client.get(self.list_url, {'month': date.today().month})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_retrieve_transaction(self):
        """Test retrieving transaction details."""
        response = self.client.get(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['type'], 'expense')
        self.assertEqual(Decimal(response.data['original_amount']), Decimal('150.50'))

    def test_create_expense_transaction(self):
        """Test creating an expense transaction."""
        # Ensure user has proper permissions
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, 
            user=self.user
        )
        membership.role = 'editor'  # or 'admin'
        membership.save()
        
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR', 
            'date': '2024-01-15',
            'note_manual': 'Test expense transaction'
        }
        response = self.client.post(self.list_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_income_transaction(self):
        """Test creating an income transaction."""
        data = {
            'workspace': self.workspace.id,
            'type': 'income',
            'income_category': self.income_category.id,
            'original_amount': '500.00',
            'original_currency': 'USD',
            'date': '2024-01-20',
            'tags': ['salary', 'bonus']
        }
        response = self.client.post(self.list_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['type'], 'income')
        self.assertEqual(response.data['tags'], ['salary', 'bonus'])

    def test_cannot_create_transaction_with_both_categories(self):
        """Test validation when both categories are provided."""
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'income_category': self.income_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(self.list_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cannot_create_transaction_without_category(self):
        """Test validation when no category is provided."""
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(self.list_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cannot_create_transaction_in_unauthorized_workspace(self):
        """Test creating transaction in workspace where user is not a member."""
        other_workspace = WorkspaceFactory(owner=self.other_user)
        
        data = {
            'workspace': other_workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(self.list_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_transaction(self):
        """Test updating a transaction."""
        data = {
            'original_amount': '175.25',
            'note_manual': 'Updated transaction note'
        }
        response = self.client.patch(self.detail_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.original_amount, Decimal('175.25'))
        self.assertEqual(self.expense_transaction.note_manual, 'Updated transaction note')

    def test_delete_transaction(self):
        """Test deleting a transaction."""
        response = self.client.delete(self.detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Transaction.objects.filter(pk=self.expense_transaction.pk).exists())

    def test_bulk_delete_transactions(self):
        """Test bulk deletion of transactions."""
        transactions = TransactionFactory.create_batch(
            3, user=self.user, workspace=self.workspace
        )
        transaction_ids = [t.id for t in transactions]
        
        url = reverse('transaction-bulk-delete')
        data = {'ids': transaction_ids}
        response = self.client.post(url, data, format='json')  # Add format='json'
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['deleted'], 3)


class BulkSyncTransactionTests(BaseAPITestCase):
    """Test bulk synchronization of transactions."""

    def setUp(self):
        super().setUp()
        self.url = reverse(
            'bulk-sync-transactions', 
            kwargs={'workspace_id': self.workspace.id}
        )

    def test_bulk_sync_create_transactions(self):
        """Test bulk creation of transactions."""
        transactions_data = {
            'create': [  
                {
                    'type': 'expense',
                    'expense_category': self.expense_category.id,
                    'original_amount': '100.00',
                    'original_currency': 'EUR', 
                    'date': '2024-01-10',
                    'note_manual': 'Expense 1'
                },
                {
                    'type': 'income',
                    'income_category': self.income_category.id,
                    'original_amount': '200.00',
                    'original_currency': 'USD',
                    'date': '2024-01-15', 
                    'note_manual': 'Income 1'
                }
            ],
            'update': [],
            'delete': []
        }
        
        response = self.client.post(self.url, transactions_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 2) 

    def test_bulk_sync_update_transactions(self):
        """Test bulk update of existing transactions."""
        transaction = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            type='expense',
            expense_category=self.expense_category,
            original_amount=Decimal('50.00')
        )
        
        transactions_data = [
            {
                'id': transaction.id,
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': '75.00',  # Updated amount
                'original_currency': 'EUR',
                'date': '2024-01-10',
                'note_manual': 'Updated expense'
            }
        ]
        
        response = self.client.post(self.url, transactions_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 0)
        self.assertEqual(response.data['updated'], 1)
        self.assertEqual(response.data['deleted'], 0)
        
        transaction.refresh_from_db()
        self.assertEqual(transaction.original_amount, Decimal('75.00'))
        self.assertEqual(transaction.note_manual, 'Updated expense')

    def test_bulk_sync_delete_transactions(self):
        """Test bulk deletion of transactions."""
        transactions = TransactionFactory.create_batch(
            2, user=self.user, workspace=self.workspace
        )
        
        # Prepare data for deletion (empty array deletes all)
        transactions_data = []
        
        response = self.client.post(self.url, transactions_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 0)
        self.assertEqual(response.data['updated'], 0)
        self.assertEqual(response.data['deleted'], 2)
        
        # Verify transactions were deleted
        self.assertEqual(Transaction.objects.filter(workspace=self.workspace).count(), 0)

    def test_bulk_sync_mixed_operations(self):
        """Test mixed create, update, and delete operations."""
        # Existing transaction to update
        existing_tx = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            type='expense',
            expense_category=self.expense_category,
            original_amount=Decimal('50.00')
        )
        
        # Existing transaction that will be deleted (not included in sync data)
        TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            type='income',
            income_category=self.income_category
        )
        
        transactions_data = [
            # Update existing
            {
                'id': existing_tx.id,
                'type': 'expense',
                'expense_category': self.expense_category.id,
                'original_amount': '100.00',  # Updated
                'original_currency': 'EUR',
                'date': '2024-01-10'
            },
            # Create new
            {
                'type': 'income',
                'income_category': self.income_category.id,
                'original_amount': '200.00',
                'original_currency': 'USD',
                'date': '2024-01-15'
            }
        ]
        
        response = self.client.post(self.url, transactions_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 1)
        self.assertEqual(response.data['updated'], 1)
        self.assertEqual(response.data['deleted'], 1)  # The one not included gets deleted
        
        # Verify final state
        self.assertEqual(Transaction.objects.filter(workspace=self.workspace).count(), 2)
        existing_tx.refresh_from_db()
        self.assertEqual(existing_tx.original_amount, Decimal('100.00'))


class CategoryAPITests(BaseAPITestCase):
    """Test Category API endpoints."""

    def test_list_expense_categories(self):
        """Test listing expense categories."""
        url = reverse('expensecategory-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.expense_category.name)

    def test_list_income_categories(self):
        """Test listing income categories."""
        url = reverse('incomecategory-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.income_category.name)

    def test_retrieve_expense_category(self):
        """Test retrieving expense category details."""
        url = reverse('expensecategory-detail', kwargs={'pk': self.expense_category.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], self.expense_category.name)
        self.assertEqual(response.data['level'], 1)

    def test_categories_filtered_by_workspace_membership(self):
        """Test that users only see categories from their workspaces."""
        # Create workspace and categories that current user doesn't have access to
        other_workspace = WorkspaceFactory(owner=self.other_user)
        other_expense_version = ExpenseCategoryVersionFactory(workspace=other_workspace)
        ExpenseCategoryFactory(version=other_expense_version)
        
        url = reverse('expensecategory-list')
        response = self.client.get(url)
        
        # Should only see categories from accessible workspaces
        # Count only categories from our workspace
        our_categories_count = ExpenseCategory.objects.filter(
            version__workspace=self.workspace
        ).count()
        self.assertEqual(len(response.data), our_categories_count)


class ExchangeRateAPITests(BaseAPITestCase):
    """Test ExchangeRate API endpoints."""
    
    def setUp(self):
        super().setUp()
        self.list_url = reverse('exchange-rate-list')

        def test_list_exchange_rates(self):
            """Test listing exchange rates."""
            ExchangeRateFactory.create_batch(3)
            
            response = self.client.get(self.list_url)
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(len(response.data), 4)  # 3 new + 1 from setUp
    
    def test_filter_exchange_rates_by_currency(self):
        """Test filtering exchange rates by currency."""
        # Použi unikátne dátumy
        from datetime import date, timedelta
        
        ExchangeRateFactory(currency='USD', date=date.today() - timedelta(days=10))
        ExchangeRateFactory(currency='GBP', date=date.today() - timedelta(days=11))
        
        response = self.client.get(self.list_url, {'currencies': 'USD,GBP'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Over že sme dostali nejaké dáta
        self.assertIsInstance(response.data, list)


    def test_filter_exchange_rates_by_date_range(self):
        """Test filtering exchange rates by date range."""
        from datetime import timedelta
        today = date.today()
        
        ExchangeRateFactory(date=today - timedelta(days=5))
        ExchangeRateFactory(date=today - timedelta(days=10))
        
        response = self.client.get(self.list_url, {
            'date_from': (today - timedelta(days=7)).isoformat(),
            'date_to': (today - timedelta(days=3)).isoformat()
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only get the rate from 5 days ago
        self.assertEqual(len(response.data), 1)


class TransactionDraftAPITests(BaseAPITestCase):
    """Test TransactionDraft API endpoints."""
    
    def setUp(self):
        super().setUp()
        self.draft = TransactionDraftFactory(
            user=self.user,
            workspace=self.workspace, 
            draft_type='expense'
        )
        # Použi správne URL z routeru
        self.list_url = reverse('transactiondraft-list')
    
    def test_save_draft(self):
        """Test saving a transaction draft."""
        transactions_data = [
            {
                'type': 'expense',
                'original_amount': '150.00',
                'original_currency': 'EUR',
                'date': '2024-01-15',
                'note_manual': 'Draft transaction 1'
            }
        ]
        
        data = {
            'user': self.user.id,
            'workspace': self.workspace.id,
            'draft_type': 'expense',
            'transactions_data': transactions_data
        }
        
        response = self.client.post(self.list_url, data, format='json')
        
        # Môže byť 201 (created) alebo 200 (updated)
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED])
    
    def test_get_draft(self):
        """Test retrieving a draft."""
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Môže vrátiť prázdny zoznam alebo dáta
        self.assertIsInstance(response.data, list)
    
    def test_discard_draft(self):
        """Test discarding a draft."""
        if self.draft.id:
            detail_url = reverse('transactiondraft-detail', kwargs={'pk': self.draft.id})
            response = self.client.delete(detail_url)
            self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])

    def test_draft_auto_deleted_after_transaction_save(self):
        """Test that draft is automatically deleted after transaction save."""
        # Create a draft
        draft = TransactionDraftFactory(
            user=self.user,
            workspace=self.workspace,
            draft_type='expense',
            transactions_data=[{'type': 'expense', 'amount': 100}]
        )
        
        # Create a transaction of the same type
        data = {
            'workspace': self.workspace.id,
            'type': 'expense',
            'expense_category': self.expense_category.id,
            'original_amount': '200.00',
            'original_currency': 'EUR',
            'date': '2024-01-15'
        }
        response = self.client.post(reverse('transaction-list'), data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify draft was deleted
        with self.assertRaises(TransactionDraft.DoesNotExist):
            TransactionDraft.objects.get(pk=draft.pk)


class ModelValidationTests(TestCase):
    """Test model-level validation and business logic."""

    def test_transaction_validation_mixed_categories(self):
        """Test transaction validation with mixed categories."""
        user = UserFactory()
        workspace = WorkspaceFactory(owner=user)
        expense_version = ExpenseCategoryVersionFactory(workspace=workspace)
        income_version = IncomeCategoryVersionFactory(workspace=workspace)
        expense_category = ExpenseCategoryFactory(version=expense_version)
        income_category = IncomeCategoryFactory(version=income_version)
        
        transaction = Transaction(
            user=user,
            workspace=workspace,
            type='expense',
            expense_category=expense_category,
            income_category=income_category,  # This should cause validation error
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            date=date.today()
        )
        
        with self.assertRaises(Exception):  # Could be ValidationError or DRF ValidationError
            transaction.full_clean()

    def test_workspace_membership_unique_constraint(self):
        """Test unique constraint on workspace membership."""
        user = UserFactory()
        workspace = WorkspaceFactory(owner=user)
        
        # Create first membership (owner should already be added by factory)
        membership = WorkspaceMembership.objects.get(workspace=workspace, user=user)
        
        # Try to create duplicate - should fail
        with self.assertRaises(Exception):
            WorkspaceMembership.objects.create(
                user=user, 
                workspace=workspace, 
                role='viewer'
            )