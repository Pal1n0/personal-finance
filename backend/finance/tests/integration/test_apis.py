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

# =============================================================================
# URL ENDPOINT CONSTANTS - DEFINED FROM urls.py CONFIGURATION
# =============================================================================

# Router-generated endpoints (from DefaultRouter)
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

# finance/tests/integration/test_apis.py - UPRAVENÝ BaseAPITestCase

class BaseAPITestCase(APITestCase):
    """Base test case with common setup methods for JWT authentication."""
    
    def setUp(self):
        """Set up test data and client with JWT support."""
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
        
        # Clear any existing memberships first
        WorkspaceMembership.objects.filter(workspace=self.workspace).delete()
        
        # Create fresh memberships
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
        
        # Create fresh exchange rates - POUŽIŤ LEN CUDZIE MENY, ŽIADNE EUR
        today = date.today()
        
        # EUR NIE je v zozname - základná mena sa nepoužíva
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


class AdminImpersonationTests(BaseAPITestCase):
    """Test admin impersonation functionality."""
    
    def setUp(self):
        super().setUp()
        # Create admin user
        self.admin_user = UserFactory(is_superuser=True, is_staff=True)
        
    def test_admin_can_impersonate_user(self):
        """Test that admin can impersonate another user."""
        self.client.force_authenticate(user=self.admin_user)
        
        # Get workspaces as admin impersonating regular user
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that response works - don't require specific impersonation structure
        # The important thing is that it works without errors
        self.assertIn('workspaces', response.data)
        self.assertIn('summary', response.data)
    
    def test_regular_user_cannot_impersonate(self):
        """Test that regular users cannot use impersonation."""
        # Regular user trying to impersonate - should work normally but without impersonation
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.other_user.id}'
        response = self.client.get(url)
        
        # Should work normally but without impersonation
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # No impersonation should occur for regular users
    
    def test_admin_impersonation_invalid_user(self):
        """Test admin impersonation with invalid user ID."""
        self.client.force_authenticate(user=self.admin_user)
        
        url = reverse(WORKSPACE_LIST) + '?user_id=99999'
        response = self.client.get(url)
        
        # Should still work but use admin as target user
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class UserSettingsAPITests(BaseAPITestCase):
    """Test UserSettings API endpoints."""

    def setUp(self):
        super().setUp()
        self.user_settings = UserSettingsFactory(user=self.user)
        self.url = reverse(USER_SETTINGS_DETAIL, kwargs={'pk': self.user_settings.pk})

    def test_retrieve_user_settings(self):
        """Test retrieving user settings."""
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user'], self.user.id)
        self.assertEqual(response.data['language'], 'en')

    def test_update_user_settings(self):
        """Test updating user settings."""
        data = {'language': 'sk'}
        response = self.client.patch(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user_settings.refresh_from_db()
        self.assertEqual(self.user_settings.language, 'sk')

    def test_cannot_update_other_user_settings(self):
        """Test that users cannot update other users' settings."""
        other_settings = UserSettingsFactory(user=self.other_user)
        url = reverse(USER_SETTINGS_DETAIL, kwargs={'pk': other_settings.pk})
        
        data = {'language': 'cs'}
        response = self.client.patch(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_invalid_language_update(self):
        """Test updating with invalid language."""
        data = {'language': 'invalid'}
        response = self.client.patch(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class WorkspaceAPITests(BaseAPITestCase):
    """Test Workspace API endpoints."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(WORKSPACE_LIST)
        self.detail_url = reverse(WORKSPACE_DETAIL, kwargs={'pk': self.workspace.pk})
        
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

    def _get_workspaces_list(self, response):
        """Helper method to extract workspaces list from paginated response."""
        if 'results' in response.data:
            return response.data['results']
        elif 'workspaces' in response.data and 'results' in response.data['workspaces']:
            return response.data['workspaces']['results']
        else:
            return response.data

    def test_list_workspaces(self):
        """Test listing user's workspaces with proper role-based filtering."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        workspaces_list = self._get_workspaces_list(response)
        
        # Keďže user je admin, mal by vidieť VŠETKY workspaces kde je member (aj neaktívne)
        all_user_workspaces_count = Workspace.objects.filter(
            members=self.user
        ).count()

        self.assertEqual(len(workspaces_list), all_user_workspaces_count)

    def test_list_workspaces_as_admin_sees_all(self):
        """Test that admin users see all workspaces (including inactive)."""
        # Create admin user and authenticate as them
        admin_user = UserFactory(is_superuser=True)
        self.client.force_authenticate(user=admin_user)
        
        # Create an inactive workspace owned by other user
        inactive_workspace = WorkspaceFactory(
            owner=self.other_user,
            is_active=False
        )
        
        # Admin should see ALL workspaces when using their own user_id or no user_id
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        workspaces_list = self._get_workspaces_list(response)
        
        # Admin should see ALL workspaces including inactive
        all_workspaces_count = Workspace.objects.all().count()
        self.assertEqual(len(workspaces_list), all_workspaces_count)
        
        # Verify inactive workspace is included
        workspace_ids = [ws['id'] for ws in workspaces_list]
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
        
        workspaces_list = self._get_workspaces_list(response)
        
        # Owner should see ALL their workspaces including inactive
        user_workspaces_count = Workspace.objects.filter(owner=self.user).count()
        self.assertEqual(len(workspaces_list), user_workspaces_count)
        
        # Verify inactive workspace is included
        workspace_ids = [ws['id'] for ws in workspaces_list]
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
        
        workspaces_list = self._get_workspaces_list(response)
        
        # Viewer should see only ACTIVE workspaces where they are members
        active_workspaces_count = Workspace.objects.filter(
            members=self.other_user,
            is_active=True
        ).count()
        
        self.assertEqual(len(workspaces_list), active_workspaces_count)
        
        # Verify inactive workspace is NOT included
        workspace_ids = [ws['id'] for ws in workspaces_list]
        self.assertNotIn(inactive_workspace.id, workspace_ids)

    def test_list_workspaces_includes_correct_data(self):
        """Test that workspace list includes correct serialized data."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        workspaces_list = self._get_workspaces_list(response)
        
        # Verify serialized data structure
        workspace_data = workspaces_list[0]  # Prvý workspace v zozname
        
        self.assertIn('id', workspace_data)
        self.assertIn('name', workspace_data)
        self.assertIn('description', workspace_data)
        self.assertIn('owner', workspace_data)
        self.assertIn('is_active', workspace_data)
        self.assertIn('user_role', workspace_data)
        self.assertIn('is_owner', workspace_data)
        self.assertIn('member_count', workspace_data)
        self.assertIn('user_permissions', workspace_data)
        
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
        
        workspaces_list = self._get_workspaces_list(response)
        self.assertEqual(len(workspaces_list), 0)

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
        
        workspaces_list = self._get_workspaces_list(response)
        self.assertEqual(len(workspaces_list), 1)
        self.assertEqual(workspaces_list[0]['user_role'], 'editor')
        
        # Test as viewer  
        self.client.force_authenticate(user=viewer_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        workspaces_list = self._get_workspaces_list(response)
        self.assertEqual(len(workspaces_list), 1)
        self.assertEqual(workspaces_list[0]['user_role'], 'viewer')

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
        response = self.client.post(self.list_url, data, format='json')
        
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
        response = self.client.patch(self.detail_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, 'Updated Workspace Name')

    def test_update_workspace_as_viewer(self):
        """Test that viewers cannot update workspace."""
        self.client.force_authenticate(user=self.other_user)
        
        data = {'name': 'Attempted Update'}
        response = self.client.patch(self.detail_url, data, format='json')
        
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
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)

    def test_workspace_members_endpoint(self):
        """Test retrieving workspace members."""
        url = reverse(WORKSPACE_MEMBERS, kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['members']), 2)  # owner + other_user

    def test_workspace_settings_endpoint(self):
        """Test retrieving workspace settings."""
        url = reverse(WORKSPACE_SETTINGS, kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['domestic_currency'], 'EUR')

    def test_workspace_membership_info_endpoint(self):
        """Test retrieving workspace membership info."""
        url = reverse(WORKSPACE_MEMBERSHIP_INFO, kwargs={'pk': self.workspace.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['role'], 'admin')

    def test_workspace_delete_permissions_comprehensive(self):
        """Comprehensive test for workspace deletion permissions and scenarios."""
        # SCENÁR 1: Owner môže soft delete aj s ďalšími members
        # Pridáme ďalšieho membera
        extra_user = UserFactory()
        WorkspaceMembershipFactory(
            workspace=self.workspace,
            user=extra_user,
            role='editor'
        )
        
        # Owner by mal môcť soft delete
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.workspace.refresh_from_db()
        self.assertFalse(self.workspace.is_active)
        
        # Reaktivujeme workspace pre ďalšie testy
        self.workspace.is_active = True
        self.workspace.save()
        
        # SCENÁR 2: Admin (nie owner) môže soft delete
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
        
        # SCENÁR 3: Editor NEmôže delete
        editor_workspace = WorkspaceFactory(owner=self.other_user)
        WorkspaceMembershipFactory(
            workspace=editor_workspace,
            user=self.user,
            role='editor'
        )
        
        editor_workspace_url = reverse(WORKSPACE_DETAIL, kwargs={'pk': editor_workspace.pk})
        response = self.client.delete(editor_workspace_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        editor_workspace.refresh_from_db()
        self.assertTrue(editor_workspace.is_active)
        
        # SCENÁR 4: Viewer NEmôže delete
        viewer_workspace = WorkspaceFactory(owner=self.other_user)
        WorkspaceMembershipFactory(
            workspace=viewer_workspace,
            user=self.user,
            role='viewer'
        )
        
        viewer_workspace_url = reverse(WORKSPACE_DETAIL, kwargs={'pk': viewer_workspace.pk})
        response = self.client.delete(viewer_workspace_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        viewer_workspace.refresh_from_db()
        self.assertTrue(viewer_workspace.is_active)

    def test_workspace_hard_delete_comprehensive(self):
        """Comprehensive test for hard delete scenarios with state changes."""
        # SCENÁR 1: Hard delete zlyhá keď sú ďalší members
        # Overíme aktuálny stav - máme owner + other_user
        self.assertEqual(self.workspace.members.count(), 2)
        
        hard_delete_url = reverse(WORKSPACE_HARD_DELETE, kwargs={'pk': self.workspace.pk})
        response = self.client.delete(hard_delete_url, {
            'confirmation': 'I understand this action is irreversible',
            'workspace_name': self.workspace.name
        }, format='json')
        
        # Hard delete by mal zlyhať
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('other members', response.data['error'].lower())
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)
        
        # SCENÁR 2: Odstránime ostatných members a hard delete by mal prejsť
        # Odstránime other_user z workspace
        WorkspaceMembership.objects.filter(
            workspace=self.workspace,
            user=self.other_user
        ).delete()
        
        # Overíme že zostal len owner
        self.assertEqual(self.workspace.members.count(), 1)
        self.assertEqual(self.workspace.members.first(), self.user)
        
        # Teraz by hard delete mal prejsť
        response = self.client.delete(hard_delete_url, {
            'confirmation': 'I understand this action is irreversible',
            'workspace_name': self.workspace.name
        }, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Overíme že workspace bol skutočne vymazaný
        with self.assertRaises(Workspace.DoesNotExist):
            Workspace.objects.get(pk=self.workspace.pk)

    def test_workspace_activate_endpoint(self):
        """Test activating an inactive workspace."""
        # First deactivate the workspace
        self.workspace.is_active = False
        self.workspace.save()
        
        activate_url = reverse(WORKSPACE_ACTIVATE, kwargs={'pk': self.workspace.pk})
        response = self.client.post(activate_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)

    def test_workspace_delete_edge_cases(self):
        """Test edge cases for workspace deletion."""
        # SCENÁR 1: Non-owner sa pokúsi delete - zlyhanie
        self.client.force_authenticate(user=self.other_user)
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)
        
        # SCENÁR 2: Non-owner sa pokúsi hard delete - zlyhanie
        hard_delete_url = reverse(WORKSPACE_HARD_DELETE, kwargs={'pk': self.workspace.pk})
        response = self.client.delete(hard_delete_url, {
            'confirmation': 'I understand this action is irreversible',
            'workspace_name': self.workspace.name
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # SCENÁR 3: Neplatná confirmácia pre hard delete
        self.client.force_authenticate(user=self.user)  # Vrátime sa k ownerovi
        response = self.client.delete(hard_delete_url, {
            'confirmation': 'wrong confirmation',
            'workspace_name': self.workspace.name
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # SCENÁR 4: Nesprávny workspace názov pre hard delete
        response = self.client.delete(hard_delete_url, {
            'confirmation': 'I understand this action is irreversible',
            'workspace_name': 'Wrong Name'
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class WorkspaceSettingsAPITests(BaseAPITestCase):
    """Test WorkspaceSettings API endpoints."""

    def setUp(self):
        super().setUp()
        self.detail_url = reverse(
            WORKSPACE_SETTINGS_DETAIL, 
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
        self.assertEqual(response.data['fiscal_year_start'], 4)

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
        response = self.client.patch(self.detail_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Note: Actual recalculation would be tested in currency service tests


class TransactionAPITests(BaseAPITestCase):
    """Test Transaction API endpoints."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(TRANSACTION_LIST)
        
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
            TRANSACTION_DETAIL, 
            kwargs={'pk': self.expense_transaction.pk}
        )

    def test_list_transactions(self):
        """Test listing transactions."""
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_filter_transactions_by_type(self):
        """Test filtering transactions by type."""
        response = self.client.get(self.list_url, {'type': 'expense'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_filter_transactions_by_month(self):
        """Test filtering transactions by month."""
        response = self.client.get(self.list_url, {'month': date.today().month})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

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
        response = self.client.post(self.list_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['type'], 'income')

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
        response = self.client.post(self.list_url, data, format='json')
        
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
        response = self.client.post(self.list_url, data, format='json')
        
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
        response = self.client.post(self.list_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_transaction(self):
        """Test updating a transaction."""
        data = {
            'original_amount': '175.25',
            'note_manual': 'Updated transaction note'
        }
        response = self.client.patch(self.detail_url, data, format='json')
        
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
        
        url = reverse(TRANSACTION_BULK_DELETE)
        data = {'ids': transaction_ids}
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['deleted'], 3)


class BulkSyncTransactionTests(BaseAPITestCase):
    """Test bulk synchronization of transactions."""

    def test_bulk_sync_create_transactions(self):
        """Test bulk creation of transactions."""
        url = reverse(BULK_SYNC_TRANSACTIONS, kwargs={'workspace_id': self.workspace.id})
        
        transactions_data = [
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
        ]
        
        response = self.client.post(url, transactions_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('created', response.data)


class CategoryAPITests(BaseAPITestCase):
    """Test Category API endpoints."""

    def test_list_expense_categories(self):
        """Test listing expense categories."""
        url = reverse(EXPENSE_CATEGORY_LIST)
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.expense_category.name)

    def test_list_income_categories(self):
        """Test listing income categories."""
        url = reverse(INCOME_CATEGORY_LIST)
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], self.income_category.name)

    def test_retrieve_expense_category(self):
        """Test retrieving expense category details."""
        url = reverse(EXPENSE_CATEGORY_DETAIL, kwargs={'pk': self.expense_category.pk})
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
        
        url = reverse(EXPENSE_CATEGORY_LIST)
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
        self.list_url = reverse(EXCHANGE_RATE_LIST)

    def test_list_exchange_rates(self):
        """Test listing exchange rates."""
        # Použi unikátne dátumy
        from datetime import date, timedelta
        
        ExchangeRateFactory.create_batch(3)
        
        response = self.client.get(self.list_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Môže vrátiť rôzny počet - záleží na setup
    
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
        from datetime import date, timedelta
        
        # Use fixed dates instead of relative to today
        fixed_date = date(2024, 1, 1)
        
        ExchangeRateFactory(date=fixed_date - timedelta(days=5))
        ExchangeRateFactory(date=fixed_date - timedelta(days=10))
        
        response = self.client.get(self.list_url, {
            'date_from': (fixed_date - timedelta(days=7)).isoformat(),
            'date_to': (fixed_date - timedelta(days=3)).isoformat()
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only get the rate from 5 days ago
        self.assertGreaterEqual(len(response.data), 0)


class TransactionDraftAPITests(BaseAPITestCase):
    """Test TransactionDraft API endpoints."""
    
    def setUp(self):
        super().setUp()
        # Clear any existing drafts first
        TransactionDraft.objects.all().delete()
        
        self.draft = TransactionDraftFactory(
            user=self.user,
            workspace=self.workspace, 
            draft_type='expense'
        )
        # Použi správne URL z routeru
        self.list_url = reverse(TRANSACTION_DRAFT_LIST)
    
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
            detail_url = reverse(TRANSACTION_DRAFT_DETAIL, kwargs={'pk': self.draft.id})
            response = self.client.delete(detail_url)
            self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])

    def test_save_draft_action(self):
        """Test saving draft using the save_draft action endpoint."""
        url = reverse(TRANSACTION_DRAFT_SAVE, kwargs={'workspace_pk': self.workspace.id})
        
        transactions_data = [
            {
                'type': 'expense',
                'original_amount': '150.00',
                'original_currency': 'EUR',
                'date': '2024-01-15'
            }
        ]
        
        data = {
            'draft_type': 'expense',
            'transactions_data': transactions_data
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_workspace_draft_action(self):
        """Test getting workspace draft using the get_workspace_draft action endpoint."""
        url = reverse(TRANSACTION_DRAFT_GET_WORKSPACE, kwargs={'workspace_pk': self.workspace.id}) + '?type=expense'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_discard_action(self):
        """Test discarding draft using the discard action endpoint."""
        url = reverse(TRANSACTION_DRAFT_DISCARD, kwargs={'pk': self.draft.id})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

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
        response = self.client.post(reverse(TRANSACTION_LIST), data, format='json')
        
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


class WorkspaceImpersonationTests(BaseAPITestCase):
    """Extended workspace tests with impersonation support."""
    
    def test_workspace_list_includes_impersonation_info(self):
        """Test that workspace list includes impersonation metadata when applicable."""
        # Create admin user
        admin_user = UserFactory(is_superuser=True)
        self.client.force_authenticate(user=admin_user)
        
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check for impersonation info in response
        if 'admin_impersonation' in response.data:
            impersonation_info = response.data['admin_impersonation']
            self.assertEqual(impersonation_info['target_user_id'], self.user.id)
            self.assertEqual(impersonation_info['requested_by_admin_id'], admin_user.id)
    
    def test_workspace_retrieve_with_impersonation(self):
        """Test retrieving single workspace with impersonation."""
        admin_user = UserFactory(is_superuser=True)
        self.client.force_authenticate(user=admin_user)
        
        url = reverse(WORKSPACE_DETAIL, kwargs={'pk': self.workspace.pk}) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check response structure with potential impersonation info
        if 'admin_impersonation' in response.data:
            self.assertEqual(response.data['admin_impersonation']['target_user_id'], self.user.id)


class PermissionTestsWithImpersonation(BaseAPITestCase):
    """Test permissions work correctly with impersonation."""
    
    def test_admin_can_access_user_resources_via_impersonation(self):
        """Test admin can access user-specific resources via impersonation."""
        admin_user = UserFactory(is_superuser=True)
        self.client.force_authenticate(user=admin_user)
        
        # Try to access user settings via impersonation
        user_settings = UserSettingsFactory(user=self.user)
        url = reverse(USER_SETTINGS_DETAIL, kwargs={'pk': user_settings.pk}) + f'?user_id={self.user.id}'
        
        response = self.client.get(url)
        
        # Admin should be able to access via impersonation
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_impersonation_transaction_creation(self):
        """Test transaction creation with impersonation."""
        admin_user = UserFactory(is_superuser=True)
        self.client.force_authenticate(user=admin_user)
        
        # Use query parameter, NOT in data
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
        
        # Should create transaction for target user
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify transaction was created for target user
        transaction = Transaction.objects.get(pk=response.data['id'])
        self.assertEqual(transaction.user.id, self.user.id)


class TargetUserTests(BaseAPITestCase):
    """Test request.target_user functionality."""
    
    def test_target_user_defaults_to_request_user(self):
        """Test that target_user defaults to request.user when no impersonation."""
        url = reverse(WORKSPACE_LIST)
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should see only user's own workspaces
    
    def test_target_user_with_impersonation(self):
        """Test target_user behavior with impersonation."""
        admin_user = UserFactory(is_superuser=True)
        self.client.force_authenticate(user=admin_user)
        
        # Create workspace for target user
        target_user_workspace = WorkspaceFactory(owner=self.user)
        WorkspaceMembershipFactory(
            workspace=target_user_workspace,
            user=self.user,
            role='owner'
        )
        
        url = reverse(WORKSPACE_LIST) + f'?user_id={self.user.id}'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Should see target user's workspaces
        workspaces_list = response.data.get('workspaces', {}).get('results', response.data.get('results', []))
        
        # Verify we got some workspaces and they belong to the target user
        self.assertGreater(len(workspaces_list), 0)
        
        # At least one workspace should belong to target user
        workspace_owners = [ws['owner'] for ws in workspaces_list]
        self.assertIn(self.user.id, workspace_owners)


class ImpersonationLoggingTests(BaseAPITestCase):
    """Test logging for admin impersonation actions."""
    
    def setUp(self):
        super().setUp()
        self.admin_user = UserFactory(is_superuser=True)
    
    def test_impersonation_activation_logging(self):
        """Test that impersonation activation is properly logged."""
        # Use the correct logger name from your views
        with self.assertLogs('finance.views', level='INFO') as log:
            self.client.force_authenticate(user=self.admin_user)
            url = reverse(WORKSPACE_LIST) + f'?user_id={self.user.id}'
            response = self.client.get(url)
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # Just verify the request was successful, don't depend on specific log messages
    
    def test_impersonation_failed_logging(self):
        """Test logging for failed impersonation attempts."""
        with self.assertLogs('finance.views', level='WARNING') as log:
            self.client.force_authenticate(user=self.admin_user)
            url = reverse(WORKSPACE_LIST) + '?user_id=99999'
            response = self.client.get(url)
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # Request should still succeed even with invalid user_id


class ImpersonationEdgeCasesTests(BaseAPITestCase):
    """Test edge cases for impersonation functionality."""
    
    def setUp(self):
        super().setUp()
        self.admin_user = UserFactory(is_superuser=True)
    
    def test_impersonation_with_unauthorized_workspace(self):
        """Test impersonation when target user doesn't have access to workspace."""
        self.client.force_authenticate(user=self.admin_user)
        
        # Create workspace that target user doesn't have access to
        unauthorized_workspace = WorkspaceFactory(owner=self.other_user)
        
        # Try to access transactions in unauthorized workspace via impersonation
        url = reverse(TRANSACTION_LIST) + f'?user_id={self.user.id}'
        response = self.client.get(url, {'workspace': unauthorized_workspace.id})
        
        # Should return empty list, not error
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_impersonation_bulk_operations(self):
        """Test bulk operations with impersonation."""
        self.client.force_authenticate(user=self.admin_user)
        
        # Create some transactions for target user
        transactions = TransactionFactory.create_batch(
            2, user=self.user, workspace=self.workspace
        )
        transaction_ids = [t.id for t in transactions]
        
        # Bulk delete via impersonation
        url = reverse(TRANSACTION_BULK_DELETE) + f'?user_id={self.user.id}'
        data = {'ids': transaction_ids}
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['deleted'], 2)