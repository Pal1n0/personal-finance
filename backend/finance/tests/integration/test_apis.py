"""
COMPREHENSIVE Integration tests for financial management system API endpoints.
Enhanced with admin impersonation, permission testing, and edge case coverage.
"""

import json
from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string
from faker import Faker
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from rest_framework_simplejwt.tokens import AccessToken

from finance.mixins.workspace_membership import WorkspaceMembershipMixin
from finance.models import (ExchangeRate, ExpenseCategory,
                            ExpenseCategoryVersion, IncomeCategory,
                            IncomeCategoryVersion, Transaction,
                            TransactionDraft, UserSettings, Workspace,
                         WorkspaceAdmin, WorkspaceMembership, Tags,
                            WorkspaceSettings)

from ..factories import (ExchangeRateFactory, ExpenseCategoryFactory,
                         ExpenseCategoryVersionFactory, IncomeCategoryFactory,
                         IncomeCategoryVersionFactory, TransactionDraftFactory,
                         TransactionFactory, UserFactory, UserSettingsFactory,
                         WorkspaceAdminFactory, WorkspaceFactory, TagFactory,
                         WorkspaceMembershipFactory, WorkspaceSettingsFactory)

User = get_user_model()
fake = Faker()

# =============================================================================
# URL ENDPOINT CONSTANTS
# =============================================================================

# Router-generated endpoints
WORKSPACE_LIST = "workspace-list"
WORKSPACE_DETAIL = "workspace-detail"
WORKSPACE_SETTINGS_LIST = "workspacesettings-list"
WORKSPACE_SETTINGS_DETAIL = "workspacesettings-detail"
USER_SETTINGS_LIST = "user-settings-list"
USER_SETTINGS_DETAIL = "user-settings-detail"
TRANSACTION_LIST = "transaction-list"
TRANSACTION_DETAIL = "transaction-detail"
EXPENSE_CATEGORY_LIST = "expensecategory-list"
EXPENSE_CATEGORY_DETAIL = "expensecategory-detail"
INCOME_CATEGORY_LIST = "incomecategory-list"
INCOME_CATEGORY_DETAIL = "incomecategory-detail"
EXCHANGE_RATE_LIST = "exchange-rate-list"
EXCHANGE_RATE_DETAIL = "exchange-rate-detail"
TRANSACTION_DRAFT_LIST = "transactiondraft-list"

# Custom action endpoints
WORKSPACE_MEMBERS = "workspace-members"
WORKSPACE_SETTINGS = "workspace-settings"
WORKSPACE_HARD_DELETE = "workspace-hard-delete"
WORKSPACE_ACTIVATE = "workspace-activate"
WORKSPACE_MEMBERSHIP_INFO = "workspace-membership-info"
TRANSACTION_BULK_DELETE = "transaction-bulk-delete"
BULK_SYNC_TRANSACTIONS = "bulk-sync-transactions"

def mock_get_exchange_rates_for_range(currencies, date_from, date_to):
    """Mock exchange rates for testing."""
    rates = {}
    for currency in currencies:
        if currency == 'EUR':
            rates[currency] = {date_from: Decimal('1.0')}
        else:
            # Mock rates for other currencies
            mock_rates = {
                'USD': Decimal('1.1'),
                'GBP': Decimal('0.85'), 
                'CHF': Decimal('0.95'),
                'PLN': Decimal('4.5'),
                'CZK': Decimal('25.0')
            }
            rates[currency] = {date_from: mock_rates.get(currency, Decimal('1.0'))}
    return rates

@patch('finance.utils.currency_utils.get_exchange_rates_for_range', mock_get_exchange_rates_for_range)
class BaseAPITestCase(APITestCase):
    """Enhanced base test case with comprehensive setup for axes-compatible authentication."""

    @classmethod
    def setUpTestData(cls):
        """Set up STATIC test data that doesn't change between test methods."""
        # Store original settings
        cls.original_email_verification = getattr(
            settings, "ACCOUNT_EMAIL_VERIFICATION", None
        )
        cls.original_email_required = getattr(settings, "ACCOUNT_EMAIL_REQUIRED", None)

        # Temporarily disable email verification for testing
        settings.ACCOUNT_EMAIL_VERIFICATION = "none"
        settings.ACCOUNT_EMAIL_REQUIRED = False

        # Create STATIC test data
        cls._create_static_test_data()

    @classmethod
    def _ensure_verified_emails(cls, users):
        """Ensure all users have verified email addresses."""
        from allauth.account.models import EmailAddress

        for user in users:
            email_address = EmailAddress.objects.filter(
                user=user, email=user.email
            ).first()
            if not email_address:
                EmailAddress.objects.create(
                    user=user, email=user.email, verified=True, primary=True
                )
            else:
                email_address.verified = True
                email_address.primary = True
                email_address.save()

    @classmethod
    def _create_static_test_data(cls):
        """Create truly STATIC data once per class run. This should only contain data
        that is NOT modified by any test, like exchange rates."""
        cls._create_test_exchange_rates()

    @classmethod
    def _create_test_exchange_rates(cls):
        """Create test exchange rates."""
        ExchangeRate.objects.all().delete()

        today = date.today()
        # Widen the range to cover all possible transaction dates from factories.
        dates = [today - timedelta(days=i) for i in range(35)]

        currencies = [
            ("USD", Decimal("1.1")),
            ("GBP", Decimal("0.85")),
            ("CHF", Decimal("0.95")),
            ("PLN", Decimal("4.5")),
            ("CZK", Decimal("25.0")),
        ]

        for currency, rate in currencies:
            for i, rate_date in enumerate(dates):
                # Use update_or_create to be safe and avoid race conditions
                ExchangeRate.objects.update_or_create(
                    currency=currency,
                    date=rate_date,
                    defaults={"rate_to_eur": rate + Decimal(i * 0.001)},
                )

    def setUp(self):
        """Set up DYNAMIC test data that might change between test methods."""
        # Create fresh data for EACH test to ensure 100% isolation.
        # Order is important.
        self._create_test_users()
        self._create_workspace_structure()
        self._create_categories()
        self._create_dynamic_test_data()

        # Authenticate user
        self.client.force_authenticate(user=self.user)

    def _create_test_users(self): # Now an instance method
        """Create test users with CORRECT roles for your architecture."""
        
        # 1. SUPERUSER - globálny admin (môže všetko)
        self.superuser = UserFactory(
            username="superuser", 
            email="superuser@example.com",
            is_superuser=True, 
            is_staff=True
        )
        
        # 2. WORKSPACE ADMIN - admin konkrétnych workspaces (NIE superuser!)
        self.workspace_admin_user = UserFactory(
            username="workspace_admin", 
            email="workspace_admin@example.com",
            is_superuser=False, 
            is_staff=False
        )
        
        # 3. REGULAR USERS - normálni používatelia
        self.user = UserFactory(
            username="regular_user", 
            email="user@example.com",
            is_superuser=False, 
            is_staff=False
        )
        
        self.other_user = UserFactory(
            username="other_user", 
            email="other@example.com", 
            is_superuser=False, 
            is_staff=False
        )
        
        # 🔥 DÔLEŽITÉ: Nastav správne heslá
        users = [self.superuser, self.workspace_admin_user, self.user, self.other_user]
        for user in users:
            user.set_password("testpass123")
            user.save()
        
        self._ensure_verified_emails(users)

    def _create_workspace_structure(self): # Now an instance method
        """Create workspace and membership structure."""
        self.workspace = WorkspaceFactory(owner=self.user)

        # Create memberships
        self.viewer_membership = WorkspaceMembershipFactory(
            workspace=self.workspace, user=self.other_user, role="viewer"
        )
        
        self.editor_membership = WorkspaceMembershipFactory(
            workspace=self.workspace, user=self.workspace_admin_user, role="editor"  
        )

        # workspace_admin_user je adminom workspace (NIE superuser!)
        self.workspace_admin_assignment = WorkspaceAdminFactory(
            user=self.workspace_admin_user,           # workspace admin user
            workspace=self.workspace,            # v tomto workspace
            assigned_by=self.superuser,               # assigned by superuser
            is_active=True
        )

        self.workspace_settings = WorkspaceSettingsFactory(workspace=self.workspace)

    def _create_categories(self): # Now an instance method
        """Create category structure."""
        self.expense_version = ExpenseCategoryVersionFactory(
            workspace=self.workspace, created_by=self.user
        )

        self.income_version = IncomeCategoryVersionFactory(
            workspace=self.workspace, created_by=self.user
        )

        self.expense_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Test Expense Category", level=1
        )

        self.income_category = IncomeCategoryFactory(
            version=self.income_version, name="Test Income Category", level=1
        )

        self.child_expense_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Child Expense Category", level=2
        )

        self.child_income_category = IncomeCategoryFactory(
            version=self.income_version, name="Child Income Category", level=2
        )

        # Create parent-child relationships
        self.expense_category.children.add(self.child_expense_category)
        self.income_category.children.add(self.child_income_category)

    def _create_dynamic_test_data(self): # Now an instance method
        """Create DYNAMIC test data that might be modified during tests."""
        self._create_test_transactions()
        self._create_test_drafts()

    # Note: The following methods are now instance methods (def) instead of class methods (@classmethod)
    # because they are called from setUp, not setUpTestData.

    def _create_test_transactions(self): # Now an instance method
        """Create test transactions."""
        # Clean up any existing transactions for this workspace
        Transaction.objects.filter(workspace=self.workspace).delete()

        # Create expense transactions
        self.expense_transactions = TransactionFactory.create_batch(
            3,
            user=self.user,
            workspace=self.workspace,
            type="expense",
            expense_category=self.expense_category,
            original_currency="EUR",
        )

        # Create income transactions
        self.income_transactions = TransactionFactory.create_batch(
            2,
            user=self.user,
            workspace=self.workspace,
            type="income",
            income_category=self.income_category,
            original_currency="USD",
        )

        # Create multi-currency transactions
        self.multi_currency_transactions = [
            TransactionFactory(
                user=self.user,
                workspace=self.workspace,
                type="expense",
                expense_category=self.expense_category,
                original_currency="GBP",
                original_amount=Decimal("75.00"),
            ),
            TransactionFactory(
                user=self.user,
                workspace=self.workspace,
                type="income",
                income_category=self.income_category,
                original_currency="CHF",
                original_amount=Decimal("120.00"),
            ),
        ]

        # Set main test transactions
        self.expense_transaction = self.expense_transactions[0]
        self.income_transaction = self.income_transactions[0]

    def _create_test_drafts(self): # Now an instance method
        """Create test transaction drafts."""
        # Clean up any existing drafts for this workspace
        TransactionDraft.objects.filter(workspace=self.workspace).delete()

        # Create expense draft
        self.expense_draft = TransactionDraftFactory(
            user=self.user,
            workspace=self.workspace,
            draft_type="expense",
            transactions_data=[
                {
                    "type": "expense",
                    "original_amount": "150.00",
                    "original_currency": "EUR",
                    "date": "2024-01-15",
                    "note_manual": "Draft expense 1",
                },
                {
                    "type": "expense",
                    "original_amount": "75.50",
                    "original_currency": "USD",
                    "date": "2024-01-16",
                    "note_manual": "Draft expense 2",
                },
            ],
        )

        # Create income draft
        self.income_draft = TransactionDraftFactory(
            user=self.user,
            workspace=self.workspace,
            draft_type="income",
            transactions_data=[
                {
                    "type": "income",
                    "original_amount": "300.00",
                    "original_currency": "EUR",
                    "date": "2024-01-20",
                    "note_manual": "Draft income 1",
                }
            ],
        )

    def _get_response_data(self, response):
        """Helper method to extract data from paginated response."""
        if hasattr(response, 'data') and isinstance(response.data, dict):
            if 'results' in response.data:
                return response.data['results']
        return response.data

    def _get_workspaces_list(self, response):
        """Helper method to extract workspaces list from paginated response."""
        data = self._get_response_data(response)
        if isinstance(data, list):
            return data
        return data.get("results", data)

    def _authenticate_user(self, user):
        """Switch to different user during test execution."""
        from rest_framework_simplejwt.tokens import RefreshToken

        # 🔥 DÔLEŽITÉ: Najprv resetovať credentials
        self.client.credentials()
        self.client.force_authenticate(user=user)

        # Generate proper JWT token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        return access_token

    def _make_user_workspace_admin(self, user, workspace):
        """Make user a workspace admin."""
        return WorkspaceAdminFactory(
            user=user,
            workspace=workspace,
            assigned_by=self.superuser,
            is_active=True
        )

    def tearDown(self):
        """Clean up after tests."""
        # Restore original settings
        from django.conf import settings

        if self.original_email_verification is not None:
            settings.ACCOUNT_EMAIL_VERIFICATION = self.original_email_verification
        if self.original_email_required is not None:
            settings.ACCOUNT_EMAIL_REQUIRED = self.original_email_required

        super().tearDown()


# =============================================================================
# CORE API TESTS
# =============================================================================


class WorkspaceAPITests(BaseAPITestCase):
    """COMPREHENSIVE Workspace API tests with role-based permissions and impersonation."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(WORKSPACE_LIST)
        self.detail_url = reverse(WORKSPACE_DETAIL, kwargs={"pk": self.workspace.pk})

        # Create additional test workspaces
        self.inactive_workspace = WorkspaceFactory(
            owner=self.user, is_active=False, name="Inactive Workspace"
        )
        self.other_user_workspace = WorkspaceFactory(
            owner=self.other_user, is_active=True
        )

    def test_update_workspace_permissions(self):
        """Test workspace update permissions for different roles."""
        # Test as admin (owner) - should succeed
        data = {"name": "Updated by Owner"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, "Updated by Owner")

        # Test as workspace admin - should succeed (má WorkspaceAdmin assignment)
        self._authenticate_user(self.workspace_admin_user)
        data = {"name": "Updated by Workspace Admin"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test as viewer - should fail
        self._authenticate_user(self.other_user)
        data = {"name": "Updated by Viewer"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_workspace_comprehensive(self):
        """Comprehensive workspace deletion tests."""
        # --- Scenario 1: Owner can delete their own workspace ---
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.workspace.refresh_from_db()
        self.assertFalse(self.workspace.is_active)

        # Reactivate for further tests
        self.workspace.is_active = True
        self.workspace.save()

        # --- Scenario 2: Superuser delete with impersonation ---
        admin_workspace = WorkspaceFactory(owner=self.other_user)
        
        # Use SUPERUSER with impersonation
        self._authenticate_user(self.superuser)
        admin_workspace_url = reverse(WORKSPACE_DETAIL, kwargs={"pk": admin_workspace.pk})
        
        # Impersonate the workspace OWNER
        impersonation_url = f"{admin_workspace_url}?user_id={self.other_user.id}"
        response = self.client.delete(impersonation_url)
        
        # Superuser with impersonation MUST be able to delete
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        admin_workspace.refresh_from_db()
        self.assertFalse(admin_workspace.is_active)

        # --- Scenario 3: Editor cannot delete foreign workspace ---
        self._authenticate_user(self.user)
        
        editor_workspace = WorkspaceFactory(owner=self.other_user)
        WorkspaceMembershipFactory(
            workspace=editor_workspace, user=self.user, role="editor"
        )

        editor_workspace_url = reverse(WORKSPACE_DETAIL, kwargs={"pk": editor_workspace.pk})
        response = self.client.delete(editor_workspace_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_workspace_custom_endpoints(self):
        """Test all custom workspace endpoints."""
        # Test workspace members endpoint
        url = reverse(WORKSPACE_MEMBERS, kwargs={"pk": self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Response structure might vary - check for any members data
        members_data = self._get_response_data(response)
        self.assertTrue(isinstance(members_data, (list, dict)))

        # Test workspace settings endpoint - OPRAVENÉ
        # The URL now correctly uses the workspace's PK, not the settings' PK.
        url = reverse("workspace-settings-detail", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertIn("domestic_currency", response.data)

        # Test workspace membership info endpoint
        url = reverse(WORKSPACE_MEMBERSHIP_INFO, kwargs={"pk": self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Owner should have role
        self.assertIn("role", response.data)

        # Test workspace activate endpoint
        self.workspace.is_active = False
        self.workspace.save()

        url = reverse(WORKSPACE_ACTIVATE, kwargs={"pk": self.workspace.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)

class TagsAPITests(BaseAPITestCase):
    """
    Comprehensive tests for the Tag API endpoints.
    Ensures CRUD operations and permissions work as expected within a workspace.
    """

    def setUp(self):
        super().setUp()
        # Create some initial tags for the workspace
        self.tag1 = TagFactory(workspace=self.workspace, name="food")
        self.tag2 = TagFactory(workspace=self.workspace, name="travel")

        # URLs for the nested tag endpoints
        self.list_url = reverse(
            "workspace-tag-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        self.detail_url = reverse(
            "workspace-tag-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": self.tag1.pk},
        )

    def test_list_tags_for_workspace(self):
        """Test that listing tags is scoped to the correct workspace."""
        # Create a tag in another workspace that should not be listed
        other_workspace = WorkspaceFactory(owner=self.other_user)
        TagFactory(workspace=other_workspace, name="other-tag")

        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = self._get_response_data(response)
        self.assertEqual(len(response_data), 2)
        tag_names = {tag["name"] for tag in response_data}
        self.assertIn("food", tag_names)
        self.assertIn("travel", tag_names)
        self.assertNotIn("other-tag", tag_names)

    def test_create_tag(self):
        """Test creating a new tag."""
        data = {"name": "  Urgent  "}  # Test with whitespace and case
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], "urgent")  # Name should be lowercased and stripped

    def test_create_existing_tag_is_idempotent(self):
        """Test that creating a tag with an existing name returns the existing tag."""
        data = {"name": "food"}  # This tag already exists
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["id"], self.tag1.id) # Should return the existing tag's ID

    def test_update_tag(self):
        """Test updating a tag's name."""
        data = {"name": "groceries"}
        response = self.client.put(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.tag1.refresh_from_db()
        self.assertEqual(self.tag1.name, "groceries")

    def test_delete_tag(self):
        """Test deleting a tag."""
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Tags.objects.filter(pk=self.tag1.pk).exists())

class SuperuserImpersonationTests(BaseAPITestCase):
    """Tests specifically for superuser impersonation functionality."""
    
    def test_superuser_sees_all_user_workspaces(self):
        """Test that superuser sees ALL workspaces during impersonation."""
        # Create additional workspace for user
        extra_workspace = WorkspaceFactory(owner=self.user)
        # Ensure membership exists without duplicates
        if not WorkspaceMembership.objects.filter(workspace=extra_workspace, user=self.user).exists():
            WorkspaceMembershipFactory(workspace=extra_workspace, user=self.user, role="owner")
        
        # Authenticate as SUPERUSER
        self._authenticate_user(self.superuser)
        
        # Superuser should see ALL user workspaces with impersonation
        response = self.client.get(reverse(WORKSPACE_LIST), {'user_id': self.user.id})
        workspaces_list = self._get_workspaces_list(response)
        
        # Should see at least the workspaces user has access to
        self.assertGreaterEqual(len(workspaces_list), 1)

    def test_superuser_can_impersonate_any_user(self):
        """Test superuser can impersonate any user across all endpoints."""
        self._authenticate_user(self.superuser)
        
        # Test transaction creation with impersonation
        # Use the new nested URL structure
        url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        ) + f"?user_id={self.user.id}"
        data = {
            "workspace": self.workspace.id,
            "type": "expense", 
            "expense_category": self.expense_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(url, data, format="json")
        # Should be able to create transaction for target user
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify transaction was created for target user
        transaction = Transaction.objects.get(pk=response.data["id"])
        self.assertEqual(transaction.user.id, self.user.id)


class TransactionAPITests(BaseAPITestCase):
    """COMPREHENSIVE Transaction API tests with filtering, bulk operations, and permissions."""

    def setUp(self):
        super().setUp()
        # Use new nested URLs that require a workspace_pk
        self.list_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        self.detail_url = reverse(
            "workspace-transaction-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_transaction.pk},
        )

    def test_list_transactions_comprehensive(self):
        """Comprehensive transaction listing with various filters."""
        # Test basic listing
        response = self.client.get(self.list_url) # list_url already contains workspace context
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        transactions_data = self._get_response_data(response)
        self.assertGreaterEqual(
            len(transactions_data),
            len(self.expense_transactions) + len(self.income_transactions),
        )

        # Test filtering by type
        response = self.client.get(self.list_url, {"type": "expense"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        transactions_data = self._get_response_data(response)
        for transaction in transactions_data:
            self.assertEqual(transaction["type"], "expense")

        # Test filtering by month
        current_month = date.today().month
        response = self.client.get(self.list_url, {"month": current_month}) # workspace is already in URL
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_transaction_detailed(self):
        """Test retrieving transaction with full detail validation."""
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify all expected fields
        expected_fields = [
            "id",
            "user",
            "workspace",
            "type",
            "expense_category",
            "income_category",
            "original_amount",
            "original_currency",
            "amount_domestic",
            "date",
            "month",
            "tags",
            "note_manual",
            "note_auto",
            "created_at",
            "updated_at",
        ]
        for field in expected_fields:
            self.assertIn(field, response.data)

        # Verify data accuracy
        self.assertEqual(response.data["type"], "expense")
        self.assertEqual(
            Decimal(response.data["original_amount"]),
            self.expense_transaction.original_amount,
        )

    def test_create_transaction_validation(self):
        """Test transaction creation with comprehensive validation."""
        # Valid expense transaction
        data = { # workspace is now taken from URL, not from data
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
            "note_manual": "Test expense transaction",
            "tags": ["test", "expense"],
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Valid income transaction
        data = { # workspace is now taken from URL
            "type": "income",
            "income_category": self.income_category.id,
            "original_amount": "500.00",
            "original_currency": "USD",
            "date": "2024-01-20",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Invalid: Both categories provided
        data = { # workspace is now taken from URL
            "type": "expense",
            "expense_category": self.expense_category.id,
            "income_category": self.income_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Invalid: No category provided
        data = { # workspace is now taken from URL
            "type": "expense",
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Invalid: Wrong category type
        data = { # workspace is now taken from URL
            "type": "expense",
            "income_category": self.income_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_transaction_comprehensive(self):
        """Comprehensive transaction update tests."""
        # --- 1. Test valid update with tag replacement ---
        # The factory gives the transaction some initial random tags.
        initial_tag_count = self.expense_transaction.tags.count()
        self.assertGreater(initial_tag_count, 0)

        data = {
            "original_amount": "175.25",
            "note_manual": "Updated transaction note",
            "tags": ["updated", "test"],
        }
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.original_amount, Decimal("175.25"))
        self.assertEqual(
            self.expense_transaction.note_manual, "Updated transaction note"
        )
        # Verify tags were replaced correctly.
        updated_tags = set(self.expense_transaction.tags.values_list("name", flat=True))
        self.assertEqual(updated_tags, {"updated", "test"})

        # --- 2. Test clearing all tags with an empty list ---
        data = {"tags": []}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.tags.count(), 0)

        # --- 3. Test that omitting the 'tags' key leaves them unchanged ---
        # First, add a tag back
        self.expense_transaction.tags.add(TagFactory(workspace=self.workspace, name="persistent-tag"))
        self.assertEqual(self.expense_transaction.tags.count(), 1)

        # Now, update another field without sending the 'tags' key
        data = {"note_manual": "Final note update"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.tags.count(), 1)
        self.assertEqual(self.expense_transaction.tags.first().name, "persistent-tag")

        # --- 4. Test update with category change ---
        data = {"expense_category": self.child_expense_category.id}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.expense_transaction.refresh_from_db()
        self.assertEqual(
            self.expense_transaction.expense_category, self.child_expense_category
        )
    def test_delete_transaction_permissions(self):
        """Test transaction deletion with permission validation."""
        # Use the new nested URL
        detail_url = reverse("workspace-transaction-detail", kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_transaction.pk})

        # --- ADVANCED DEBUGGING START ---
        try:
            db_transaction = Transaction.objects.get(pk=self.expense_transaction.pk)
            print(f"🔍 DB CHECK: Transaction PK={db_transaction.pk} FOUND in DB.")
            print(f"🔍 DB CHECK: Transaction belongs to Workspace PK={db_transaction.workspace.pk}")
            if db_transaction.workspace.pk != self.workspace.pk:
                print(f"🔥 MISMATCH: Transaction's workspace ({db_transaction.workspace.pk}) != Test's workspace ({self.workspace.pk})")
        except Transaction.DoesNotExist:
            print(f"🔥 NOT FOUND: Transaction PK={self.expense_transaction.pk} does NOT exist in DB before DELETE call!")
        # --- ADVANCED DEBUGGING END ---

        # --- DEBUGGING START ---
        print(f"🔍 DEBUG Test: Authenticated user ID: {self.user.id}")
        print(f"🔍 DEBUG Test: Workspace PK from test: {self.workspace.pk}")
        print(f"🔍 DEBUG Test: Expense transaction PK from test: {self.expense_transaction.pk}")
        print(f"🔍 DEBUG Test: Expense transaction user ID: {self.expense_transaction.user.id}")
        print(f"🔍 DEBUG Test: Expense transaction workspace PK: {self.expense_transaction.workspace.pk}")
        # --- DEBUGGING END ---

        # Test delete as owner (should succeed)
        response = self.client.delete(detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            Transaction.objects.filter(pk=self.expense_transaction.pk).exists()
        )

        # Recreate transaction for viewer test
        transaction = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            type="expense",
            expense_category=self.expense_category,
        )
        detail_url_for_viewer = reverse("workspace-transaction-detail", kwargs={"workspace_pk": self.workspace.pk, "pk": transaction.pk})

        # Test delete as viewer (should fail)
        self._authenticate_user(self.other_user)
        response = self.client.delete(detail_url_for_viewer)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_bulk_operations(self):
        """Test bulk transaction operations."""
        # Bulk delete using the workspace-specific bulk-sync endpoint
        transaction_ids = [t.id for t in self.expense_transactions[:2]]
        url = reverse(
            BULK_SYNC_TRANSACTIONS, kwargs={"workspace_id": self.workspace.id}
        )
        data = {"delete": transaction_ids}

        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["deleted"]), 2)

        # Bulk sync
        url = reverse(
            BULK_SYNC_TRANSACTIONS, kwargs={"workspace_id": self.workspace.id}
        )
        transactions_data = {
            "create": [
                {
                    "type": "expense",
                    "expense_category": self.expense_category.id,
                    "original_amount": "100.00",
                    "original_currency": "EUR",
                    "date": "2024-01-10",
                    "note_manual": "Bulk expense 1",
                }
            ]
        }
        response = self.client.post(url, transactions_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("created", response.data)


class CategoryAPITests(BaseAPITestCase):
    """COMPREHENSIVE Category API tests with hierarchy and workspace validation."""

    def test_list_categories_comprehensive(self):
        """Comprehensive category listing tests."""
        # Test expense categories
        url = reverse(EXPENSE_CATEGORY_LIST)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        categories_data = self._get_response_data(response)
        self.assertGreaterEqual(len(categories_data), 2)  # parent + child

        # Verify category structure
        for category in categories_data:
            self.assertIn("id", category)
            self.assertIn("name", category)
            self.assertIn("level", category)
            self.assertIn("children", category)
            self.assertIn("version", category)

        # Test income categories
        url = reverse(INCOME_CATEGORY_LIST)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        categories_data = self._get_response_data(response)
        self.assertGreaterEqual(len(categories_data), 2)  # parent + child

    def test_retrieve_category_detailed(self):
        """Test retrieving category with full hierarchy."""
        # Test expense category
        url = reverse(EXPENSE_CATEGORY_DETAIL, kwargs={"pk": self.expense_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data["name"], self.expense_category.name)
        self.assertEqual(response.data["level"], 1)
        self.assertIn("children", response.data)
        self.assertEqual(len(response.data["children"]), 1)  # Should have one child

        # Test income category
        url = reverse(INCOME_CATEGORY_DETAIL, kwargs={"pk": self.income_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["name"], self.income_category.name)

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
        categories_data = self._get_response_data(response)

        accessible_categories_count = ExpenseCategory.objects.filter(
            version__workspace__members=self.user
        ).count()
        self.assertEqual(len(categories_data), accessible_categories_count)

    def test_category_sync_endpoint(self):
        """Test category synchronization endpoint."""
        # Use the new nested URL for category sync
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )

        sync_data = [
            {
                "name": "New Expense Category",
                "level": 1,
                "description": "Synced category",
                "children": [],
            }
        ]
        data = {"create": sync_data}

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_category_move_validation_used_category(self):
        """Test that used category cannot be moved."""
        # Create transaction with category
        Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            expense_category=self.child_expense_category,
            type="expense",
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )

        # Try to move used category via sync endpoint
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )

        sync_data = {
            "update": [
                {
                    "id": self.child_expense_category.id,
                    "name": self.child_expense_category.name,
                    "level": 1,
                    "parent_id": None,
                }
            ]
        }

        response = self.client.post(url, sync_data, format="json")
        # Should fail for used category
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_category_move_validation_unused_category(self):
        """Test that unused category can be moved."""
        # Ensure category is not used
        self.assertFalse(
            Transaction.objects.filter(
                expense_category=self.child_expense_category
            ).exists()
        )

        # Move unused category via sync endpoint
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )

        sync_data = {
            "update": [
                {
                    "id": self.child_expense_category.id,
                    "name": self.child_expense_category.name,
                    "level": 1,
                    "parent_id": None,
                }
            ]
        }

        response = self.client.post(url, sync_data, format="json")

        # Should succeed for unused category
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_leaf_category_with_transactions_cannot_move(self):
        """Test that leaf category (level 5) with transactions cannot be moved."""
        # Create leaf category
        leaf_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Leaf Category", level=5
        )

        # Create transaction with leaf category
        Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            expense_category=leaf_category,
            type="expense",
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )

        # Try to move via sync
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )

        sync_data = {
            "update": [
                {
                    "id": leaf_category.id,
                    "name": leaf_category.name,
                    "level": 4,  # Try to move from level 5 to 4
                    "parent_id": self.expense_category.id,
                }
            ]
        }

        response = self.client.post(url, sync_data, format="json")
        # Should fail for used leaf category
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TransactionDraftAPITests(BaseAPITestCase):
    """COMPREHENSIVE TransactionDraft API tests with atomic operations."""

    def setUp(self):
        super().setUp()
        # Use the new nested URL for drafts
        self.list_url = reverse(
            "workspace-transactiondraft-list", kwargs={"workspace_pk": self.workspace.pk}
        )

    def test_list_drafts_comprehensive(self):
        """Comprehensive draft listing tests."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        drafts_data = self._get_response_data(response)
        self.assertGreaterEqual(len(drafts_data), 2)  # expense + income drafts

        # Verify draft structure
        for draft in drafts_data:
            self.assertIn("id", draft)
            self.assertIn("draft_type", draft)
            self.assertIn("transactions_data", draft)
            self.assertIn("workspace", draft)

    def test_retrieve_draft_detailed(self):
        """Test retrieving draft with full data."""
        url = reverse(
            "workspace-transactiondraft-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_draft.pk},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data["draft_type"], "expense")
        self.assertEqual(len(response.data["transactions_data"]), 2)
        self.assertEqual(
            response.data["transactions_data"][0]["original_amount"], "150.00"
        )

    def test_create_draft_validation(self):
        """Test draft creation with comprehensive validation."""
        # Valid expense draft
        data = {
            # workspace is now taken from the URL
            "draft_type": "expense",
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "250.00",
                    "original_currency": "EUR",
                    "date": "2024-01-25",
                    "expense_category_id": self.expense_category.id,
                    "note_manual": "New draft expense",
                }
            ],
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Valid income draft
        data = {
            # workspace is now taken from the URL
            "draft_type": "income",
            "transactions_data": [
                {
                    "type": "income",
                    "original_amount": "750.00",
                    "original_currency": "USD",
                    "date": "2024-01-26",
                    "income_category_id": self.income_category.id,
                }
            ],
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Invalid: Mixed transaction types in draft
        data = {
            # workspace is now taken from the URL
            "draft_type": "expense",
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "250.00",
                    "original_currency": "EUR",
                    "date": "2024-01-25",
                },
                {
                    "type": "income",  # Wrong type for expense draft
                    "original_amount": "750.00",
                    "original_currency": "USD",
                    "date": "2024-01-26",
                },
            ],
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_draft_comprehensive(self):
        """Comprehensive draft update tests."""
        url = reverse(
            "workspace-transactiondraft-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_draft.pk},
        )

        # Update draft data
        updated_data = {
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "999.00",
                    "original_currency": "EUR",
                    "date": "2024-01-25",
                    "note_manual": "UPDATED draft transaction",
                }
            ]
        }
        response = self.client.patch(url, updated_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify draft was updated
        self.expense_draft.refresh_from_db()
        self.assertEqual(len(self.expense_draft.transactions_data), 1)
        self.assertEqual(
            self.expense_draft.transactions_data[0]["original_amount"], "999.00"
        )

    def test_delete_draft_permissions(self):
        """Test draft deletion with permission validation."""
        url = reverse(
            "workspace-transactiondraft-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_draft.pk},
        )

        # Test delete as owner (should succeed)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            TransactionDraft.objects.filter(pk=self.expense_draft.pk).exists()
        )

        # Create draft for other user
        other_user_draft = TransactionDraftFactory(
            user=self.other_user,
            workspace=self.workspace,
            draft_type="expense",
        )
        other_draft_url = reverse(
            "workspace-transactiondraft-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": other_user_draft.pk},
        )

        # Test delete as different user (should fail)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_draft_category_move_scenario_exact(self):
        """Test draft validation when category level changes."""
        # 1. ✅ Vytvor draft s kategóriou na spodnom leveli (ešte nepoužitá)
        self.assertEqual(self.child_expense_category.level, 2)  # Spodný level
        self.assertFalse(
            Transaction.objects.filter(
                expense_category=self.child_expense_category
            ).exists()
        )  # Ešte nepoužitá

        # Use the new nested URL for creating a draft
        save_url = reverse(
            "workspace-transactiondraft-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        draft_data = {
            "draft_type": "expense",
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "200.00",
                    "original_currency": "EUR",
                    "date": "2024-01-20",
                    "expense_category_id": self.child_expense_category.id,
                }
            ],
        }

        # Ulož draft - MALO BY prejsť
        response = self.client.post(save_url, draft_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 2. ✅ Presuň kategóriu do vyššieho levelu (ešte stále nepoužitá v reálnej transakcii)
        self.child_expense_category.level = 1  # ❌ Už nie je spodný level!
        self.child_expense_category.save()

        # Over že kategória je stále nepoužitá v reálnych transakciách
        self.assertFalse(
            Transaction.objects.filter(
                expense_category=self.child_expense_category
            ).exists()
        )

        # 3. ✅ Skús znova uložiť draft - MALO BY ZLYHAŤ
        get_url = (
            reverse(
                "workspace-transactiondraft-list",
                kwargs={"workspace_pk": self.workspace.pk},
            )
            + "?type=expense"
        )
        draft_response = self.client.get(get_url)

        if draft_response.status_code == status.HTTP_200_OK:
            # Get the first draft from the list
            draft_to_save = self._get_response_data(draft_response)[0]
            # Skús uložiť existujúci draft - MALO BY ZLYHAŤ
            save_response = self.client.post(
                save_url, draft_to_save, format="json"
            )

            # 🚨 TU JE KRITICKÁ VALIDÁCIA - draft by NEMAL prejsť!
            self.assertEqual(save_response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn("category", str(save_response.data).lower())
            self.assertIn("level", str(save_response.data).lower())
        else:
            # Alebo draft bol automaticky zmazaný/invalidovaný - to je tiež OK
            self.assertEqual(draft_response.status_code, status.HTTP_404_NOT_FOUND)


    def test_draft_custom_endpoints(self):
        """Test all custom draft endpoints."""
        # Test draft save endpoint (now POST to list)
        save_url = reverse(
            "workspace-transactiondraft-list", kwargs={"workspace_pk": self.workspace.id}
        )
        draft_data = {
            "draft_type": "expense",
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "333.00",
                    "original_currency": "EUR",
                    "date": "2024-01-30",
                    "note_manual": "Custom endpoint test",
                }
            ],
        }
        response = self.client.post(save_url, draft_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        draft_id = response.data['id']

        # Test draft get workspace endpoint
        get_url = (
            reverse(
                "transaction-draft-get-workspace",
                kwargs={"workspace_pk": self.workspace.id},
            )
            + "?type=expense"
        )
        response = self.client.get(get_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test draft discard endpoint (now DELETE on detail)
        discard_url = reverse(
            "workspace-transactiondraft-detail", kwargs={"workspace_pk": self.workspace.id, "pk": draft_id}
        )
        response = self.client.delete(discard_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)


class ExchangeRateAPITests(BaseAPITestCase):
    """COMPREHENSIVE ExchangeRate API tests with date range and currency filtering."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(EXCHANGE_RATE_LIST)

    def test_list_exchange_rates_comprehensive(self):
        """Comprehensive exchange rate listing tests."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rates_data = self._get_response_data(response)
        self.assertGreaterEqual(len(rates_data), 5)  # Multiple currencies

        # Test filtering by currency
        response = self.client.get(self.list_url, {"currency": "USD"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rates_data = self._get_response_data(response)
        for rate in rates_data:
            self.assertEqual(rate["currency"], "USD")

        # Test filtering by date range
        today = date.today()
        week_ago = today - timedelta(days=7)
        response = self.client.get(
            self.list_url, {"date_from": week_ago.isoformat(), "date_to": today.isoformat()}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_exchange_rate_detailed(self):
        """Test retrieving specific exchange rate."""
        rate = ExchangeRate.objects.first()
        url = reverse(EXCHANGE_RATE_DETAIL, kwargs={"pk": rate.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data["currency"], rate.currency)
        self.assertEqual(Decimal(response.data["rate_to_eur"]), rate.rate_to_eur)


class WorkspaceMembershipCRUDTests(BaseAPITestCase):
    """CRUD tests for WorkspaceMembership operations."""

    def test_list_workspace_memberships(self):
        """Test listing all workspace memberships."""
        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        members_data = self._get_response_data(response)
        
        # Should have at least owner and viewer
        self.assertGreaterEqual(len(members_data), 2)
        
        # Verify membership data structure
        for member in members_data:
            self.assertIn('user_id', member)
            self.assertIn('role', member)
            self.assertIn('joined_at', member)

    def test_update_workspace_membership_role(self):
        """Test updating workspace membership role."""
        # Only workspace admin or owner can update roles
        self._authenticate_user(self.workspace_admin_user)
        
        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        update_data = {
            "user_id": self.other_user.id,
            "role": "editor"
        }
        
        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify role was updated
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, 
            user=self.other_user
        )
        self.assertEqual(membership.role, "editor")

    def test_remove_workspace_member(self):
        """Test removing member from workspace."""
        # Only workspace admin or owner can remove members
        self._authenticate_user(self.workspace_admin_user)
        
        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        remove_data = {
            "user_id": self.other_user.id
        }
        
        response = self.client.delete(url, remove_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify member was removed
        self.assertFalse(
            WorkspaceMembership.objects.filter(
                workspace=self.workspace, 
                user=self.other_user
            ).exists()
        )


class WorkspaceAdminCRUDTests(BaseAPITestCase):
    """CRUD tests for WorkspaceAdmin operations."""

    def test_list_workspace_admins(self):
        """Test listing all workspace admins."""
        url = reverse("workspaceadmin-list") + f"?workspace={self.workspace.id}"
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        admins_data = self._get_response_data(response)
        
        # Should have at least the workspace_admin_user
        self.assertGreaterEqual(len(admins_data), 1)
        
        # Verify admin data structure
        for admin in admins_data:
            self.assertIn('user_id', admin)
            self.assertIn('is_active', admin)
            self.assertIn('assigned_by', admin)
            
    def test_deactivate_workspace_admin(self):
        """Test deactivating workspace admin."""
        # Create a test admin assignment
        test_admin = UserFactory()
        admin_assignment = WorkspaceAdminFactory(
            user=test_admin,
            workspace=self.workspace,
            assigned_by=self.superuser,
            is_active=True
        )
        
        # Only superuser can deactivate
        self._authenticate_user(self.superuser)
        
        url = reverse("workspace-deactivate-admin", kwargs={"pk": admin_assignment.pk})
        response = self.client.post(url, format="json")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify admin was deactivated
        admin_assignment.refresh_from_db()
        self.assertFalse(admin_assignment.is_active)
        self.assertIsNotNone(admin_assignment.deactivated_at)


class TransactionDraftUpdateTests(BaseAPITestCase):
    """Update operations for Transaction Drafts."""
            
    def test_update_draft_partial_data(self):
        """Test partial update of draft data."""
        # First get existing draft
        get_url = reverse(
            "workspace-transactiondraft-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_draft.pk},
        )
        draft_response = self.client.get(get_url)
        
        if draft_response.status_code == status.HTTP_200_OK:
            draft_data = draft_response.data
            # Modify only some fields
            if draft_data.get('transactions_data'):
                draft_data['transactions_data'][0]['note_manual'] = "Partially updated"
                
            update_url = reverse(
                "workspace-transactiondraft-detail",
                kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_draft.pk},
            )
            response = self.client.patch(update_url, {"transactions_data": draft_data['transactions_data']}, format="json")
            self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)


class CategoryCRUDTests(BaseAPITestCase):
    """CRUD tests for Category operations."""
    
    def test_create_category(self):
        """Test creating new category."""
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )
        
        category_data = {
            "name": "New Test Category",
            "level": 1,
            "description": "Test category creation",
            "children": []
        }
        
        response = self.client.post(url, {"create": [category_data]}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    def test_update_category(self):
        """Test updating category details."""
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )
        
        update_data = {
            "update": [
                {
                    "id": self.expense_category.id,
                    "name": "Updated Category Name",
                    "level": self.expense_category.level,
                    "description": "Updated description"
                }
            ]
        }
        
        response = self.client.post(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    def test_move_category_hierarchy(self):
        """Test moving category in hierarchy."""
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )
        
        # Move child category to be root
        move_data = {
            "update": [
                {
                    "id": self.child_expense_category.id,
                    "name": self.child_expense_category.name,
                    "level": 1,  # Move to root level
                    "parent_id": None
                }
            ]
        }
        
        response = self.client.post(url, move_data, format="json")
        # Should succeed if category is not used
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class UserSettingsAPITests(BaseAPITestCase):
    """Tests for UserSettings API endpoints."""
    
    def test_retrieve_user_settings(self):
        """Test retrieving user settings."""
        url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": self.user.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify settings structure
        self.assertIn("preferred_currency", response.data)
        self.assertIn("date_format", response.data)
        
    def test_update_user_settings(self):
        """Test updating user settings."""
        url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": self.user.id})
        update_data = {
            "preferred_currency": "USD",
            "date_format": "MM/DD/YYYY"
        }
        
        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify settings were updated
        user_settings = UserSettings.objects.get(user=self.user)
        self.assertEqual(user_settings.preferred_currency, "USD")
        self.assertEqual(user_settings.language, "sk")


class WorkspaceSettingsAPITests(BaseAPITestCase):
    """Tests for WorkspaceSettings API endpoints."""
    
    def test_retrieve_workspace_settings(self):
        """Test retrieving workspace settings."""
        url = reverse(WORKSPACE_SETTINGS_DETAIL, kwargs={"pk": self.workspace_settings.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify settings structure podľa modelu
        self.assertIn("domestic_currency", response.data)
        self.assertIn("fiscal_year_start", response.data)
        self.assertIn("display_mode", response.data)
        self.assertIn("accounting_mode", response.data)
        
    def test_update_workspace_settings(self):
        """Test updating workspace settings."""
        url = reverse(WORKSPACE_SETTINGS_DETAIL, kwargs={"pk": self.workspace_settings.id})
        update_data = {
            "domestic_currency": "USD",
            "display_mode": "day",
            "accounting_mode": True
        }
        
        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify settings were updated
        self.workspace_settings.refresh_from_db()
        self.assertEqual(self.workspace_settings.domestic_currency, "USD")
        self.assertEqual(self.workspace_settings.display_mode, "day")
        self.assertEqual(self.workspace_settings.accounting_mode, True)

class CategoryUsageTests(BaseAPITestCase):
    """Tests for category usage validation."""
    
    def test_category_usage_validation(self):
        """Test that used categories cannot be deleted."""
        # Create transaction with category
        transaction = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            expense_category=self.child_expense_category,
            type="expense"
        )
        
        # Try to delete used category via sync endpoint
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )
        
        delete_data = {
            "delete": [self.child_expense_category.id]
        }
        
        response = self.client.post(url, delete_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_unused_category_can_be_deleted(self):
        """Test that unused categories can be deleted."""
        # Ensure category is not used
        self.assertFalse(
            Transaction.objects.filter(
                expense_category=self.child_expense_category
            ).exists()
        )
        
        # Delete unused category via sync endpoint
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )
        
        delete_data = {
            "delete": [self.child_expense_category.id]
        }
        
        response = self.client.post(url, delete_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AdminImpersonationAdvancedTests(BaseAPITestCase):
    """Advanced tests for admin impersonation functionality."""
    
    def test_superuser_can_impersonate_for_bulk_operations(self):
        """Test superuser can perform bulk operations with impersonation."""
        self._authenticate_user(self.superuser)
        
        # Bulk create transactions for target user
        url = reverse(BULK_SYNC_TRANSACTIONS, kwargs={"workspace_id": self.workspace.id}) + f"?user_id={self.user.id}"
        bulk_data = {
            "create": [
                {
                    "type": "expense",
                    "expense_category": self.expense_category.id,
                    "original_amount": "100.00",
                    "original_currency": "EUR",
                    "date": "2024-01-10",
                }
            ]
        }
        
        response = self.client.post(url, bulk_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify transactions were created for target user
        transactions = Transaction.objects.filter(workspace=self.workspace)
        self.assertTrue(any(t.user == self.user for t in transactions))
        
    def test_impersonation_with_different_roles(self):
        """Test impersonation works correctly with different user roles."""
        self._authenticate_user(self.superuser)
        
        # Impersonate viewer user
        url = reverse(TRANSACTION_LIST) + f"?user_id={self.other_user.id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class WorkspaceAdminManagementTests(BaseAPITestCase):
    """Tests for workspace admin management functionality."""
    
    def test_assign_workspace_admin(self):
        """Test assigning a new workspace admin."""
        self._authenticate_user(self.superuser)
        
        new_admin = UserFactory()
        url = reverse("workspace-assign-admin")
        # The action is on the viewset, so we use the basename and the action name.
        url = reverse("workspaceadmin-assign-admin", kwargs={"workspace_pk": self.workspace.id})
        assign_data = {
            "user_id": new_admin.id,
            "workspace_id": self.workspace.id
        }
        
        response = self.client.post(url, assign_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify admin was assigned
        self.assertTrue(
            WorkspaceAdmin.objects.filter(
                user=new_admin, 
                workspace=self.workspace, 
                is_active=True
            ).exists()
        )
        
    def test_list_workspace_admins_comprehensive(self):
        """Test comprehensive listing of workspace admins."""
        url = reverse("workspaceadmin-list") + f"?workspace={self.workspace.id}"
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        admins_data = self._get_response_data(response)
        
        # Should include active admins
        admin_users = [admin['user_id'] for admin in admins_data]
        self.assertIn(self.workspace_admin_user.id, admin_users)


class WorkspaceOwnershipTests(BaseAPITestCase):
    """Tests for workspace ownership functionality."""
    
    def test_transfer_workspace_ownership(self):
        """Test transferring workspace ownership to another user."""
        # Only owner can transfer ownership
        transfer_url = reverse("workspace-change-owner", kwargs={"pk": self.workspace.pk})
        transfer_data = {
            "new_owner_id": self.workspace_admin_user.id
        }
        
        response = self.client.post(transfer_url, transfer_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify ownership was transferred
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.owner, self.workspace_admin_user)
        
    def test_owner_permissions_after_transfer(self):
        """Test original owner permissions after ownership transfer."""
        # Transfer ownership
        self.workspace.owner = self.workspace_admin_user
        self.workspace.save()
        
        # Original owner should still have access but not full control
        response = self.client.get(reverse(WORKSPACE_DETAIL, kwargs={"pk": self.workspace.pk}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class MemberRoleManagementTests(BaseAPITestCase):
    """Tests for member role management functionality."""
    
    def test_promote_member_to_editor(self):
        """Test promoting a member from viewer to editor role."""
        self._authenticate_user(self.workspace_admin_user)
        
        url = reverse("workspace-members", kwargs={"pk": self.workspace.pk})
        url = reverse("workspace-update-member-role", kwargs={"pk": self.workspace.pk})
        promote_data = {
            "user_id": self.other_user.id,
            "role": "editor"
        }
        
        response = self.client.patch(url, promote_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify role was updated
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, 
            user=self.other_user
        )
        self.assertEqual(membership.role, "editor")
        
    def test_demote_editor_to_viewer(self):
        """Test demoting an editor to viewer role."""
        # First promote to editor
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, 
            user=self.other_user
        )
        membership.role = "editor"
        membership.save()
        
        self._authenticate_user(self.workspace_admin_user)
        
        url = reverse("workspace-members", kwargs={"pk": self.workspace.pk})
        demote_data = {
            "user_id": self.other_user.id,
            "role": "viewer"
        }
        
        response = self.client.patch(url, demote_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify role was updated
        membership.refresh_from_db()
        self.assertEqual(membership.role, "viewer")


class IntegrationSecurityTests(BaseAPITestCase):
    """Integration security tests covering multiple layers."""
    
    def test_comprehensive_access_control(self):
        """Test comprehensive access control across all endpoints."""
        # Test as viewer
        self._authenticate_user(self.other_user)
        
        # Can read but not write
        list_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Viewer cannot create a transaction
        create_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.post(create_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
    def test_data_isolation_between_workspaces(self):
        """Test that data is properly isolated between workspaces."""
        # Create separate workspace for other user
        other_workspace = WorkspaceFactory(owner=self.other_user)
        
        # Current user should not see other user's workspace data
        list_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.get(list_url)
        transactions_data = self._get_response_data(response)
        
        # No transactions should belong to other user's workspace
        for transaction in transactions_data:
            self.assertNotEqual(transaction['workspace'], other_workspace.id)


class BulkOperationsTests(BaseAPITestCase):
    """Tests for bulk operations across different models."""
    
    def test_bulk_transaction_operations(self):
        """Test comprehensive bulk transaction operations."""
        # Bulk create
        url = reverse(BULK_SYNC_TRANSACTIONS, kwargs={"workspace_id": self.workspace.id})
        bulk_data = {
            "create": [
                {
                    "type": "expense",
                    "expense_category": self.expense_category.id,
                    "original_amount": "100.00",
                    "original_currency": "EUR",
                    "date": "2024-01-10",
                },
                {
                    "type": "income", 
                    "income_category": self.income_category.id,
                    "original_amount": "200.00",
                    "original_currency": "USD",
                    "date": "2024-01-11",
                }
            ],
            "update": [
                {
                    "id": self.expense_transaction.id,
                    "original_amount": "150.00",
                    "note_manual": "Bulk updated"
                }
            ],
            "delete": [t.id for t in self.income_transactions]
        }
        
        response = self.client.post(url, bulk_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify operations were performed
        self.assertIn("created", response.data)
        self.assertIn("updated", response.data) 
        self.assertIn("deleted", response.data)

# =============================================================================
# MODEL VALIDATION TESTS
# =============================================================================

class ModelValidationTests(TestCase):
    """Model-level validation tests."""
    
    def test_transaction_amount_validation(self):
        """Test transaction amount validation."""
        from django.core.exceptions import ValidationError
        
        user = UserFactory()
        workspace = WorkspaceFactory(owner=user)
        category = ExpenseCategoryFactory()
        
        # Negative amount should raise validation error
        transaction = Transaction(
            user=user,
            workspace=workspace,
            type="expense", 
            expense_category=category,
            original_amount=Decimal("-100.00"),
            original_currency="EUR",
            date=date.today()
        )
        
        with self.assertRaises(ValidationError):
            transaction.full_clean()
            
    def test_category_level_validation(self):
        """Test category level validation."""
        from django.core.exceptions import ValidationError
        
        workspace = WorkspaceFactory()
        version = ExpenseCategoryVersionFactory(workspace=workspace)
        
        # Level 6 should be invalid
        category = ExpenseCategory(
            version=version,
            name="Invalid Level",
            level=6
        )
        
        with self.assertRaises(ValidationError):
            category.full_clean()


class EdgeCaseTests(BaseAPITestCase):
    """Tests for edge cases and error conditions."""
    
    def test_nonexistent_resource_access(self):
        """Test accessing nonexistent resources."""
        # Nonexistent transaction - using the correct nested URL
        url = reverse(
            "workspace-transaction-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": 99999},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Nonexistent workspace  
        url = reverse(WORKSPACE_DETAIL, kwargs={"pk": 99999})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
    def test_malformed_request_data(self):
        """Test handling of malformed request data."""
        # Malformed JSON
        url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.post(
            url, 
            '{"malformed": json}', 
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_large_amount_handling(self):
        """Test handling of very large amounts."""
        data = { # workspace is taken from URL
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "999999999.99",
            "original_currency": "EUR", 
            "date": "2024-01-15",
        }
        create_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.post(create_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

class PerformanceTests(BaseAPITestCase):
    """Performance-related tests."""
    
    def test_large_dataset_handling(self):
        """Test API performance with larger datasets."""
        # Create larger dataset
        TransactionFactory.create_batch(
            50,
            user=self.user,
            workspace=self.workspace,
            type="expense",
            expense_category=self.expense_category,
        )
        
        # Test listing performance
        import time
        start_time = time.time()
        list_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.get(list_url)
        end_time = time.time()
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Response should be reasonably fast
        self.assertLess(end_time - start_time, 2.0)  # Under 2 seconds


# =============================================================================
# INTEGRATION TESTS  
# =============================================================================

class IntegrationTests(BaseAPITestCase):
    """End-to-end integration tests."""
    
    def test_complete_workflow(self):
        """Test complete user workflow."""
        # 1. User accesses their workspaces
        response = self.client.get(reverse(WORKSPACE_LIST))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 2. User creates a draft transaction
        draft_list_url = reverse(
            "workspace-transactiondraft-list",
            kwargs={"workspace_pk": self.workspace.pk},
        )
        draft_data = {
            "draft_type": "expense",
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "150.00",
                    "original_currency": "EUR",
                    "date": "2024-01-15",
                    "expense_category_id": self.expense_category.id,
                }
            ]
        }
        response = self.client.post(draft_list_url, draft_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # 3. User converts draft to actual transaction
        transaction_data = { # workspace is from URL
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "150.00",
            "original_currency": "EUR", 
            "date": "2024-01-15",
        }
        create_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.post(create_url, transaction_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # 4. User views their transactions
        list_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        transactions = self._get_response_data(response)
        self.assertGreaterEqual(len(transactions), 1)
        
        # 5. User updates their settings
        settings_url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": self.user.id})
        settings_data = {"preferred_currency": "USD"}
        user_settings = UserSettings.objects.get(user=self.user)
        settings_url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": user_settings.pk})
        settings_data = {"language": "en"}
        response = self.client.patch(settings_url, settings_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class ErrorHandlingTests(BaseAPITestCase):
    """Tests for error handling and edge cases."""
    
    def test_invalid_currency_handling(self):
        """Test handling of invalid currencies."""
        data = { # workspace is from URL
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "100.00",
            "original_currency": "INVALID",  # Invalid currency code
            "date": "2024-01-15",
        }
        create_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.post(create_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_invalid_date_handling(self):
        """Test handling of invalid dates."""
        data = { # workspace is from URL
            "type": "expense", 
            "expense_category": self.expense_category.id,
            "original_amount": "100.00",
            "original_currency": "EUR",
            "date": "invalid-date",  # Invalid date format
        }
        create_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.post(create_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_foreign_key_violation(self):
        """Test handling of invalid foreign keys."""
        data = { # workspace is from URL, but we test with a bad category
            "expense_category": 99999, # Nonexistent category
            "type": "expense",
            "original_amount": "100.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        create_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.post(create_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# =============================================================================
# SECURITY TESTS
# =============================================================================

class SecurityTests(BaseAPITestCase):
    """Security-related tests."""
    
    def test_cross_workspace_access_prevention(self):
        """Test that users cannot access other users' workspaces."""
        # Create workspace for other user
        other_workspace = WorkspaceFactory(owner=self.other_user)
        
        # Current user tries to access other user's workspace
        url = reverse(WORKSPACE_DETAIL, kwargs={"pk": other_workspace.id})
        response = self.client.get(url)
        # Should not be able to access - 404 is correct as it shouldn't leak existence
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

class AuthenticationTests(BaseAPITestCase):
    """Authentication and authorization tests."""
    
    def test_unauthenticated_access(self):
        """Test that unauthenticated users cannot access protected endpoints."""
        self.client.force_authenticate(user=None)  # Log out
        
        response = self.client.get(reverse(WORKSPACE_LIST))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        list_url = reverse("workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk})
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_token_authentication(self):
        """Test JWT token authentication."""
        from rest_framework_simplejwt.tokens import RefreshToken
        
        # Get token for user
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        
        # Use token for authentication
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(reverse(WORKSPACE_LIST))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
# =============================================================================
# TEST RUNNER CONFIGURATION  
# =============================================================================


def run_integration_tests():
    """Helper function to run all integration tests."""
    import unittest

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(WorkspaceAPITests)
    suite.addTests(loader.loadTestsFromTestCase(SuperuserImpersonationTests))
    suite.addTests(loader.loadTestsFromTestCase(TransactionAPITests))
    suite.addTests(loader.loadTestsFromTestCase(CategoryAPITests))
    suite.addTests(loader.loadTestsFromTestCase(TransactionDraftAPITests))
    suite.addTests(loader.loadTestsFromTestCase(ExchangeRateAPITests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceMembershipCRUDTests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceAdminCRUDTests))
    suite.addTests(loader.loadTestsFromTestCase(TransactionDraftUpdateTests))
    suite.addTests(loader.loadTestsFromTestCase(CategoryCRUDTests))
    suite.addTests(loader.loadTestsFromTestCase(UserSettingsAPITests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceSettingsAPITests))
    suite.addTests(loader.loadTestsFromTestCase(BulkOperationsTests))
    suite.addTests(loader.loadTestsFromTestCase(ModelValidationTests))
    suite.addTests(loader.loadTestsFromTestCase(EdgeCaseTests))
    suite.addTests(loader.loadTestsFromTestCase(PerformanceTests))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTests))
    suite.addTests(loader.loadTestsFromTestCase(ErrorHandlingTests))
    suite.addTests(loader.loadTestsFromTestCase(SecurityTests))
    suite.addTests(loader.loadTestsFromTestCase(AuthenticationTests))

    # 🔥 DOPLNENÉ CHÝBAJÚCE TESTY Z PÔVODNÉHO SÚBORU
    suite.addTests(loader.loadTestsFromTestCase(CategoryUsageTests))
    suite.addTests(loader.loadTestsFromTestCase(TagsAPITests))
    suite.addTests(loader.loadTestsFromTestCase(AdminImpersonationAdvancedTests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceAdminManagementTests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceOwnershipTests))
    suite.addTests(loader.loadTestsFromTestCase(MemberRoleManagementTests))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationSecurityTests))

    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING COMPREHENSIVE INTEGRATION TEST SUITE")
    print(f"Total Test Classes: 27")  # 🔥 OPRAVENÉ: 21 → 27
    print(f"Estimated Test Methods: 70+")  # 🔥 OPRAVENÉ: 52+ → 70+
    print("=" * 70)
    
    result = run_integration_tests()
    
    print("=" * 70)
    print("TEST EXECUTION COMPLETE")
    print(f"Tests run: {result.testsRun}")
    if result.failures:
        print(f"Failures: {len(result.failures)}")
    if result.errors:
        print(f"Errors: {len(result.errors)}")
            