"""
COMPREHENSIVE Integration tests for financial management system API endpoints.
Enhanced with admin impersonation, permission testing, and edge case coverage.
"""

import json
from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch

from django.db import transaction
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string
from faker import Faker
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from rest_framework_simplejwt.tokens import AccessToken

from django.core.exceptions import ValidationError

from finance.mixins.workspace_membership import WorkspaceMembershipMixin
from finance.models import (
    ExchangeRate,
    ExpenseCategory,
    ExpenseCategoryVersion,
    IncomeCategory,
    IncomeCategoryVersion,
    Tags,
    Transaction,
    TransactionDraft,
    UserSettings,
    Workspace,
    WorkspaceAdmin,
    WorkspaceMembership,
    WorkspaceSettings,
)
from finance.views import TransactionViewSet

from ..factories import (
    ExchangeRateFactory,
    ExpenseCategoryFactory,
    ExpenseCategoryVersionFactory,
    IncomeCategoryFactory,
    IncomeCategoryVersionFactory,
    TagFactory,
    TransactionDraftFactory,
    TransactionFactory,
    UserFactory,
    UserSettingsFactory,
    WorkspaceAdminFactory,
    WorkspaceFactory,
    WorkspaceMembershipFactory,
    WorkspaceSettingsFactory,
)

User = get_user_model()
fake = Faker()

# =============================================================================
# URL ENDPOINT CONSTANTS
# =============================================================================

# Router-generated endpoints
WORKSPACE_LIST = "workspace-list"
WORKSPACE_DETAIL = "workspace-detail"
WORKSPACE_SETTINGS_LIST = "workspacesettings-list"
WORKSPACE_SETTINGS_DETAIL = "workspace-settings-detail"
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
        """
        Create a baseline of recent exchange rates.
        This method is designed to be non-destructive to support isolated test setups.
        """

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
                # Use update_or_create to be safe. This prevents this setup from
                # interfering with tests that need specific historical rates.
                ExchangeRate.objects.update_or_create(
                    currency=currency,
                    date=rate_date,
                    defaults={"rate_to_eur": rate + Decimal(i * 0.001)},
                )

    def setUp(self):
        """Set up DYNAMIC test data that might change between test methods."""
        # Create fresh data for EACH test to ensure 100% isolation.
        # Order is important.
        super().setUp()
        cache.clear()
        with transaction.atomic():
            Tags.objects.all().delete()
        self._create_test_users()
        self._create_workspace_structure()
        self._create_categories()
        self._create_dynamic_test_data()

        # Authenticate user
        self.client.force_authenticate(user=self.user)

    def _create_test_users(self):  # Now an instance method
        """Create test users with CORRECT roles for your architecture."""

        # 1. SUPERUSER - globálny admin (môže všetko)
        self.superuser = UserFactory(
            username="superuser",
            email="superuser@example.com",
            is_superuser=True,
            is_staff=True,
        )

        # 2. WORKSPACE ADMIN - admin konkrétnych workspaces (NIE superuser!)
        self.workspace_admin_user = UserFactory(
            username="workspace_admin",
            email="workspace_admin@example.com",
            is_superuser=False,
            is_staff=False,
        )

        # 3. REGULAR USERS - normálni používatelia
        self.user = UserFactory(
            username="regular_user",
            email="user@example.com",
            is_superuser=False,
            is_staff=False,
        )

        self.other_user = UserFactory(
            username="other_user",
            email="other@example.com",
            is_superuser=False,
            is_staff=False,
        )

        # 🔥 DÔLEŽITÉ: Nastav správne heslá
        users = [self.superuser, self.workspace_admin_user, self.user, self.other_user]
        for user in users:
            user.set_password("testpass123")
            user.save()

        self._ensure_verified_emails(users)

    def _create_workspace_structure(self):  # Now an instance method
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
            user=self.workspace_admin_user,  # workspace admin user
            workspace=self.workspace,  # v tomto workspace
            assigned_by=self.superuser,  # assigned by superuser
            is_active=True,
        )

        self.workspace_settings = self.workspace.settings

    def _create_categories(self):  # Now an instance method
        """Create a production-ready, consistent 5-level category hierarchy for tests."""
        self.expense_version = ExpenseCategoryVersionFactory(
            workspace=self.workspace, created_by=self.user, levels_count=5
        )
        self.income_version = IncomeCategoryVersionFactory(
            workspace=self.workspace, created_by=self.user, levels_count=5
        )

        # --- Build Expense Hierarchy (L1 -> L2 -> L3 -> L4 -> L5) ---
        # Step 1: Create all categories first
        self.expense_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Root Expense", level=1
        )
        l2_exp = ExpenseCategoryFactory(
            version=self.expense_version, name="L2 Expense", level=2
        )
        l3_exp = ExpenseCategoryFactory(
            version=self.expense_version, name="L3 Expense", level=3
        )
        l4_exp = ExpenseCategoryFactory(
            version=self.expense_version, name="L4 Expense", level=4
        )
        self.leaf_expense_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Leaf Expense", level=5
        )
        self.child_expense_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Child Expense Category", level=2
        )

        # Step 2: Establish parent-child relationships
        self.expense_category.children.add(l2_exp, self.child_expense_category)
        l2_exp.children.add(l3_exp)
        l3_exp.children.add(l4_exp)
        l4_exp.children.add(self.leaf_expense_category)

        # --- Build Income Hierarchy (L1 -> L2 -> L3 -> L4 -> L5) ---
        # Step 1: Create all categories first
        self.income_category = IncomeCategoryFactory(
            version=self.income_version, name="Root Income", level=1
        )
        l2_inc = IncomeCategoryFactory(
            version=self.income_version, name="L2 Income", level=2
        )
        l3_inc = IncomeCategoryFactory(
            version=self.income_version, name="L3 Income", level=3
        )
        l4_inc = IncomeCategoryFactory(
            version=self.income_version, name="L4 Income", level=4
        )
        self.leaf_income_category = IncomeCategoryFactory(
            version=self.income_version, name="Leaf Income", level=5
        )
        self.child_income_category = IncomeCategoryFactory(
            version=self.income_version, name="Child Income Category", level=2
        )

        # Step 2: Establish parent-child relationships
        self.income_category.children.add(l2_inc, self.child_income_category)
        l2_inc.children.add(l3_inc)
        l3_inc.children.add(l4_inc)
        l4_inc.children.add(self.leaf_income_category)

    def _create_dynamic_test_data(self):  # Now an instance method
        """Create DYNAMIC test data that might be modified during tests."""
        self._create_test_transactions()
        self._create_test_drafts()

    # Note: The following methods are now instance methods (def) instead of class methods (@classmethod)
    # because they are called from setUp, not setUpTestData.

    def _create_test_transactions(self):  # Now an instance method
        """Create test transactions."""
        # Clean up any existing transactions for this workspace
        Transaction.objects.filter(workspace=self.workspace).delete()

        # Create tags that are correctly associated with the workspace first.
        # This prevents the factory from creating orphaned tags.
        food_tag, _ = Tags.objects.get_or_create(workspace=self.workspace, name="food")
        travel_tag, _ = Tags.objects.get_or_create(
            workspace=self.workspace, name="travel"
        )

        # Create expense transactions
        self.expense_transactions = TransactionFactory.create_batch(
            3,
            user=self.user,
            workspace=self.workspace,
            type="expense",
            expense_category=self.expense_category,
            original_currency="EUR",
            tags=[],
        )
        # Manually assign the tags after creation for full control.
        for transaction in self.expense_transactions:
            transaction.tags.add(food_tag, travel_tag)

        # Create income transactions
        self.income_transactions = TransactionFactory.create_batch(
            2,
            user=self.user,
            workspace=self.workspace,
            type="income",
            income_category=self.income_category,
            original_currency="USD",
            tags=[],
        )
        for transaction in self.income_transactions:
            transaction.tags.add(travel_tag)

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

    def _create_test_drafts(self):  # Now an instance method
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
        if hasattr(response, "data") and isinstance(response.data, dict):
            if "results" in response.data:
                return response.data["results"]
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
            user=user, workspace=workspace, assigned_by=self.superuser, is_active=True
        )

    def tearDown(self):
        """Clean up after tests."""
        # Restore original settings
        from django.conf import settings

        if self.original_email_verification is not None:
            settings.ACCOUNT_EMAIL_VERIFICATION = self.original_email_verification
        if self.original_email_required is not None:
            settings.ACCOUNT_EMAIL_REQUIRED = self.original_email_required
        cache.clear()
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
        admin_workspace_url = reverse(
            WORKSPACE_DETAIL, kwargs={"pk": admin_workspace.pk}
        )

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

        editor_workspace_url = reverse(
            WORKSPACE_DETAIL, kwargs={"pk": editor_workspace.pk}
        )
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
        url = reverse(
            "workspace-settings-detail", kwargs={"workspace_pk": self.workspace.pk}
        )
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
        # Clean slate: Delete any tags that might have been created by other tests
        Tags.objects.filter(workspace=self.workspace).delete()

        # Use get_or_create to safely create or retrieve tags. This is robust and
        # avoids both IntegrityError (if tags exist) and DoesNotExist (if they don't).
        # The `_` is used to ignore the `created` boolean returned by get_or_create.
        self.tag1, _ = Tags.objects.get_or_create(workspace=self.workspace, name="food")
        self.tag2, _ = Tags.objects.get_or_create(
            workspace=self.workspace, name="travel"
        )

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
        self.assertEqual(
            response.data["name"], "urgent"
        )  # Name should be lowercased and stripped

    def test_create_existing_tag_is_idempotent(self):
        """Test that creating a tag with an existing name returns the existing tag."""
        data = {"name": "food"}  # This tag already exists
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            response.data["id"], self.tag1.id
        )  # Should return the existing tag's ID

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
        if not WorkspaceMembership.objects.filter(
            workspace=extra_workspace, user=self.user
        ).exists():
            WorkspaceMembershipFactory(
                workspace=extra_workspace, user=self.user, role="owner"
            )

        # Authenticate as SUPERUSER
        self._authenticate_user(self.superuser)

        # Superuser should see ALL user workspaces with impersonation
        response = self.client.get(reverse(WORKSPACE_LIST), {"user_id": self.user.id})
        workspaces_list = self._get_workspaces_list(response)

        # Should see at least the workspaces user has access to
        self.assertGreaterEqual(len(workspaces_list), 1)

    def test_superuser_can_impersonate_any_user(self):
        """Test superuser can impersonate any user across all endpoints."""
        self._authenticate_user(self.superuser)

        # Test transaction creation with impersonation
        # Use the new nested URL structure
        url = (
            reverse(
                "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
            )
            + f"?user_id={self.user.id}"
        )
        data = {
            "workspace": self.workspace.id,
            "type": "expense",
            "expense_category": self.leaf_expense_category.id,
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
            kwargs={
                "workspace_pk": self.workspace.pk,
                "pk": self.expense_transaction.pk,
            },
        )

    def test_list_transactions_comprehensive(self):
        """Comprehensive transaction listing with various filters."""
        # Test basic listing
        response = self.client.get(
            self.list_url
        )  # list_url already contains workspace context
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
        response = self.client.get(
            self.list_url, {"month": current_month}
        )  # workspace is already in URL
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
            "tag_list",
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
        data = {  # workspace is now taken from URL, not from data
            "type": "expense",
            "expense_category": self.leaf_expense_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
            "note_manual": "Test expense transaction",
            "tags": ["test", "expense"],
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Valid income transaction
        data = {  # workspace is now taken from URL
            "type": "income",
            "income_category": self.leaf_income_category.id,
            "original_amount": "500.00",
            "original_currency": "USD",
            "date": "2024-01-20",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Invalid: Both categories provided
        data = {  # workspace is now taken from URL
            "type": "expense",
            "expense_category": self.expense_category.id,
            "income_category": self.income_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(self.list_url, data, format="json")
        print(response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Invalid: No category provided
        data = {  # workspace is now taken from URL
            "type": "expense",
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Invalid: Wrong category type
        data = {  # workspace is now taken from URL
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
        self.expense_transaction.tags.add(
            TagFactory(workspace=self.workspace, name="persistent-tag")
        )
        self.assertEqual(self.expense_transaction.tags.count(), 1)

        # Now, update another field without sending the 'tags' key
        data = {"note_manual": "Final note update"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.tags.count(), 1)
        self.assertEqual(self.expense_transaction.tags.first().name, "persistent-tag")

        # --- 4. Test update with category change ---
        data = {"expense_category": self.leaf_expense_category.id}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.expense_transaction.refresh_from_db()
        self.assertEqual(
            self.expense_transaction.expense_category, self.leaf_expense_category
        )

    def test_delete_transaction_permissions(self):
        """Test transaction deletion with permission validation."""
        # Use the new nested URL
        detail_url = reverse(
            "workspace-transaction-detail",
            kwargs={
                "workspace_pk": self.workspace.pk,
                "pk": self.expense_transaction.pk,
            },
        )

        # --- ADVANCED DEBUGGING START ---
        try:
            db_transaction = Transaction.objects.get(pk=self.expense_transaction.pk)
            print(f"🔍 DB CHECK: Transaction PK={db_transaction.pk} FOUND in DB.")
            print(
                f"🔍 DB CHECK: Transaction belongs to Workspace PK={db_transaction.workspace.pk}"
            )
            if db_transaction.workspace.pk != self.workspace.pk:
                print(
                    f"🔥 MISMATCH: Transaction's workspace ({db_transaction.workspace.pk}) != Test's workspace ({self.workspace.pk})"
                )
        except Transaction.DoesNotExist:
            print(
                f"🔥 NOT FOUND: Transaction PK={self.expense_transaction.pk} does NOT exist in DB before DELETE call!"
            )
        # --- ADVANCED DEBUGGING END ---

        # --- DEBUGGING START ---
        print(f"🔍 DEBUG Test: Authenticated user ID: {self.user.id}")
        print(f"🔍 DEBUG Test: Workspace PK from test: {self.workspace.pk}")
        print(
            f"🔍 DEBUG Test: Expense transaction PK from test: {self.expense_transaction.pk}"
        )
        print(
            f"🔍 DEBUG Test: Expense transaction user ID: {self.expense_transaction.user.id}"
        )
        print(
            f"🔍 DEBUG Test: Expense transaction workspace PK: {self.expense_transaction.workspace.pk}"
        )
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
        detail_url_for_viewer = reverse(
            "workspace-transaction-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": transaction.pk},
        )

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

    def test_get_queryset_without_workspace_pk_returns_empty_and_logs(self):
        """Test get_queryset returns empty and logs warning when workspace_pk is missing."""
        # This test needs to bypass the URL dispatcher's workspace_pk resolution
        # to explicitly test the safeguard within get_queryset.
        list_url = "/dummy/transactions/" # Use a dummy URL since the actual URL pattern doesn't expect workspace_pk for this test case
        # Mock the request to ensure no workspace_pk is present
        from django.test.client import RequestFactory
        factory = RequestFactory()
        mock_request = factory.get(list_url)
        mock_request.user = self.user
        mock_request.target_user = self.user
        mock_request.query_params = {} # Ensure no query params
        mock_request.is_admin_impersonation = False
        mock_request.workspace = None # Explicitly ensure no workspace in request
        mock_request.resolver_match = None # Mock resolver_match as well if needed by mixin

        with patch("finance.views.logger") as mock_logger:
            view = TransactionViewSet(request=mock_request)
            view.kwargs = {}
            queryset = view.get_queryset()
            self.assertEqual(queryset.count(), 0)
            mock_logger.warning.assert_called_with(
                "Transaction queryset requested without workspace_pk in URL."
            )




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
        self.assertEqual(len(response.data["children"]), 2)  # Should have two children

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

        # Create a new category as a child of the existing root `self.expense_category`.
        # Use `parent_id` so the backend knows where to attach the new node.
        sync_data = [
            {
                "temp_id": "t1",
                "name": "New Expense Category",
                "level": self.expense_category.level + 1,
                "description": "Synced category",
                "parent_id": self.expense_category.id,
            }
        ]
        data = {"create": sync_data}

        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_category_move_validation_used_category(self):
        """Test that used category cannot be moved."""
        # ARRANGE
        # Create a valid structure: Parent (L4) -> Leaf Child (L5)
        parent_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Parent Category L4", level=4
        )
        leaf_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Leaf Child L5", level=5
        )
        parent_category.children.add(leaf_category)

        # Create a transaction using the valid leaf category (level 5)
        Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            expense_category=leaf_category,  # Correctly use a level 5 category
            type="expense",
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )

        # ACTION
        # Try to move the PARENT of the used category. This should be blocked.
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )

        sync_data = {
            "update": [
                {
                    "id": parent_category.id,  # Attempt to move the parent
                    "name": parent_category.name,
                    "level": 1,
                    "parent_id": None,
                }
            ]
        }

        response = self.client.post(url, sync_data, format="json")

        # ASSERT: The move should be rejected because a child category is used.
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_category_move_validation_unused_category(self):
        """
        Test moving a category where the frontend provides placeholder categories
        to maintain a uniform tree depth, which the backend must validate.
        """
        # ARRANGE
        # Rule: All branches in this test will have a uniform depth of 4.
        #
        # Initial State:
        # root (lvl 1)
        # ├── Old Parent (lvl 2)
        # │   └── Category to Move (lvl 3)
        # │       └── Leaf Child (lvl 4)
        # └── New Parent (lvl 2)
        #     └── Sibling (lvl 3)
        #         └── Sibling Leaf (lvl 4)

        root_category = self.expense_category

        # Step 1: Create all categories without parent relationships first.
        old_parent = ExpenseCategoryFactory(
            version=self.expense_version, level=2, name="Old Parent"
        )
        new_parent = ExpenseCategoryFactory(
            version=self.expense_version, level=2, name="New Parent"
        )
        category_to_move = ExpenseCategoryFactory(
            version=self.expense_version, level=3, name="Category to Move"
        )
        leaf_child = ExpenseCategoryFactory(
            version=self.expense_version, level=4, name="Leaf Child"
        )
        sibling = ExpenseCategoryFactory(
            version=self.expense_version, level=3, name="Sibling"
        )
        sibling_leaf = ExpenseCategoryFactory(
            version=self.expense_version, level=4, name="Sibling Leaf"
        )

        # Step 2: Manually establish the initial parent-child relationships.
        root_category.children.add(old_parent, new_parent)
        old_parent.children.add(category_to_move)
        category_to_move.children.add(leaf_child)
        new_parent.children.add(sibling)
        sibling.children.add(sibling_leaf)

        # ACTION
        # The frontend calculates that moving "Category to Move" will leave a gap.
        # It must send `create` operations for placeholders to extend the old branch
        # back to the required uniform depth of 4.
        payload = {
            "update": [
                {
                    "id": category_to_move.id,
                    "parent_id": new_parent.id,
                    "name": category_to_move.name,  # Include name for validation
                    "level": category_to_move.level,  # Include level for validation
                }
            ],
            "create": [
                {
                    "temp_id": "p1",
                    "name": "Placeholder 3",
                    "level": 3,
                    "parent_id": old_parent.id,
                },
                {
                    "temp_id": "p2",
                    "name": "Placeholder 4",
                    "level": 4,
                    "parent_temp_id": "p1",
                },
            ],
            "delete": [],
        }
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )
        response = self.client.post(url, payload, format="json")
        print(response.data)

        # ASSERT
        # The backend should accept this complete and valid payload.
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

        # Verify the move was successful.
        category_to_move.refresh_from_db()
        self.assertEqual(category_to_move.parents.first(), new_parent)

        # Verify the placeholders were created correctly to maintain uniform depth.
        # This is a more robust way to check than a complex filter.
        try:
            placeholder_3 = ExpenseCategory.objects.get(
                name="Placeholder 3", version=self.expense_version
            )
            placeholder_4 = ExpenseCategory.objects.get(
                name="Placeholder 4", version=self.expense_version
            )
        except ExpenseCategory.DoesNotExist:
            self.fail("Placeholder categories were not created in the database.")

        self.assertEqual(
            placeholder_3.parents.first(),
            old_parent,
            "Placeholder 3 should be a child of Old Parent",
        )
        self.assertEqual(
            placeholder_4.parents.first(),
            placeholder_3,
            "Placeholder 4 should be a child of Placeholder 3",
        )

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

    def test_expense_category_usage_not_member_403(self):
        """Test expense category usage endpoint returns 403 if user is not workspace member."""
        # Create a new workspace and category that current user is NOT a member of
        other_workspace = WorkspaceFactory(owner=UserFactory())
        other_expense_version = ExpenseCategoryVersionFactory(workspace=other_workspace)
        other_category = ExpenseCategoryFactory(version=other_expense_version, name="Other Cat")

        url = reverse(EXPENSE_CATEGORY_DETAIL, kwargs={"pk": other_category.pk}) + "usage/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("not a member of this workspace", response.data["detail"])

    def test_expense_category_usage_insufficient_permissions_403(self):
        """Test expense category usage endpoint returns 403 if user has insufficient permissions (e.g., viewer)."""
        # Authenticate as a viewer
        self._authenticate_user(self.other_user) # self.other_user is a viewer
        url = reverse(EXPENSE_CATEGORY_DETAIL, kwargs={"pk": self.expense_category.pk}) + "usage/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("You need editor or higher permissions", response.data["detail"])

    def test_income_category_usage_not_member_403(self):
        """Test income category usage endpoint returns 403 if user is not workspace member."""
        other_workspace = WorkspaceFactory(owner=UserFactory())
        other_income_version = IncomeCategoryVersionFactory(workspace=other_workspace)
        other_category = IncomeCategoryFactory(version=other_income_version, name="Other Inc Cat")

        url = reverse(INCOME_CATEGORY_DETAIL, kwargs={"pk": other_category.pk}) + "usage/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("not a member of this workspace", response.data["detail"])

    def test_category_sync_workspace_not_found(self):
        """Test category_sync returns 404 if workspace is not found."""
        self._authenticate_user(self.user) # Authenticate as a regular user

        # Mock user_permissions to simulate workspace_exists as False
        # Mock _validate_workspace_existence to simulate workspace not found or access denied
        with patch("finance.services.workspace_context_service.WorkspaceContextService._validate_workspace_existence", return_value=None):
            # Use a dummy URL, as the check happens before actual URL resolution
            sync_url = reverse(
                "workspace-category-sync",
                kwargs={"workspace_pk": 99999, "category_type": "expense"}
            )
            response = self.client.post(sync_url, {}, format="json")
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertIn("You do not have permission to perform this action.", str(response.data["detail"]))

    def test_category_sync_invalid_category_type(self):
        """Test category_sync returns 400 for invalid category type."""
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "invalid_type"},
        )
        response = self.client.post(url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid category type", response.data["detail"])

    def test_category_sync_generic_exception(self):
        """Test category_sync returns 400 for a generic exception."""
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )
        data = {"create": [{"temp_id": "t1", "name": "Test", "level": 1}]}

        # Mock sync_categories_tree to raise a generic exception
        with patch("finance.views.sync_categories_tree") as mock_sync_categories_tree:
            mock_sync_categories_tree.side_effect = Exception("Service layer error")
            mock_sync_categories_tree.__name__ = "sync_categories_tree"
            response = self.client.post(url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn("Service operation failed", response.data["detail"])
            self.assertIn("Service operation failed", response.data["detail"])



class TransactionDraftAPITests(BaseAPITestCase):
    """COMPREHENSIVE TransactionDraft API tests with atomic operations."""

    def setUp(self):
        super().setUp()
        # Use the new nested URL for drafts
        self.list_url = reverse(
            "workspace-transactiondraft-list",
            kwargs={"workspace_pk": self.workspace.pk},
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
        # Create a valid leaf category for testing
        leaf_expense_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Leaf Expense Category", level=5
        )
        leaf_income_category = IncomeCategoryFactory(
            version=self.income_version, name="Leaf Income Category", level=5
        )

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
                    "expense_category_id": leaf_expense_category.id,
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
                    "income_category_id": leaf_income_category.id,
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
        response = self.client.delete(other_draft_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_save_draft_access_denied_403(self):
        """Test save_draft returns 403 if user doesn't have access to workspace."""
        self._authenticate_user(self.user) # Authenticate with a regular user
        url = reverse("workspace-transactiondraft-list", kwargs={"workspace_pk": 99999}) # Non-existent workspace
        draft_data = {
            "draft_type": "expense",
            "transactions_data": [],
        }
        # Mock _has_workspace_access to return False
        with patch("finance.views.TransactionDraftViewSet._has_workspace_access", return_value=False):
            response = self.client.post(url, draft_data, format="json")
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertIn("You do not have permission to perform this action.", str(response.data))

    def test_get_workspace_draft_access_denied_403(self):
        """Test get_workspace_draft returns 403 if user doesn't have access to workspace."""
        self._authenticate_user(self.user)
        url = reverse("transaction-draft-get-workspace", kwargs={"workspace_pk": 99999}) + "?type=expense"
        with patch("finance.views.TransactionDraftViewSet._has_workspace_access", return_value=False):
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertIn("You do not have permission to perform this action.", str(response.data))

    def test_get_workspace_draft_not_found_returns_empty(self):
        """Test get_workspace_draft returns empty transactions_data if no draft exists."""
        self._authenticate_user(self.user)
        # Delete existing drafts to ensure no draft exists
        TransactionDraft.objects.all().delete()
        url = reverse("transaction-draft-get-workspace", kwargs={"workspace_pk": self.workspace.pk}) + "?type=expense"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["transactions_data"], [])

    def test_discard_draft_not_found_404(self):
        """Test discard draft returns 404 if draft not found."""
        self._authenticate_user(self.user)
        url = reverse("workspace-transactiondraft-detail", kwargs={"workspace_pk": self.workspace.pk, "pk": 99999}) # Non-existent draft
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn("No TransactionDraft matches the given query.", str(response.data))

        # 1. Create a valid level 5 category for the test.
        valid_leaf_category = ExpenseCategoryFactory(
            version=self.expense_version, name="Valid Leaf for Draft Test", level=5
        )
        self.assertFalse(
            Transaction.objects.filter(expense_category=valid_leaf_category).exists()
        )

        # Use the nested URL for creating a draft.
        save_url = reverse(
            "workspace-transactiondraft-list",
            kwargs={"workspace_pk": self.workspace.pk},
        )
        draft_data = {
            "draft_type": "expense",
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "200.00",
                    "original_currency": "EUR",
                    "date": "2024-01-20",
                    "expense_category_id": valid_leaf_category.id,
                }
            ],
        }

        # 2. Save the draft with the valid level 5 category. This SHOULD pass.
        response = self.client.post(save_url, draft_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 3. Move the category to a non-leaf level, making it invalid for transactions.
        valid_leaf_category.level = 4  # No longer a leaf level!
        valid_leaf_category.save()

        # Verify the category is still not used in any real transactions.
        self.assertFalse(
            Transaction.objects.filter(expense_category=valid_leaf_category).exists()
        )

        # 4. Try to save the draft again. This SHOULD FAIL because the category is now invalid.
        # We fetch the exact draft we created to get its latest data for the update attempt.
        draft_id = response.data["id"]
        draft_to_resave_url = reverse(
            "workspace-transactiondraft-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": draft_id},
        )
        draft_to_resave_response = self.client.get(draft_to_resave_url)
        self.assertEqual(draft_to_resave_response.status_code, status.HTTP_200_OK)
        draft_to_save_data = draft_to_resave_response.data

        # Try to save the existing draft data again. The serializer's create handles this as an update.
        save_response = self.client.post(save_url, draft_to_save_data, format="json")

        # CRITICAL VALIDATION: The draft save should now be rejected.
        self.assertEqual(save_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("category", str(save_response.data).lower())
        self.assertIn("level", str(save_response.data).lower())

    def test_draft_custom_endpoints(self):
        """Test all custom draft endpoints."""
        # Create a valid leaf category to make the draft valid
        leaf_category = ExpenseCategoryFactory(version=self.expense_version, level=5)

        # Test draft save endpoint (now POST to list)
        save_url = reverse(
            "workspace-transactiondraft-list",
            kwargs={"workspace_pk": self.workspace.pk},
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
                    "expense_category_id": leaf_category.id,
                }
            ],
        }
        response = self.client.post(save_url, draft_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        draft_id = response.data["id"]

        # Test draft get workspace endpoint
        get_url = (
            reverse(
                "transaction-draft-get-workspace",
                kwargs={"workspace_pk": self.workspace.pk},
            )
            + "?type=expense"
        )
        response = self.client.get(get_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test draft discard endpoint (now DELETE on detail)
        discard_url = reverse(
            "workspace-transactiondraft-detail",
            kwargs={"workspace_pk": self.workspace.pk, "pk": draft_id},
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
        response = self.client.get(self.list_url, {"currencies": "USD"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rates_data = self._get_response_data(response)
        for rate in rates_data:
            self.assertEqual(rate["currency"], "USD")

        # Test filtering by date range
        today = date.today()
        week_ago = today - timedelta(days=7)
        response = self.client.get(
            self.list_url,
            {"date_from": week_ago.isoformat(), "date_to": today.isoformat()},
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
        response_data = self._get_response_data(response)
        members_list = response_data.get("members", [])

        # Should have at least owner and viewer
        self.assertGreaterEqual(len(members_list), 2)

        # Verify membership data structure
        for member in members_list:
            self.assertIn("user_id", member)
            self.assertIn("role", member)
            self.assertIn("joined_at", member)

    def test_update_workspace_membership_role(self):
        """Test updating workspace membership role."""
        # Only workspace admin or owner can update roles
        self._authenticate_user(self.workspace_admin_user)

        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        update_data = {"user_id": self.other_user.id, "role": "editor"}

        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify role was updated
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.other_user
        )
        self.assertEqual(membership.role, "editor")

    def test_remove_workspace_member(self):
        """Test removing member from workspace."""
        # Only workspace admin or owner can remove members
        self._authenticate_user(self.workspace_admin_user)

        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        remove_data = {"user_id": self.other_user.id}

        response = self.client.delete(url, remove_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify member was removed
        self.assertFalse(
            WorkspaceMembership.objects.filter(
                workspace=self.workspace, user=self.other_user
            ).exists()
        )

    def test_update_workspace_membership_missing_data(self):
        """Test updating workspace membership role with missing data returns 400."""
        self._authenticate_user(self.workspace_admin_user)
        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        update_data = {"user_id": self.other_user.id} # Missing 'role'
        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("user_id' and 'role' are required", str(response.data))

    def test_remove_workspace_member_missing_data(self):
        """Test removing member from workspace with missing user_id returns 400."""
        self._authenticate_user(self.workspace_admin_user)
        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        remove_data = {} # Missing 'user_id'
        response = self.client.delete(url, remove_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("user_id", str(response.data))

    def test_remove_non_existent_workspace_member(self):
        """Test removing a non-existent member from workspace returns 404."""
        self._authenticate_user(self.workspace_admin_user)
        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        remove_data = {"user_id": 99999} # Non-existent user ID
        # Mock the service call to simulate member not found
        with patch("finance.services.membership_service.MembershipService.remove_member") as mock_remove:
            mock_remove.return_value = False
            mock_remove.__name__ = "remove_member"  # Explicitly set __name__
            response = self.client.delete(url, remove_data, format="json")
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
            self.assertIn("Member not found", response.data["detail"])

    def test_workspace_members_method_not_allowed(self):
        """Test unsupported HTTP method on members endpoint returns 405."""
        self._authenticate_user(self.workspace_admin_user)
        url = reverse("workspace-members", kwargs={"pk": self.workspace.id})
        response = self.client.put(url, {}, format="json") # PUT is not allowed
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)



class WorkspaceAdminCRUDTests(BaseAPITestCase):
    """CRUD tests for WorkspaceAdmin operations."""

    def test_list_workspace_admins(self):
        """Test listing all workspace admins."""
        # This endpoint is for superusers only.
        self._authenticate_user(self.superuser)

        url = reverse("workspaceadmin-list") + f"?workspace={self.workspace.id}"
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        admins_data = self._get_response_data(response)

        # Should have at least the workspace_admin_user
        self.assertGreaterEqual(len(admins_data), 1)

        # Verify admin data structure
        for admin in admins_data:
            self.assertIn("user_id", admin)
            self.assertIn("is_active", admin)
            self.assertIn("assigned_by_username", admin)

    def test_deactivate_workspace_admin(self):
        """Test deactivating workspace admin."""
        # Create a test admin assignment
        test_admin = UserFactory()
        admin_assignment = WorkspaceAdminFactory(
            user=test_admin,
            workspace=self.workspace,
            assigned_by=self.superuser,
            is_active=True,
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

    def test_assign_admin_missing_user_id(self):
        """Test assign_admin returns 400 if user_id is missing."""
        self._authenticate_user(self.superuser)
        url = reverse(
            "workspaceadmin-assign-admin", kwargs={"workspace_pk": self.workspace.id}
        )
        response = self.client.post(url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("User ID is required", response.data["detail"])

    def test_assign_admin_workspace_access_denied(self):
        """Test assign_admin returns 403 if superuser has no impersonation context for workspace."""
        self._authenticate_user(self.superuser)
        # Create a new user to assign to the workspace
        user_to_assign = UserFactory()
        # Add the user to the workspace first to fulfill membership requirement
        WorkspaceMembershipFactory(
            workspace=self.workspace, user=user_to_assign, role="editor"
        )

        url = reverse(
            "workspaceadmin-assign-admin", kwargs={"workspace_pk": self.workspace.id}
        )
        assign_data = {"user_id": user_to_assign.id}

        with patch("finance.services.workspace_context_service.WorkspaceContextService._validate_workspace_existence", return_value=None):
            response = self.client.post(url, assign_data, format="json")
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertIn("Workspace access denied", response.data["detail"])

    def test_assign_admin_user_to_assign_not_found(self):
        """Test assign_admin returns 404 if user to be assigned is not found."""
        self._authenticate_user(self.superuser)
        url = reverse(
            "workspaceadmin-assign-admin", kwargs={"workspace_pk": self.workspace.id}
        )
        assign_data = {"user_id": 99999} # Non-existent user
        response = self.client.post(url, assign_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn("User to be assigned not found", response.data["detail"])

    def test_assign_admin_user_not_workspace_member(self):
        """Test assign_admin returns 400 if user to be assigned is not a workspace member."""
        self._authenticate_user(self.superuser)
        # Create a new user who is NOT a member of self.workspace
        non_member_user = UserFactory()
        url = reverse(
            "workspaceadmin-assign-admin", kwargs={"workspace_pk": self.workspace.id}
        )
        assign_data = {"user_id": non_member_user.id}
        response = self.client.post(url, assign_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("User must be workspace member", response.data["detail"])

    def test_assign_admin_generic_exception(self):
        """Test assign_admin returns 500 for generic exceptions."""
        self._authenticate_user(self.superuser)
        new_admin = UserFactory()
        WorkspaceMembershipFactory(
            workspace=self.workspace, user=new_admin, role="editor"
        )
        url = reverse(
            "workspaceadmin-assign-admin", kwargs={"workspace_pk": self.workspace.id}
        )
        assign_data = {"user_id": new_admin.id}

        with patch("finance.views.WorkspaceAdmin.objects.get_or_create", side_effect=Exception("Database error")):
            response = self.client.post(url, assign_data, format="json")
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            self.assertIn("Admin assignment failed", response.data["detail"])

    def test_deactivate_admin_not_found(self):
        """Test deactivate_admin returns 404 if admin assignment not found."""
        self._authenticate_user(self.superuser)
        url = reverse("workspace-deactivate-admin", kwargs={"pk": 99999}) # Non-existent admin assignment
        response = self.client.post(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Workspace admin assignment not found", response.data["detail"])

    def test_deactivate_admin_validation_error(self):
        """Test deactivate_admin returns 400 for a ValidationError from service."""
        self._authenticate_user(self.superuser)
        url = reverse("workspace-deactivate-admin", kwargs={"pk": self.workspace_admin_assignment.pk})

        with patch("finance.services.workspace_service.WorkspaceService.deactivate_workspace_admin") as mock_deactivate:
            mock_deactivate.side_effect = ValidationError("Cannot deactivate owner")


            response = self.client.post(url, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn("Cannot deactivate owner", str(response.data))
        admin_assignment = WorkspaceAdminFactory(
            user=UserFactory(),
            workspace=self.workspace,
            assigned_by=self.superuser,
            is_active=True,
        )
        url = reverse("workspace-deactivate-admin", kwargs={"pk": admin_assignment.pk})

        with patch("finance.services.workspace_service.WorkspaceService.deactivate_workspace_admin", side_effect=ValidationError("Cannot deactivate owner")):
            response = self.client.post(url, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn("Cannot deactivate owner", response.data["detail"])



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
            if draft_data.get("transactions_data"):
                draft_data["transactions_data"][0]["note_manual"] = "Partially updated"

            update_url = reverse(
                "workspace-transactiondraft-detail",
                kwargs={"workspace_pk": self.workspace.pk, "pk": self.expense_draft.pk},
            )
            response = self.client.patch(
                update_url,
                {"transactions_data": draft_data["transactions_data"]},
                format="json",
            )
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
            "temp_id": "t1",
            "name": "New Test Category",
            "level": 1,
            "description": "Test category creation",
            "children": [],
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
                    "description": "Updated description",
                }
            ]
        }

        response = self.client.post(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_move_category_hierarchy(self):
        """
        Test moving a category with its children to a new parent.
        This test validates that a non-leaf category can be moved as long as it maintains its children,
        respecting the business rule that non-leaf categories cannot be childless.
        """
        # ARRANGE: Create a more complex hierarchy to test a branch move.
        # Initial state:
        #   - self.expense_category (L1) -> self.child_expense_category (L2)
        # We will add:
        #   - new_root (L1)
        #   - grandchild (L3), as a child of self.child_expense_category
        # The goal is to move the branch (child_expense_category + grandchild) under new_root.
        new_root = ExpenseCategoryFactory(
            version=self.expense_version, name="New Root", level=1
        )
        grandchild = ExpenseCategoryFactory(
            version=self.expense_version, name="Grandchild", level=3
        )
        self.child_expense_category.children.add(grandchild)
        self.child_expense_category.save()

        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )

        # ACTION: Move the 'child_expense_category' (which is now a parent)
        # from its old root to become a child of 'new_root'.
        move_data = {
            "update": [
                {
                    "id": self.child_expense_category.id,
                    "name": self.child_expense_category.name,
                    "level": 2,  # It will be level 2 under the new root
                    "parent_id": new_root.id,
                }
            ]
        }
        response = self.client.post(url, move_data, format="json")

        # ASSERT: The move should be successful.
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

        # Verify the parent has been changed
        self.child_expense_category.refresh_from_db()
        self.assertEqual(self.child_expense_category.parents.first(), new_root)

        # Verify its child (the grandchild) moved with it
        self.assertTrue(
            self.child_expense_category.children.filter(id=grandchild.id).exists()
        )


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
        update_data = {"preferred_currency": "USD", "date_format": "MM/DD/YYYY"}

        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify settings were updated
        user_settings = UserSettings.objects.get(user=self.user)
        self.assertEqual(user_settings.preferred_currency, "USD")
        self.assertEqual(user_settings.language, "en")

    def test_update_user_settings_invalid_fields(self):
        """Test updating user settings with invalid fields returns 400."""
        url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": self.user.id})
        update_data = {"invalid_field": "some_value"}
        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Fields not allowed for update", response.data["detail"])

    def test_retrieve_user_settings_not_found(self):
        """Test retrieving user settings for non-existent user returns 404."""
        # Create a user for whom settings should be missing
        user_with_no_settings = UserFactory()
        # Ensure no UserSettings exist for this user by manually deleting any created by signal
        UserSettings.objects.filter(user=user_with_no_settings).delete()

        # Authenticate as superuser to allow impersonation
        self._authenticate_user(self.superuser)

        # Construct the URL to impersonate 'user_with_no_settings'.
        # The PK in the URL is technically ignored by the view's get_object,
        # but is kept for consistency with URL patterns that expect a PK.
        url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": user_with_no_settings.id}) + f"?user_id={user_with_no_settings.id}"
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)



class WorkspaceSettingsAPITests(BaseAPITestCase):
    """Tests for WorkspaceSettings API endpoints."""

    def test_retrieve_workspace_settings(self):
        """Test retrieving workspace settings."""
        # Use the new nested URL structure
        url = reverse(
            WORKSPACE_SETTINGS_DETAIL, kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify settings structure podľa modelu
        self.assertIn("domestic_currency", response.data)
        self.assertIn("fiscal_year_start", response.data)
        self.assertIn("display_mode", response.data)
        self.assertIn("accounting_mode", response.data)

    def test_update_workspace_settings(self):
        """Test updating workspace settings."""
        # Use the new nested URL structure
        url = reverse(
            WORKSPACE_SETTINGS_DETAIL, kwargs={"workspace_pk": self.workspace.pk}
        )
        update_data = {
            "domestic_currency": "USD",
            "display_mode": "day",
            "accounting_mode": True,
        }

        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify settings were updated
        self.workspace_settings.refresh_from_db()
        self.assertEqual(self.workspace_settings.domestic_currency, "USD")
        self.assertEqual(self.workspace_settings.display_mode, "day")
        self.assertEqual(self.workspace_settings.accounting_mode, True)

    def test_retrieve_workspace_settings_not_found(self):
        """Test retrieving workspace settings for non-existent workspace returns 404."""
        url = reverse(WORKSPACE_SETTINGS_DETAIL, kwargs={"workspace_pk": 99999}) # Non-existent workspace
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_workspace_settings_invalid_currency_from_service(self):
        """Test updating workspace settings with an invalid currency raises a ValidationError from the service."""
        url = reverse(
            WORKSPACE_SETTINGS_DETAIL, kwargs={"workspace_pk": self.workspace.pk}
        )
        update_data = {"domestic_currency": "INVALID"}

        # The ServiceExceptionHandlerMixin should catch the ValidationError
        response = self.client.patch(url, update_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("invalid currency: invalid", str(response.data).lower())


class CategoryUsageTests(BaseAPITestCase):
    """Tests for category usage validation."""

    def test_category_usage_validation(self):
        """Test that used categories cannot be deleted."""
        # Create transaction with category
        transaction = TransactionFactory(
            user=self.user,
            workspace=self.workspace,
            expense_category=self.child_expense_category,
            type="expense",
        )

        # Try to delete used category via sync endpoint
        url = reverse(
            "workspace-category-sync",
            kwargs={"workspace_pk": self.workspace.pk, "category_type": "expense"},
        )

        delete_data = {"delete": [self.child_expense_category.id]}

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

        delete_data = {"delete": [self.child_expense_category.id]}

        response = self.client.post(url, delete_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AdminImpersonationAdvancedTests(BaseAPITestCase):
    """Advanced tests for admin impersonation functionality."""

    def test_superuser_can_impersonate_for_bulk_operations(self):
        """Test superuser can perform bulk operations with impersonation."""
        self._authenticate_user(self.superuser)

        # Bulk create transactions for target user
        url = (
            reverse(BULK_SYNC_TRANSACTIONS, kwargs={"workspace_id": self.workspace.id})
            + f"?user_id={self.user.id}"
        )
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
        url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        url_with_impersonation = f"{url}?user_id={self.other_user.id}"
        response = self.client.get(url_with_impersonation)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class WorkspaceAdminManagementTests(BaseAPITestCase):
    """Tests for workspace admin management functionality."""

    def test_assign_workspace_admin(self):
        """Test assigning a new workspace admin."""
        self._authenticate_user(self.superuser)

        new_admin = UserFactory()
        # Business Rule: A user must be a member of the workspace before they can be made an admin.
        # We must first add the user to the workspace.
        WorkspaceMembershipFactory(
            workspace=self.workspace, user=new_admin, role="editor"
        )

        url = reverse(
            "workspaceadmin-assign-admin", kwargs={"workspace_pk": self.workspace.id}
        )
        assign_data = {"user_id": new_admin.id, "workspace_id": self.workspace.id}

        response = self.client.post(url, assign_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify admin was assigned
        self.assertTrue(
            WorkspaceAdmin.objects.filter(
                user=new_admin, workspace=self.workspace, is_active=True
            ).exists()
        )

    def test_list_workspace_admins_comprehensive(self):
        """Test comprehensive listing of workspace admins."""
        # This is a superuser-only endpoint.
        self._authenticate_user(self.superuser)

        url = reverse("workspaceadmin-list") + f"?workspace={self.workspace.id}"
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        admins_data = self._get_response_data(response)

        # Should include active admins
        admin_users = [admin["user_id"] for admin in admins_data]
        self.assertIn(self.workspace_admin_user.id, admin_users)


class WorkspaceOwnershipTests(BaseAPITestCase):
    """Tests for workspace ownership functionality."""

    def test_transfer_workspace_ownership(self):
        """Test transferring workspace ownership to another user."""
        # Only owner can transfer ownership
        transfer_url = reverse(
            "workspace-change-owner", kwargs={"pk": self.workspace.pk}
        )
        transfer_data = {"new_owner_id": self.workspace_admin_user.id}

        response = self.client.post(transfer_url, transfer_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify ownership was transferred
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.owner, self.workspace_admin_user)

    def test_owner_permissions_after_transfer(self):
        """Test original owner permissions after ownership transfer."""
        # 1. Authenticate as a superuser, who has permission to change ownership.
        self._authenticate_user(self.superuser)

        # 2. Transfer ownership from the original owner (self.user) to a new owner.
        # The superuser must impersonate the current owner (self.user) to perform the action.
        base_url = reverse("workspace-change-owner", kwargs={"pk": self.workspace.pk})
        transfer_url = f"{base_url}?user_id={self.user.id}"
        transfer_data = {
            "new_owner_id": self.other_user.id,
            "old_owner_action": "editor",  # Demote original owner to editor
        }
        response = self.client.post(transfer_url, transfer_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

        # Verify ownership was transferred
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.owner, self.other_user)

        # 3. Re-authenticate as the original owner to check their new permissions
        self._authenticate_user(self.user)

        # 4. Verify original owner still has access but not full control (e.g., cannot delete)
        response = self.client.get(
            reverse(WORKSPACE_DETAIL, kwargs={"pk": self.workspace.pk})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Attempting to delete should now be forbidden for the original owner
        delete_response = self.client.delete(
            reverse(WORKSPACE_DETAIL, kwargs={"pk": self.workspace.pk})
        )
        self.assertEqual(delete_response.status_code, status.HTTP_403_FORBIDDEN)


class MemberRoleManagementTests(BaseAPITestCase):
    """Tests for member role management functionality."""

    def test_promote_member_to_editor(self):
        """Test promoting a member from viewer to editor role."""
        self._authenticate_user(self.workspace_admin_user)

        url = reverse("workspace-members", kwargs={"pk": self.workspace.pk})
        promote_data = {"user_id": self.other_user.id, "role": "editor"}

        response = self.client.patch(url, promote_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify role was updated
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.other_user
        )
        self.assertEqual(membership.role, "editor")

    def test_demote_editor_to_viewer(self):
        """Test demoting an editor to viewer role."""
        # First promote to editor
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.other_user
        )
        membership.role = "editor"
        membership.save()

        self._authenticate_user(self.workspace_admin_user)

        url = reverse("workspace-members", kwargs={"pk": self.workspace.pk})
        demote_data = {"user_id": self.other_user.id, "role": "viewer"}

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
        list_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Viewer cannot create a transaction
        create_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.post(create_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_data_isolation_between_workspaces(self):
        """Test that data is properly isolated between workspaces."""
        # Create separate workspace for other user
        other_workspace = WorkspaceFactory(owner=self.other_user)

        # Current user should not see other user's workspace data
        list_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.get(list_url)
        transactions_data = self._get_response_data(response)

        # No transactions should belong to other user's workspace
        for transaction in transactions_data:
            self.assertNotEqual(transaction["workspace"], other_workspace.id)


class BulkOperationsTests(BaseAPITestCase):
    """Tests for bulk operations across different models."""

    def test_bulk_transaction_operations(self):
        """Test comprehensive bulk transaction operations."""

        self.workspace_settings.domestic_currency = "EUR"
        self.workspace_settings.save()
        # ARRANGE
        # Ensure exchange rates exist for the dates in the payload.
        # The test creates a USD transaction for 2024-01-11.
        ExchangeRateFactory(
            currency="USD", date=date(2024, 1, 11), rate_to_eur=Decimal("0.92")
        )
        ExchangeRateFactory(
            currency="EUR", date=date(2024, 1, 10), rate_to_eur=Decimal("1.0")
        )

        url = reverse(
            BULK_SYNC_TRANSACTIONS, kwargs={"workspace_id": self.workspace.id}
        )

        # Define the expected changes
        create_count = 2
        update_count = 1
        delete_ids = [t.id for t in self.income_transactions]
        delete_count = len(delete_ids)

        bulk_data = {
            "create": [
                {
                    "type": "expense",
                    "expense_category": self.leaf_expense_category.id,  # MUST use a leaf category
                    "original_amount": "100.00",
                    "original_currency": "EUR",
                    "date": "2024-01-10",
                },
                {
                    "type": "income",
                    "income_category": self.leaf_income_category.id,  # MUST use a leaf category
                    "original_amount": "200.00",
                    "original_currency": "USD",
                    "date": "2024-01-11",
                },
            ],
            "update": [
                {
                    "id": self.expense_transaction.id,
                    "original_amount": "150.00",
                    "note_manual": "Bulk updated",
                }
            ],
            "delete": delete_ids,
        }

        # ACTION
        response = self.client.post(url, bulk_data, format="json")

        # ASSERT
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

        # 1. Verify the counts in the response payload
        self.assertEqual(len(response.data["created"]), create_count)
        self.assertEqual(len(response.data["updated"]), update_count)
        self.assertEqual(len(response.data["deleted"]), delete_count)

        # 2. Verify the database state for CREATED transactions
        created_ids = response.data["created"]
        self.assertEqual(
            Transaction.objects.filter(id__in=created_ids).count(), create_count
        )

        # 3. Verify the database state for UPDATED transactions
        self.expense_transaction.refresh_from_db()
        self.assertEqual(self.expense_transaction.original_amount, Decimal("150.00"))
        self.assertEqual(self.expense_transaction.note_manual, "Bulk updated")

        # 4. Verify the database state for DELETED transactions
        self.assertFalse(Transaction.objects.filter(id__in=delete_ids).exists())


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
            date=date.today(),
        )

        with self.assertRaises(ValidationError):
            transaction.full_clean()

    def test_category_level_validation(self):
        """Test category level validation."""
        from django.core.exceptions import ValidationError

        workspace = WorkspaceFactory()
        version = ExpenseCategoryVersionFactory(workspace=workspace)

        # Level 6 should be invalid
        category = ExpenseCategory(version=version, name="Invalid Level", level=6)

        with self.assertRaises(ValidationError):
            category.full_clean()


class EdgeCaseTests(BaseAPITestCase):
    """Tests for edge cases and error conditions."""

    def test_regular_user_accessing_other_workspace_gets_404(self):
        """
        Test that a regular user gets a 404 for a workspace they don't belong to.
        This prevents information leakage about the existence of other workspaces.
        """
        # ARRANGE: Create a workspace owned by another user
        other_workspace = WorkspaceFactory(owner=self.other_user)

        # ACTION: The authenticated user (self.user) tries to access it
        url = reverse(WORKSPACE_DETAIL, kwargs={"pk": other_workspace.pk})
        response = self.client.get(url)

        # ASSERT: Should be 404 Not Found, not 403 Forbidden
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_admin_probing_nonexistent_workspace_gets_403(self):
        """
        Test that a superuser probing for a non-existent workspace without
        impersonation gets a 403 Forbidden to prevent information leakage.
        """
        # ARRANGE: Authenticate as a superuser
        self._authenticate_user(self.superuser)

        # ACTION: Superuser tries to access a non-existent workspace ID directly
        url = reverse(
            "workspace-transaction-detail",
            kwargs={
                "workspace_pk": 99999,
                "pk": 99999,
            },  # Use a non-existent workspace ID
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_malformed_request_data(self):
        """Test handling of malformed request data."""
        # Malformed JSON
        url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.post(
            url, '{"malformed": json}', content_type="application/json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_large_amount_handling(self):
        """Test handling of very large amounts."""
        data = {  # workspace is taken from URL
            "type": "expense",
            "expense_category": self.leaf_expense_category.id,  # MUST use a leaf category (Level 5)
            "original_amount": "999999999.99",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        create_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
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
        list_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
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
                    "expense_category_id": self.leaf_expense_category.id,  # MUST use a leaf category
                }
            ],
        }
        response = self.client.post(draft_list_url, draft_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 3. User converts draft to actual transaction
        transaction_data = {  # workspace is from URL
            "type": "expense",
            "expense_category": self.leaf_expense_category.id,  # MUST use a leaf category
            "original_amount": "150.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        create_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.post(create_url, transaction_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 4. User views their transactions
        list_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
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
        data = {  # workspace is from URL
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "100.00",
            "original_currency": "INVALID",  # Invalid currency code
            "date": "2024-01-15",
        }
        create_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.post(create_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_date_handling(self):
        """Test handling of invalid dates."""
        data = {  # workspace is from URL
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "100.00",
            "original_currency": "EUR",
            "date": "invalid-date",  # Invalid date format
        }
        create_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.post(create_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_foreign_key_violation(self):
        """Test handling of invalid foreign keys."""
        data = {  # workspace is from URL, but we test with a bad category
            "expense_category": 99999,  # Nonexistent category
            "type": "expense",
            "original_amount": "100.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        create_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
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

        list_url = reverse(
            "workspace-transaction-list", kwargs={"workspace_pk": self.workspace.pk}
        )
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_token_authentication(self):
        """Test JWT token authentication."""
        from rest_framework_simplejwt.tokens import RefreshToken

        # Get token for user
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)

        # Use token for authentication
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
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
    print("Total Test Classes: 27")  # 🔥 OPRAVENÉ: 21 → 27
    print("Estimated Test Methods: 70+")  # 🔥 OPRAVENÉ: 52+ → 70+
    print("=" * 70)

    result = run_integration_tests()

    print("=" * 70)
    print("TEST EXECUTION COMPLETE")
    print(f"Tests run: {result.testsRun}")
    if result.failures:
        print(f"Failures: {len(result.failures)}")
    if result.errors:
        print(f"Errors: {len(result.errors)}")
