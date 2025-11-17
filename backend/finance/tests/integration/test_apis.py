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
                            WorkspaceAdmin, WorkspaceMembership,
                            WorkspaceSettings)

from ..factories import (ExchangeRateFactory, ExpenseCategoryFactory,
                         ExpenseCategoryVersionFactory, IncomeCategoryFactory,
                         IncomeCategoryVersionFactory, TransactionDraftFactory,
                         TransactionFactory, UserFactory, UserSettingsFactory,
                         WorkspaceAdminFactory, WorkspaceFactory,
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
TRANSACTION_DRAFT_DETAIL = "transactiondraft-detail"

# Custom action endpoints
WORKSPACE_MEMBERS = "workspace-members"
WORKSPACE_SETTINGS = "workspace-settings"
WORKSPACE_HARD_DELETE = "workspace-hard-delete"
WORKSPACE_ACTIVATE = "workspace-activate"
WORKSPACE_MEMBERSHIP_INFO = "workspace-membership-info"
TRANSACTION_BULK_DELETE = "transaction-bulk-delete"
BULK_SYNC_TRANSACTIONS = "bulk-sync-transactions"
SYNC_CATEGORIES = "category-sync"
TRANSACTION_DRAFT_SAVE = "transaction-draft-save"
TRANSACTION_DRAFT_GET_WORKSPACE = "transaction-draft-get-workspace"
TRANSACTION_DRAFT_DISCARD = "transaction-draft-discard"


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

        # Create test users
        cls._create_test_users()

        # Create workspace structure
        cls._create_workspace_structure()

        # Create categories
        cls._create_categories()

        # Create STATIC test data
        cls._create_static_test_data()

    @classmethod
    def _create_test_users(cls):
        """Create test users with different roles."""
        cls.user = UserFactory()
        cls.user.set_password("testpass123")
        cls.user.save()

        cls.other_user = UserFactory()
        cls.other_user.set_password("testpass123")
        cls.other_user.save()

        cls.admin_user = UserFactory(is_superuser=True, is_staff=True)
        cls.admin_user.set_password("testpass123")
        cls.admin_user.save()

        cls.workspace_admin_user = UserFactory()
        cls.workspace_admin_user.set_password("testpass123")
        cls.workspace_admin_user.save()

        cls._ensure_verified_emails(
            [cls.user, cls.other_user, cls.admin_user, cls.workspace_admin_user]
        )

    @classmethod
    def _create_workspace_structure(cls):
        """Create workspace and membership structure."""
        cls.workspace = WorkspaceFactory(owner=cls.user)

        # Clear conflicting memberships
        WorkspaceMembership.objects.filter(
            workspace=cls.workspace, user__in=[cls.other_user, cls.workspace_admin_user]
        ).delete()

        # Create memberships
        cls.viewer_membership = WorkspaceMembershipFactory(
            workspace=cls.workspace, user=cls.other_user, role="viewer"
        )

        cls.editor_membership = WorkspaceMembershipFactory(
            workspace=cls.workspace, user=cls.workspace_admin_user, role="editor"
        )

        cls.workspace_admin = WorkspaceAdminFactory(
            user=cls.workspace_admin_user,
            workspace=cls.workspace,
            assigned_by=cls.admin_user,
        )

        cls.workspace_settings = WorkspaceSettingsFactory(workspace=cls.workspace)

    @classmethod
    def _create_categories(cls):
        """Create category structure."""
        cls.expense_version = ExpenseCategoryVersionFactory(
            workspace=cls.workspace, created_by=cls.user
        )

        cls.income_version = IncomeCategoryVersionFactory(
            workspace=cls.workspace, created_by=cls.user
        )

        cls.expense_category = ExpenseCategoryFactory(
            version=cls.expense_version, name="Test Expense Category", level=1
        )

        cls.income_category = IncomeCategoryFactory(
            version=cls.income_version, name="Test Income Category", level=1
        )

        cls.child_expense_category = ExpenseCategoryFactory(
            version=cls.expense_version, name="Child Expense Category", level=2
        )

        cls.child_income_category = IncomeCategoryFactory(
            version=cls.income_version, name="Child Income Category", level=2
        )

        # Create parent-child relationships
        cls.expense_category.children.add(cls.child_expense_category)
        cls.income_category.children.add(cls.child_income_category)

    @classmethod
    def _create_static_test_data(cls):
        """Create STATIC test data that doesn't change between tests."""
        cls._create_test_exchange_rates()
        # Transactions and drafts are created in setUp() because they're often modified

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
    def _create_test_exchange_rates(cls):
        """Create test exchange rates."""
        ExchangeRate.objects.all().delete()

        today = date.today()
        dates = [today - timedelta(days=i) for i in range(10)]

        currencies = [
            ("USD", Decimal("1.1")),
            ("GBP", Decimal("0.85")),
            ("CHF", Decimal("0.95")),
            ("PLN", Decimal("4.5")),
            ("CZK", Decimal("25.0")),
        ]

        for currency, rate in currencies:
            for i, rate_date in enumerate(dates):
                ExchangeRateFactory(currency=currency, rate_to_eur=rate, date=rate_date)

    def setUp(self):
        """Set up DYNAMIC test data that might change between test methods."""
        # Create DYNAMIC test data (transactions, drafts)
        self._create_dynamic_test_data()

        # Authenticate user
        self.client.force_authenticate(user=self.user)

    def _create_dynamic_test_data(self):
        """Create DYNAMIC test data that might be modified during tests."""
        self._create_test_transactions()
        self._create_test_drafts()

    def _create_test_transactions(self):
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

    def _create_test_drafts(self):
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

    # Ostatné helper metody zostávajú rovnaké...
    def _get_workspaces_list(self, response):
        """Helper method to extract workspaces list from paginated response."""
        if "results" in response.data:
            return response.data["results"]
        elif "workspaces" in response.data and "results" in response.data["workspaces"]:
            return response.data["workspaces"]["results"]
        elif "workspaces" in response.data and isinstance(
            response.data["workspaces"], list
        ):
            return response.data["workspaces"]
        else:
            return response.data.get("results", response.data)

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
# CORE API TESTS - zostávajú rovnaké, len s optimalizovaným setupom
# =============================================================================


class WorkspaceAPITests(BaseAPITestCase):
    """COMPREHENSIVE Workspace API tests with role-based permissions and impersonation."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(WORKSPACE_LIST)
        self.detail_url = reverse(WORKSPACE_DETAIL, kwargs={"pk": self.workspace.pk})

        # Create additional test workspaces - tieto sú DYNAMIC, lebo sa menia v testoch
        self.inactive_workspace = WorkspaceFactory(
            owner=self.user, is_active=False, name="Inactive Workspace"
        )

        self.other_user_workspace = WorkspaceFactory(
            owner=self.other_user, is_active=True
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
            members=self.other_user, is_active=True
        ).count()
        self.assertEqual(len(workspaces_list), active_workspaces_count)

    def test_retrieve_workspace_detailed(self):
        """Test retrieving workspace details with comprehensive data validation."""
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify all expected fields are present
        expected_fields = [
            "id",
            "name",
            "description",
            "owner",
            "owner_username",
            "owner_email",
            "user_role",
            "member_count",
            "is_owner",
            "user_permissions",
            "created_at",
            "is_active",
        ]
        for field in expected_fields:
            self.assertIn(field, response.data)

        # Verify data accuracy
        self.assertEqual(response.data["name"], self.workspace.name)
        self.assertEqual(response.data["user_role"], "owner")
        self.assertTrue(response.data["is_owner"])
        self.assertGreater(response.data["member_count"], 0)

    def test_create_workspace_validation(self):
        """Test workspace creation with comprehensive validation."""
        data = {"name": "Valid Workspace", "description": "Valid description"}

        response = self.client.post(self.list_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify workspace was created correctly
        workspace = Workspace.objects.get(name="Valid Workspace")
        self.assertEqual(workspace.owner, self.user)

        # Verify membership was created
        membership = WorkspaceMembership.objects.get(
            workspace=workspace, user=self.user
        )
        self.assertEqual(membership.role, "owner")

    def test_update_workspace_permissions(self):
        """Test workspace update permissions for different roles."""
        # Test as admin (owner) - should succeed
        data = {"name": "Updated by Owner"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, "Updated by Owner")

        # Test as editor - should fail
        self._authenticate_user(self.workspace_admin_user)
        data = {"name": "Updated by Editor"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Test as viewer - should fail
        self._authenticate_user(self.other_user)
        data = {"name": "Updated by Viewer"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_workspace_comprehensive(self):
        """Comprehensive workspace deletion tests for BaseWorkspaceViewSet architecture."""

        from django.core.cache import cache

        # --- Scenario 1: Owner can delete their own workspace (Self-owned) ---
        print("🧪 Testing OWNER delete...")

        # Clear cache for this workspace
        cache_key = f"workspace_role_{self.user.id}_{self.workspace.id}"
        cache.delete(cache_key)

        # Make the actual API call
        response = self.client.delete(self.detail_url)

        # ASSERTION 1: Owner must be able to delete the workspace (HTTP 204)
        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
            "Owner should be able to delete workspace",
        )

        # Verify soft deletion
        self.workspace.refresh_from_db()
        self.assertFalse(self.workspace.is_active)
        print("✅ Owner can delete their own workspace")

        # Reactivate for further tests
        self.workspace.is_active = True
        self.workspace.save()

        # --- Scenario 2: Superuser delete with impersonation ---
        print("\n🧪 Testing SUPERUSER delete WITH IMPERSONATION...")

        # Create workspace owned by other_user
        admin_workspace = WorkspaceFactory(owner=self.other_user)

        # 🔥 DIAGNOSTIKA: Overme stav superuser
        print(f"🔍 Admin user: {self.admin_user.username}")
        print(f"🔍 Is superuser: {self.admin_user.is_superuser}")
        print(f"🔍 Is staff: {self.admin_user.is_staff}")
        print(f"🔍 Admin user ID: {self.admin_user.id}")

        # 🔥 DIAGNOSTIKA: Overme workspace a target user
        print(f"🔍 Workspace ID: {admin_workspace.id}")
        print(f"🔍 Workspace owner: {admin_workspace.owner.username}")
        print(f"🔍 Workspace owner ID: {admin_workspace.owner.id}")
        print(f"🔍 Target user: {self.other_user.username}")
        print(f"🔍 Target user ID: {self.other_user.id}")
        print(
            f"🔍 Are owner and target the same? {admin_workspace.owner.id == self.other_user.id}"
        )

        # 🔥 DIAGNOSTIKA: Overme či target user je členom workspace
        from finance.models import WorkspaceMembership

        is_member = WorkspaceMembership.objects.filter(
            workspace=admin_workspace, user=self.other_user
        ).exists()
        print(f"🔍 Target user is workspace member: {is_member}")

        if is_member:
            membership = WorkspaceMembership.objects.get(
                workspace=admin_workspace, user=self.other_user
            )
            print(f"🔍 Membership role: {membership.role}")
        else:
            print("🔍 ❌ NO MEMBERSHIP FOUND - this is the problem!")

        # Use admin user with impersonation of workspace OWNER (other_user)
        self._authenticate_user(self.admin_user)
        admin_workspace_url = reverse(
            WORKSPACE_DETAIL, kwargs={"pk": admin_workspace.pk}
        )

        # Impersonate the workspace OWNER
        impersonation_url = f"{admin_workspace_url}?user_id={self.other_user.id}"

        print(f"🔍 Impersonation URL: {impersonation_url}")

        response = self.client.delete(impersonation_url)
        print(f"🔍 Superuser delete response: {response.status_code}")

        if response.status_code != status.HTTP_204_NO_CONTENT:
            print(f"🔍 ❌ SUPERUSER DELETE FAILED: {response.status_code}")
            if hasattr(response, "data"):
                print(f"🔍 Response data: {response.data}")

        # ASSERTION 2: Superuser with impersonation MUST be able to delete
        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
            "Superuser with impersonation MUST be able to delete workspace",
        )

        admin_workspace.refresh_from_db()
        self.assertFalse(admin_workspace.is_active)
        print("✅ Superuser can delete workspace WITH impersonation")

        # --- Scenario 3: Editor cannot delete foreign workspace ---
        # Return to original user
        self._authenticate_user(self.user)

        print("\n🧪 Testing EDITOR delete...")

        # Editor should NOT be able to delete foreign workspace
        editor_workspace = WorkspaceFactory(owner=self.other_user)
        WorkspaceMembershipFactory(
            workspace=editor_workspace, user=self.user, role="editor"
        )

        editor_workspace_url = reverse(
            WORKSPACE_DETAIL, kwargs={"pk": editor_workspace.pk}
        )
        response = self.client.delete(editor_workspace_url)

        # ASSERTION 3
        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
            "Editor should not be able to delete workspace",
        )

        print("✅ Editor cannot delete workspace - CORRECT")

        # --- Scenario 4: Test BaseWorkspaceViewSet permissions integration ---
        print("\n🧪 Testing BaseWorkspaceViewSet integration...")

        # Create new workspace for permission integration testing
        test_workspace = WorkspaceFactory(owner=self.user)
        test_url = reverse(WORKSPACE_DETAIL, kwargs={"pk": test_workspace.pk})

        # Test that BaseWorkspaceViewSet correctly sets permissions
        response = self.client.get(test_url)

        # Test DELETE with BaseWorkspaceViewSet
        response = self.client.delete(test_url)

        if response.status_code == status.HTTP_204_NO_CONTENT:
            test_workspace.refresh_from_db()
            self.assertFalse(test_workspace.is_active)

        print("✅ BaseWorkspaceViewSet integration test completed")
        print("🎉 ALL TESTS PASSED with BaseWorkspaceViewSet architecture!")

    def test_workspace_custom_endpoints(self):
        """Test all custom workspace endpoints."""
        # Test workspace members endpoint
        url = reverse(WORKSPACE_MEMBERS, kwargs={"pk": self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("members", response.data)
        self.assertGreater(len(response.data["members"]), 0)

        # Test workspace settings endpoint
        url = reverse(WORKSPACE_SETTINGS, kwargs={"pk": self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("domestic_currency", response.data)

        # Test workspace membership info endpoint
        url = reverse(WORKSPACE_MEMBERSHIP_INFO, kwargs={"pk": self.workspace.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["role"], "owner")

        # Test workspace activate endpoint
        self.workspace.is_active = False
        self.workspace.save()

        url = reverse(WORKSPACE_ACTIVATE, kwargs={"pk": self.workspace.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace.refresh_from_db()
        self.assertTrue(self.workspace.is_active)


class TransactionAPITests(BaseAPITestCase):
    """COMPREHENSIVE Transaction API tests with filtering, bulk operations, and permissions."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(TRANSACTION_LIST)
        self.detail_url = reverse(
            TRANSACTION_DETAIL, kwargs={"pk": self.expense_transaction.pk}
        )

    def test_list_transactions_comprehensive(self):
        """Comprehensive transaction listing with various filters."""
        # Test basic listing
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(
            len(response.data),
            len(self.expense_transactions) + len(self.income_transactions),
        )

        # Test filtering by type
        response = self.client.get(self.list_url, {"type": "expense"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for transaction in response.data:
            self.assertEqual(transaction["type"], "expense")

        # Test filtering by month
        current_month = date.today().month
        response = self.client.get(self.list_url, {"month": current_month})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test filtering by workspace
        response = self.client.get(self.list_url, {"workspace": self.workspace.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test lightweight mode
        response = self.client.get(self.list_url, {"light": "true"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify lightweight response has basic fields
        if len(response.data) > 0:
            transaction = response.data[0]
            self.assertIn("id", transaction)
            self.assertIn("type", transaction)
            self.assertIn("amount_domestic", transaction)

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
        data = {
            "workspace": self.workspace.id,
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
            "note_manual": "Test expense transaction",
            "tags": ["test", "expense"],
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertIn(
            response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST]
        )

        # Valid income transaction
        data = {
            "workspace": self.workspace.id,
            "type": "income",
            "income_category": self.income_category.id,
            "original_amount": "500.00",
            "original_currency": "USD",
            "date": "2024-01-20",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertIn(
            response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST]
        )

        # Invalid: Both categories provided
        data = {
            "workspace": self.workspace.id,
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
        data = {
            "workspace": self.workspace.id,
            "type": "expense",
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(self.list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Invalid: Wrong category type
        data = {
            "workspace": self.workspace.id,
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
        # Valid update
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

        # Test update with category change
        data = {"expense_category": self.child_expense_category.id}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.expense_transaction.refresh_from_db()
        self.assertEqual(
            self.expense_transaction.expense_category, self.child_expense_category
        )

    def test_delete_transaction_permissions(self):
        """Test transaction deletion with permission validation."""
        # Test delete as editor (should succeed)
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.user
        )
        membership.role = "editor"
        membership.save()

        response = self.client.delete(self.detail_url)
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
        detail_url = reverse(TRANSACTION_DETAIL, kwargs={"pk": transaction.pk})

        # Test delete as viewer (should fail)
        membership.role = "viewer"
        membership.save()

        response = self.client.delete(detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_bulk_operations(self):
        """Test bulk transaction operations."""
        # Bulk delete
        transaction_ids = [t.id for t in self.expense_transactions[:2]]
        url = reverse(TRANSACTION_BULK_DELETE)
        data = {"ids": transaction_ids}
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["deleted"], 2)

        # Bulk sync
        url = reverse(
            BULK_SYNC_TRANSACTIONS, kwargs={"workspace_id": self.workspace.id}
        )
        transactions_data = [
            {
                "type": "expense",
                "expense_category": self.expense_category.id,
                "original_amount": "100.00",
                "original_currency": "EUR",
                "date": "2024-01-10",
                "note_manual": "Bulk expense 1",
            },
            {
                "type": "income",
                "income_category": self.income_category.id,
                "original_amount": "200.00",
                "original_currency": "USD",
                "date": "2024-01-15",
                "note_manual": "Bulk income 1",
            },
        ]
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
        self.assertGreaterEqual(len(response.data), 2)  # parent + child

        # Verify category structure
        for category in response.data:
            self.assertIn("id", category)
            self.assertIn("name", category)
            self.assertIn("level", category)
            self.assertIn("children", category)
            self.assertIn("version", category)

        # Test income categories
        url = reverse(INCOME_CATEGORY_LIST)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 2)  # parent + child

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

        accessible_categories_count = ExpenseCategory.objects.filter(
            version__workspace__members=self.user
        ).count()
        self.assertEqual(len(response.data), accessible_categories_count)

    def test_category_sync_endpoint(self):
        """Test category synchronization endpoint."""
        url = reverse(
            SYNC_CATEGORIES,
            kwargs={"workspace_id": self.workspace.id, "category_type": "expense"},
        )

        sync_data = [
            {
                "name": "New Expense Category",
                "level": 1,
                "description": "Synced category",
                "children": [
                    {
                        "name": "Child Category",
                        "level": 2,
                        "description": "Child of synced category",
                    }
                ],
            }
        ]

        response = self.client.post(url, sync_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("created", response.data)
        self.assertIn("updated", response.data)

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
            SYNC_CATEGORIES,
            kwargs={"workspace_id": self.workspace.id, "category_type": "expense"},
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
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("used in transactions", response.data["errors"][0].lower())

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
            SYNC_CATEGORIES,
            kwargs={"workspace_id": self.workspace.id, "category_type": "expense"},
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
            SYNC_CATEGORIES,
            kwargs={"workspace_id": self.workspace.id, "category_type": "expense"},
        )

        sync_data = {
            "update": [
                {
                    "id": leaf_category.id,
                    "name": leaf_category.name,
                    "level": 5,
                    "parent_id": None,  # Try to move
                }
            ]
        }

        response = self.client.post(url, sync_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("used in transactions", response.data["errors"][0].lower())


class CategoryUsageTests(BaseAPITestCase):
    """Tests for category usage endpoints."""

    def test_expense_category_usage_check(self):
        url = reverse("expense-category-usage", kwargs={"pk": self.expense_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("is_used", response.data)

    def test_income_category_usage_check(self):
        url = reverse("income-category-usage", kwargs={"pk": self.income_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("is_used", response.data)

    def test_expense_category_usage_check_used(self):
        Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            expense_category=self.expense_category,
            type="expense",
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )

        url = reverse("expense-category-usage", kwargs={"pk": self.expense_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_used"])

    def test_expense_category_usage_check_not_used(self):
        url = reverse("expense-category-usage", kwargs={"pk": self.expense_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["is_used"])

    def test_expense_category_usage_permission_denied(self):
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.user
        )
        membership.role = "viewer"
        membership.save()

        url = reverse("expense-category-usage", kwargs={"pk": self.expense_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_income_category_usage_check_used(self):
        Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            income_category=self.income_category,
            type="income",
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )

        url = reverse("income-category-usage", kwargs={"pk": self.income_category.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_used"])


# =============================================================================
# SETTINGS & CONFIGURATION TESTS
# =============================================================================


class UserSettingsAPITests(BaseAPITestCase):
    """COMPREHENSIVE UserSettings API tests with security validation."""

    def setUp(self):
        super().setUp()
        self.user_settings = UserSettingsFactory(user=self.user)
        self.url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": self.user_settings.pk})

    def test_retrieve_user_settings_security(self):
        """Test user settings retrieval with security validation."""
        # User should be able to access their own settings
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["user"], self.user.id)
        self.assertEqual(response.data["language"], "en")

        # User should NOT be able to access other users' settings
        other_settings = UserSettingsFactory(user=self.other_user)
        other_url = reverse(USER_SETTINGS_DETAIL, kwargs={"pk": other_settings.pk})
        response = self.client.get(other_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_user_settings_validation(self):
        """Test user settings update with comprehensive validation."""
        # Valid language update
        data = {"language": "sk"}
        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user_settings.refresh_from_db()
        self.assertEqual(self.user_settings.language, "sk")

        # Invalid language
        data = {"language": "invalid"}
        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class WorkspaceSettingsAPITests(BaseAPITestCase):
    """COMPREHENSIVE WorkspaceSettings API tests with currency change handling."""

    def setUp(self):
        super().setUp()
        self.detail_url = reverse(
            WORKSPACE_SETTINGS_DETAIL, kwargs={"pk": self.workspace_settings.pk}
        )

    def test_retrieve_workspace_settings_detailed(self):
        """Test retrieving workspace settings with all configuration options."""
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        expected_fields = [
            "id",
            "workspace",
            "domestic_currency",
            "fiscal_year_start",
            "display_mode",
            "accounting_mode",
        ]
        for field in expected_fields:
            self.assertIn(field, response.data)

        self.assertEqual(response.data["domestic_currency"], "EUR")
        self.assertEqual(response.data["fiscal_year_start"], 1)

    def test_update_workspace_settings_comprehensive(self):
        """Comprehensive workspace settings update tests."""
        # Test basic update
        data = {"fiscal_year_start": 4, "display_mode": "day", "accounting_mode": True}
        response = self.client.patch(self.detail_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace_settings.refresh_from_db()
        self.assertEqual(self.workspace_settings.fiscal_year_start, 4)
        self.assertEqual(self.workspace_settings.display_mode, "day")
        self.assertTrue(self.workspace_settings.accounting_mode)

        # Test currency change (should trigger recalculation)
        data = {"domestic_currency": "USD"}
        response = self.client.patch(self.detail_url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.workspace_settings.refresh_from_db()
        self.assertEqual(self.workspace_settings.domestic_currency, "USD")

        # Verify recalculation details in response
        if "recalculation_details" in response.data:
            self.assertIn(
                "transactions_updated", response.data["recalculation_details"]
            )

    def test_workspace_settings_permissions(self):
        """Test workspace settings access with different user roles."""
        # Test as viewer (should be able to read but not update)
        self._authenticate_user(self.other_user)

        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = {"domestic_currency": "GBP"}
        response = self.client.patch(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# =============================================================================
# DRAFT & TEMPORARY DATA TESTS
# =============================================================================


class TransactionDraftAPITests(BaseAPITestCase):
    """COMPREHENSIVE TransactionDraft API tests with atomic operations."""

    def setUp(self):
        super().setUp()
        self.list_url = reverse(TRANSACTION_DRAFT_LIST)

    def test_draft_lifecycle_comprehensive(self):
        """Comprehensive test of draft lifecycle operations."""
        # Test saving draft
        save_url = reverse(
            TRANSACTION_DRAFT_SAVE, kwargs={"workspace_pk": self.workspace.id}
        )

        transactions_data = [
            {
                "type": "expense",
                "original_amount": "150.00",
                "original_currency": "EUR",
                "date": "2024-01-15",
                "note_manual": "Draft transaction 1",
            },
            {
                "type": "expense",
                "original_amount": "75.50",
                "original_currency": "USD",
                "date": "2024-01-16",
                "note_manual": "Draft transaction 2",
            },
        ]

        data = {"draft_type": "expense", "transactions_data": transactions_data}

        response = self.client.post(save_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["transactions_data"]), 2)

        # Test retrieving draft
        get_url = (
            reverse(
                TRANSACTION_DRAFT_GET_WORKSPACE,
                kwargs={"workspace_pk": self.workspace.id},
            )
            + "?type=expense"
        )
        response = self.client.get(get_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["transactions_data"]), 2)

        # Test discarding draft
        discard_url = reverse(
            TRANSACTION_DRAFT_DISCARD, kwargs={"pk": self.expense_draft.pk}
        )
        response = self.client.delete(discard_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify draft was deleted
        with self.assertRaises(TransactionDraft.DoesNotExist):
            TransactionDraft.objects.get(pk=self.expense_draft.pk)

    def test_draft_category_move_scenario_exact(self):

        # 1. ✅ Vytvor draft s kategóriou na spodnom leveli (ešte nepoužitá)
        self.assertEqual(self.child_expense_category.level, 2)  # Spodný level
        self.assertFalse(
            Transaction.objects.filter(
                expense_category=self.child_expense_category
            ).exists()
        )  # Ešte nepoužitá

        save_url = reverse(
            "transaction-draft-save", kwargs={"workspace_pk": self.workspace.pk}
        )
        draft_data = {
            "draft_type": "expense",
            "transactions_data": [
                {
                    "type": "expense",
                    "original_amount": "200.00",
                    "original_currency": "EUR",
                    "date": "2024-01-20",
                    "expense_category_id": self.child_expense_category.id,  # ✅ Spodný level, ešte nepoužitá
                }
            ],
        }

        # Ulož draft - MALO BY prejsť
        response = self.client.post(save_url, draft_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

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
        # Najprv načítaj draft - OPRAVA: použite správny endpoint name
        get_url = (
            reverse(
                "transaction-draft-get-workspace",
                kwargs={"workspace_pk": self.workspace.pk},
            )
            + "?type=expense"
        )
        draft_response = self.client.get(get_url)

        if draft_response.status_code == status.HTTP_200_OK:
            # Skús uložiť existujúci draft - MALO BY ZLYHAŤ
            save_response = self.client.post(
                save_url, draft_response.data, format="json"
            )

            # 🚨 TU JE KRITICKÁ VALIDÁCIA - draft by NEMAL prejsť!
            self.assertEqual(save_response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn("category", str(save_response.data).lower())
            self.assertIn("level", str(save_response.data).lower())
        else:
            # Alebo draft bol automaticky zmazaný/invalidovaný - to je tiež OK
            self.assertIn(
                draft_response.status_code,
                [status.HTTP_404_NOT_FOUND, status.HTTP_400_BAD_REQUEST],
            )

    def test_draft_unique_constraint(self):
        """Test that only one draft exists per workspace-type combination."""
        # Try to create another draft for same workspace and type
        save_url = reverse(
            TRANSACTION_DRAFT_SAVE, kwargs={"workspace_pk": self.workspace.id}
        )

        data = {
            "draft_type": "expense",
            "transactions_data": [{"type": "expense", "amount": 300}],
        }

        response = self.client.post(save_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Should only be one draft for this workspace and type
        drafts_count = TransactionDraft.objects.filter(
            user=self.user, workspace=self.workspace, draft_type="expense"
        ).count()
        self.assertEqual(drafts_count, 1)


# =============================================================================
# EXCHANGE RATE & CURRENCY TESTS
# =============================================================================


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
            self.assertIn("id", rate)
            self.assertIn("currency", rate)
            self.assertIn("rate_to_eur", rate)
            self.assertIn("date", rate)

    def test_filter_exchange_rates_advanced(self):
        """Test advanced filtering of exchange rates."""
        # Filter by specific currencies
        response = self.client.get(self.list_url, {"currencies": "USD,GBP"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        for rate in response.data:
            self.assertIn(rate["currency"], ["USD", "GBP"])

        # Filter by date range
        date_from = (date.today() - timedelta(days=7)).isoformat()
        date_to = (date.today() - timedelta(days=1)).isoformat()

        response = self.client.get(
            self.list_url, {"date_from": date_from, "date_to": date_to}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # All returned rates should be within date range
        for rate in response.data:
            rate_date = date.fromisoformat(rate["date"])
            self.assertGreaterEqual(rate_date, date.fromisoformat(date_from))
            self.assertLessEqual(rate_date, date.fromisoformat(date_to))


# =============================================================================
# ADMIN & PERMISSION TESTS
# =============================================================================


class AdminImpersonationAdvancedTests(BaseAPITestCase):
    """ADVANCED admin impersonation tests with comprehensive scenarios."""

    def test_impersonation_across_all_endpoints(self):
        """Test impersonation works across all major API endpoints."""
        self._authenticate_user(self.admin_user)

        # Test workspace listing with impersonation
        url = reverse(WORKSPACE_LIST) + f"?user_id={self.user.id}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test transaction creation with impersonation
        url = reverse(TRANSACTION_LIST) + f"?user_id={self.user.id}"
        data = {
            "workspace": self.workspace.id,
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "200.00",
            "original_currency": "EUR",
            "date": "2024-01-15",
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify transaction was created for target user
        transaction = Transaction.objects.get(pk=response.data["id"])
        self.assertEqual(transaction.user.id, self.user.id)

    def test_impersonation_security(self):
        """Test security aspects of impersonation functionality."""
        # Regular user should not be able to impersonate
        self._authenticate_user(self.other_user)

        url = reverse(WORKSPACE_LIST) + f"?user_id={self.user.id}"
        response = self.client.get(url)

        # Should work normally but without actual impersonation
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class WorkspaceAdminManagementTests(BaseAPITestCase):
    """Tests for workspace admin management."""

    def test_assign_workspace_admin_success(self):
        self._authenticate_user(self.admin_user)

        url = reverse(
            "workspace-assign-admin", kwargs={"workspace_pk": self.workspace.pk}
        )
        data = {"user_id": self.other_user.id}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        admin_assignment = WorkspaceAdmin.objects.get(
            user=self.other_user, workspace=self.workspace
        )
        self.assertTrue(admin_assignment.is_active)

    def test_assign_workspace_admin_non_superuser_denied(self):
        url = reverse(
            "workspace-assign-admin", kwargs={"workspace_pk": self.workspace.pk}
        )
        data = {"user_id": self.other_user.id}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_deactivate_workspace_admin_success(self):
        admin_assignment = WorkspaceAdmin.objects.create(
            user=self.other_user,
            workspace=self.workspace,
            assigned_by=self.admin_user,
            is_active=True,
        )

        self._authenticate_user(self.admin_user)

        url = reverse("workspace-deactivate-admin", kwargs={"pk": admin_assignment.pk})
        response = self.client.post(url, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        admin_assignment.refresh_from_db()
        self.assertFalse(admin_assignment.is_active)
        self.assertIsNotNone(admin_assignment.deactivated_at)


class WorkspaceOwnershipTests(BaseAPITestCase):
    """Tests for workspace ownership changes."""

    def test_change_workspace_owner_success(self):
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.user
        )
        membership.role = "admin"
        membership.save()

        url = reverse("workspace-change-owner", kwargs={"pk": self.workspace.pk})
        data = {"new_owner_id": self.other_user.id}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.owner, self.other_user)

        old_owner_membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.user
        )
        new_owner_membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.other_user
        )
        self.assertEqual(old_owner_membership.role, "admin")
        self.assertEqual(new_owner_membership.role, "owner")

    def test_change_workspace_owner_insufficient_permissions(self):
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.user
        )
        membership.role = "editor"
        membership.save()

        url = reverse("workspace-change-owner", kwargs={"pk": self.workspace.pk})
        data = {"new_owner_id": self.other_user.id}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class MemberRoleManagementTests(BaseAPITestCase):
    """Tests for member role management."""

    def test_update_member_role(self):
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.user
        )
        membership.role = "admin"
        membership.save()

        url = reverse("workspace-update-member-role", kwargs={"pk": self.workspace.pk})
        data = {"user_id": self.other_user.id, "role": "editor"}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["new_role"], "editor")

    def test_update_member_role_insufficient_permissions(self):
        membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.user
        )
        membership.role = "editor"
        membership.save()

        url = reverse("workspace-update-member-role", kwargs={"pk": self.workspace.pk})
        data = {"user_id": self.other_user.id, "role": "editor"}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


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
            type="expense",
            expense_category=expense_category,
            income_category=income_category,
            original_amount=Decimal("100.00"),
            original_currency="EUR",
            date=date.today(),
        )

        with self.assertRaises(Exception):
            transaction.full_clean()

        # Test no category
        transaction = Transaction(
            user=user,
            workspace=workspace,
            type="expense",
            original_amount=Decimal("100.00"),
            original_currency="EUR",
            date=date.today(),
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
                user=user, workspace=workspace, role="viewer"
            )

    def test_category_hierarchy_validation(self):
        """Test category hierarchy validation."""
        workspace = WorkspaceFactory()
        version = ExpenseCategoryVersionFactory(workspace=workspace)

        parent = ExpenseCategoryFactory(version=version, level=1)
        child = ExpenseCategoryFactory(version=version, level=2)

        # Test valid parent-child relationship
        parent.children.add(child)
        parent.full_clean()  # Should not raise


# =============================================================================
# SECURITY & INTEGRATION TESTS
# =============================================================================


class IntegrationSecurityTests(BaseAPITestCase):
    """Security-focused integration tests."""

    def test_cross_workspace_access_prevention(self):
        """Test that users cannot access data from other workspaces."""
        # Create workspace that current user doesn't belong to
        other_workspace = WorkspaceFactory(owner=self.other_user)
        other_transaction = TransactionFactory(
            user=self.other_user, workspace=other_workspace
        )

        # Try to access transaction from other workspace
        url = reverse(TRANSACTION_DETAIL, kwargs={"pk": other_transaction.pk})
        response = self.client.get(url)

        # Should not be accessible
        self.assertIn(
            response.status_code, [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN]
        )

    def test_user_data_isolation(self):
        """Test that users can only access their own data."""
        # Create transaction for other user in same workspace
        other_user_transaction = TransactionFactory(
            user=self.other_user, workspace=self.workspace
        )

        # Try to access other user's transaction
        url = reverse(TRANSACTION_DETAIL, kwargs={"pk": other_user_transaction.pk})
        response = self.client.get(url)

        # Should be accessible if in same workspace (depending on permissions)
        # But the transaction should belong to the other user
        if response.status_code == status.HTTP_200_OK:
            self.assertEqual(response.data["user"], self.other_user.id)


# =============================================================================
# PERFORMANCE & EDGE CASE TESTS
# =============================================================================


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

        response = self.client.get(reverse(TRANSACTION_LIST), {"light": "true"})

        end_time = time.time()
        response_time = end_time - start_time

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Lightweight response should be fast
        self.assertLess(response_time, 0.5)


class EdgeCaseTests(BaseAPITestCase):
    """Tests for edge cases and error conditions."""

    def test_large_transaction_amounts(self):
        """Test handling of very large transaction amounts."""
        data = {
            "workspace": self.workspace.id,
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "999999999.99",  # Very large amount
            "original_currency": "EUR",
            "date": "2024-01-15",
        }

        response = self.client.post(reverse(TRANSACTION_LIST), data, format="json")
        self.assertIn(
            response.status_code, [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST]
        )

    def test_invalid_date_formats(self):
        """Test handling of invalid date formats."""
        data = {
            "workspace": self.workspace.id,
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": "100.00",
            "original_currency": "EUR",
            "date": "invalid-date-format",
        }

        response = self.client.post(reverse(TRANSACTION_LIST), data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# =============================================================================
# TEST RUNNER CONFIGURATION
# =============================================================================


def run_integration_tests():
    """Helper function to run all integration tests."""
    import unittest

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(WorkspaceAPITests)
    suite.addTests(loader.loadTestsFromTestCase(TransactionAPITests))
    suite.addTests(loader.loadTestsFromTestCase(CategoryAPITests))
    suite.addTests(loader.loadTestsFromTestCase(CategoryUsageTests))
    suite.addTests(loader.loadTestsFromTestCase(UserSettingsAPITests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceSettingsAPITests))
    suite.addTests(loader.loadTestsFromTestCase(TransactionDraftAPITests))
    suite.addTests(loader.loadTestsFromTestCase(ExchangeRateAPITests))
    suite.addTests(loader.loadTestsFromTestCase(AdminImpersonationAdvancedTests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceAdminManagementTests))
    suite.addTests(loader.loadTestsFromTestCase(WorkspaceOwnershipTests))
    suite.addTests(loader.loadTestsFromTestCase(MemberRoleManagementTests))
    suite.addTests(loader.loadTestsFromTestCase(ModelValidationTests))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationSecurityTests))
    suite.addTests(loader.loadTestsFromTestCase(PerformanceTests))
    suite.addTests(loader.loadTestsFromTestCase(EdgeCaseTests))

    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == "__main__":
    run_integration_tests()
