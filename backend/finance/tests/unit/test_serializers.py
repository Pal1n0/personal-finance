"""
Test cases for financial management system serializers.

This module contains comprehensive tests for all Django REST Framework serializers
in the finance application, covering validation, serialization, deserialization,
and business logic with proper mocking and test isolation.

Test Structure:
- TestUserSettingsSerializer: User preference and settings serialization
- TestWorkspaceSerializer: Workspace data with membership context
- TestWorkspaceMembershipSerializer: Role-based membership operations
- TestWorkspaceSettingsSerializer: Workspace configuration validation
- TestTransactionSerializer: Financial transaction processing
- TestTransactionListSerializer: Optimized transaction list views
- TestCategorySerializers: Expense and income category management
"""

from datetime import date
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from rest_framework.exceptions import ValidationError as DRFValidationError

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
from finance.serializers import (
    ExchangeRateSerializer,
    ExpenseCategorySerializer,
    ExpenseCategoryVersionSerializer,
    IncomeCategorySerializer,
    IncomeCategoryVersionSerializer,
    TagSerializer,
    TransactionDraftSerializer,
    TransactionListSerializer,
    TransactionSerializer,
    UserSettingsSerializer,
    WorkspaceAdminSerializer,
    WorkspaceMembershipSerializer,
    WorkspaceSerializer,
    WorkspaceSettingsSerializer,
)

User = get_user_model()


class TestUserSettingsSerializer(TestCase):
    """
    Tests for UserSettingsSerializer handling user preferences.

    Covers language validation, serialization format, and user preference
    management with proper error handling.
    """

    def setUp(self):
        """Set up test user and user settings instance."""
        self.user = User.objects.create_user(
            email="test@test.com", password="testpass123", username="testuser"
        )
        self.user_settings = self.user.settings
        self.user_settings.language = "en"
        self.user_settings.save()

    def test_valid_serialization(self):
        """Test successful serialization of user settings."""
        serializer = UserSettingsSerializer(instance=self.user_settings)

        self.assertEqual(serializer.data["language"], "en")
        self.assertEqual(serializer.data["user"], self.user.id)

    def test_valid_language_validation(self):
        """Test validation of supported language codes."""
        serializer = UserSettingsSerializer(data={"language": "en"})

        self.assertTrue(serializer.is_valid())

    @patch("finance.serializers.settings")
    def test_invalid_language_validation(self, mock_settings):
        """Test rejection of invalid language codes."""
        mock_settings.LANGUAGES = [("en", "English"), ("sk", "Slovak")]
        serializer = UserSettingsSerializer(data={"language": "invalid"})

        self.assertFalse(serializer.is_valid())
        self.assertIn("language", serializer.errors)

    def test_update_currency_and_date_format(self):
        """Test that preferred_currency and date_format can be updated."""
        data = {"preferred_currency": "USD", "date_format": "YYYY-MM-DD"}
        serializer = UserSettingsSerializer(
            instance=self.user_settings, data=data, partial=True
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        serializer.save()

        self.user_settings.refresh_from_db()
        self.assertEqual(self.user_settings.preferred_currency, "USD")
        self.assertEqual(self.user_settings.date_format, "YYYY-MM-DD")


class TestWorkspaceSerializer(TestCase):
    """
    Tests for WorkspaceSerializer with cached permission context.

    Covers workspace serialization, member count, user role, permissions,
    and creation logic using a mocked request context with cached permissions.
    """

    def setUp(self):
        """Set up test workspace, owner, member, and a mock request."""
        self.owner = User.objects.create_user(
            email="owner@test.com", password="testpass123", username="owner"
        )
        self.member = User.objects.create_user(
            email="member@test.com", password="testpass123", username="member"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner, is_active=True
        )
        self.membership = WorkspaceMembership.objects.create(
            workspace=self.workspace, user=self.member, role="editor"
        )

        self.request = Mock()
        self.request.user = self.member
        # Define a base set of permissions for a typical 'editor' role
        self.request.user_permissions = {
            "workspace_role": "editor",
            "can_view": True,
            "can_edit": True,
            "can_manage_members": False,
            "can_create_transactions": True,
        }
        # The target_user is required for the create method
        self.request.target_user = self.owner

    def test_serialization_with_cached_permissions(self):
        """Test workspace serialization includes data from cached context."""
        serializer = WorkspaceSerializer(
            instance=self.workspace, context={"request": self.request}
        )

        data = serializer.data
        self.assertEqual(data["name"], "Test Workspace")
        self.assertEqual(data["owner_username"], "owner")
        self.assertEqual(data["user_role"], "editor")
        self.assertEqual(data["user_permissions"], self.request.user_permissions)

    def test_user_role_retrieval_from_cache(self):
        """Test retrieval of user's role from cached permissions."""
        serializer = WorkspaceSerializer(
            instance=self.workspace, context={"request": self.request}
        )
        role = serializer.get_user_role(self.workspace)
        self.assertEqual(role, "editor")

    def test_member_count_calculation(self):
        """Test calculation of total members in a workspace."""
        # Refresh instance to get the latest count from the database
        self.workspace.refresh_from_db()
        serializer = WorkspaceSerializer(instance=self.workspace)
        # Owner + member = 2
        self.assertEqual(serializer.data["member_count"], 2)

    def test_ownership_check_for_owner(self):
        """Test ownership detection for the workspace owner."""
        self.request.user = self.owner
        serializer = WorkspaceSerializer(
            instance=self.workspace, context={"request": self.request}
        )
        is_owner = serializer.get_is_owner(self.workspace)
        self.assertTrue(is_owner)

    def test_ownership_check_for_non_owner(self):
        """Test ownership detection for a non-owner member."""
        self.request.user = self.member  # This is the default from setUp
        serializer = WorkspaceSerializer(
            instance=self.workspace, context={"request": self.request}
        )
        is_owner = serializer.get_is_owner(self.workspace)
        self.assertFalse(is_owner)

    def test_user_permissions_retrieval_from_cache(self):
        """Test retrieval of user permissions from the cached context."""
        serializer = WorkspaceSerializer(
            instance=self.workspace, context={"request": self.request}
        )
        permissions = serializer.get_user_permissions(self.workspace)
        self.assertEqual(permissions, self.request.user_permissions)

    def test_anonymous_user_permissions(self):
        """Test permission calculation for anonymous (unauthenticated) users."""
        self.request.user = AnonymousUser()
        serializer = WorkspaceSerializer(
            instance=self.workspace, context={"request": self.request}
        )
        permissions = serializer.get_user_permissions(self.workspace)
        self.assertFalse(permissions["can_view"])
        self.assertFalse(permissions["can_create_transactions"])

    def test_valid_name_validation(self):
        """Test validation of a properly formatted workspace name."""
        serializer = WorkspaceSerializer(
            data={"name": "Valid Name"}, context={"request": self.request}
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))

    def test_name_too_short_validation(self):
        """Test rejection of an overly short workspace name."""
        serializer = WorkspaceSerializer(
            data={"name": "A"}, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("name", context.exception.detail)

    def test_name_too_long_validation(self):
        """Test rejection of an overly long workspace name."""
        long_name = "A" * 101
        serializer = WorkspaceSerializer(
            data={"name": long_name}, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("name", context.exception.detail)

    def test_name_stripping_validation(self):
        """Test automatic whitespace stripping from workspace names."""
        serializer = WorkspaceSerializer(
            data={"name": "  Test Workspace  "}, context={"request": self.request}
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        self.assertEqual(serializer.validated_data["name"], "Test Workspace")

    @patch("finance.serializers.WorkspaceService.create_workspace")
    def test_workspace_creation_delegates_to_service(self, mock_create_workspace):
        """Test that workspace creation is delegated to the WorkspaceService."""
        # Arrange
        self.request.user = self.owner
        self.request.target_user = self.owner

        # Define the mock return value
        mock_workspace = Workspace(id=99, name="New Workspace", owner=self.owner)

        # Create a mock for the serializer's handle_service_call
        # This isolates the test to the serializer's `create` method logic
        handle_service_call_mock = Mock(return_value=mock_workspace)

        serializer = WorkspaceSerializer(
            data={"name": "New Workspace", "description": "A description"},
            context={"request": self.request},
        )
        serializer.handle_service_call = handle_service_call_mock

        # Act
        self.assertTrue(serializer.is_valid(raise_exception=True))
        created_workspace = serializer.save()

        # Assert
        # Check that handle_service_call was called correctly
        handle_service_call_mock.assert_called_once_with(
            serializer.workspace_service.create_workspace,
            name="New Workspace",
            description="A description",
            owner=self.owner,
        )

        # Check that the serializer returns the object from the service
        self.assertEqual(created_workspace, mock_workspace)
        self.assertEqual(created_workspace.name, "New Workspace")

    def test_nested_settings_serialization_avoids_recursion(self):
        """
        Test that the nested 'settings' in WorkspaceSerializer does not include
        the 'workspace' field, preventing recursive serialization.
        """
        # The WorkspaceSettings object is created automatically by a signal.
        # We can retrieve it and check its serialization.
        self.workspace.refresh_from_db()
        self.assertIsNotNone(self.workspace.settings)

        # Update the settings to have a predictable value
        settings = self.workspace.settings
        settings.domestic_currency = "USD"
        settings.save()

        # Re-fetch the workspace to ensure the settings are loaded
        self.workspace.refresh_from_db()

        serializer = WorkspaceSerializer(instance=self.workspace)
        settings_data = serializer.data.get("settings")

        self.assertIsNotNone(settings_data)
        self.assertNotIn("workspace", settings_data)
        self.assertEqual(settings_data["domestic_currency"], "USD")


class TestWorkspaceMembershipSerializer(TestCase):
    """
    Tests for WorkspaceMembershipSerializer handling role assignments.

    Covers role validation, permission checks based on cached context,
    and security controls for membership management.
    """

    def setUp(self):
        """Set up test workspace, users with different roles, and memberships."""
        self.owner = User.objects.create_user(
            email="owner@test.com", password="testpass123", username="owner"
        )
        self.admin_user = User.objects.create_user(
            email="admin@test.com", password="testpass123", username="admin"
        )
        self.member = User.objects.create_user(
            email="member@test.com", password="testpass123", username="member"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner
        )

        # Membership for the user whose role is being changed
        self.membership_to_change = WorkspaceMembership.objects.create(
            workspace=self.workspace, user=self.member, role="viewer"
        )
        # Membership for the owner is created automatically, so we get it
        self.owner_membership = WorkspaceMembership.objects.get(
            workspace=self.workspace, user=self.owner
        )

        self.request = Mock()
        # By default, the acting user is an admin
        self.request.user = self.admin_user
        self.request.user_permissions = {"workspace_role": "admin"}

    def test_serialization_with_user_data(self):
        """Test membership serialization includes user and workspace details."""
        serializer = WorkspaceMembershipSerializer(instance=self.membership_to_change)
        data = serializer.data
        self.assertEqual(data["user_username"], "member")
        self.assertEqual(data["workspace_name"], "Test Workspace")
        self.assertEqual(data["role"], "viewer")
        self.assertFalse(data["is_workspace_owner"])

    def test_is_workspace_owner_field(self):
        """Test the `is_workspace_owner` field is correctly serialized."""
        serializer = WorkspaceMembershipSerializer(instance=self.owner_membership)
        self.assertTrue(serializer.data["is_workspace_owner"])

        serializer = WorkspaceMembershipSerializer(instance=self.membership_to_change)
        self.assertFalse(serializer.data["is_workspace_owner"])

    def test_admin_can_change_role(self):
        """Test that a user with an 'admin' role can change another member's role."""
        serializer = WorkspaceMembershipSerializer(
            instance=self.membership_to_change,
            data={"role": "editor"},
            context={"request": self.request},
            partial=True,
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        self.assertEqual(serializer.validated_data["role"], "editor")

    def test_owner_can_change_role(self):
        """Test that a user with an 'owner' role can change another member's role."""
        self.request.user = self.owner
        self.request.user_permissions = {"workspace_role": "owner"}
        serializer = WorkspaceMembershipSerializer(
            instance=self.membership_to_change,
            data={"role": "editor"},
            context={"request": self.request},
            partial=True,
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        self.assertEqual(serializer.validated_data["role"], "editor")

    def test_viewer_cannot_change_role(self):
        """Test that a user with a 'viewer' role cannot change roles."""
        self.request.user = self.member
        self.request.user_permissions = {"workspace_role": "viewer"}
        serializer = WorkspaceMembershipSerializer(
            instance=self.membership_to_change,
            data={"role": "editor"},
            context={"request": self.request},
            partial=True,
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn(
            "You don't have permission to change roles.", str(context.exception)
        )

    def test_cannot_change_owner_role(self):
        """Test that no one can change the role of the workspace owner."""
        serializer = WorkspaceMembershipSerializer(
            instance=self.owner_membership,
            data={"role": "editor"},
            context={"request": self.request},
            partial=True,
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("Cannot change owner's role.", str(context.exception))

    def test_invalid_role_validation(self):
        """Test rejection of an invalid role value."""
        serializer = WorkspaceMembershipSerializer(
            instance=self.membership_to_change,
            data={"role": "invalid_role"},
            context={"request": self.request},
            partial=True,
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("Invalid role", str(context.exception))


class TestWorkspaceSettingsSerializer(TestCase):
    """
    Tests for WorkspaceSettingsSerializer handling workspace configuration.

    Covers currency validation, fiscal year settings, and workspace-specific
    configuration with proper business rule enforcement.
    """

    def setUp(self):
        """Set up test workspace and settings instance."""
        self.owner = User.objects.create_user(
            email="owner@test.com", password="testpass123", username="owner"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner
        )
        self.settings = self.workspace.settings
        self.settings.domestic_currency = "EUR"
        self.settings.fiscal_year_start = 1
        self.settings.display_mode = "light"
        self.settings.accounting_mode = True
        self.settings.save()

    def test_valid_serialization(self):
        """Test serialization of workspace settings with all fields."""
        serializer = WorkspaceSettingsSerializer(instance=self.settings)

        data = serializer.data
        self.assertEqual(data["domestic_currency"], "EUR")
        self.assertEqual(data["fiscal_year_start"], 1)

    def test_valid_currency_validation(self):
        """Test validation of supported currency codes."""
        serializer = WorkspaceSettingsSerializer(
            data={"domestic_currency": "USD", "accounting_mode": True}
        )

        self.assertTrue(serializer.is_valid())

    def test_invalid_currency_validation(self):
        """Test rejection of invalid currency codes."""
        serializer = WorkspaceSettingsSerializer(
            data={"domestic_currency": "INVALID", "accounting_mode": True}
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("domestic_currency", serializer.errors)

    def test_valid_fiscal_year_start_validation(self):
        """Test validation of proper fiscal year start months."""
        serializer = WorkspaceSettingsSerializer(
            data={"fiscal_year_start": 6, "accounting_mode": True}
        )

        self.assertTrue(serializer.is_valid())

    def test_invalid_fiscal_year_start_validation(self):
        """Test rejection of invalid fiscal year start months."""
        serializer = WorkspaceSettingsSerializer(
            data={"fiscal_year_start": 13, "accounting_mode": True}
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("fiscal_year_start", serializer.errors)

    def test_update_display_and_accounting_modes(self):
        """Test that display_mode and accounting_mode can be updated."""
        data = {"display_mode": "day", "accounting_mode": False}
        serializer = WorkspaceSettingsSerializer(
            instance=self.settings, data=data, partial=True
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        serializer.save()

        self.settings.refresh_from_db()
        self.assertEqual(self.settings.display_mode, "day")
        self.assertEqual(self.settings.accounting_mode, False)


class TestTransactionSerializer(TestCase):
    """
    Tests for TransactionSerializer with service-layer integration.

    Covers transaction validation (delegated to services), category and tag
    management, and security controls like cross-workspace prevention.
    """

    def setUp(self):
        """Set up users, workspace, categories (at the required leaf level), and a mock request."""
        self.owner = User.objects.create_user(
            username="owner", email="owner@test.com", password="password"
        )
        self.user = User.objects.create_user(
            username="user", email="user@test.com", password="password"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner
        )

        # Category versions are required for categories
        self.expense_version = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace, name="Expense V1", created_by=self.owner
        )
        self.income_version = IncomeCategoryVersion.objects.create(
            workspace=self.workspace, name="Income V1", created_by=self.owner
        )

        # IMPORTANT: Categories must be at level 5 to be valid for transactions
        self.expense_category = ExpenseCategory.objects.create(
            name="Office Supplies", version=self.expense_version, level=5
        )
        self.income_category = IncomeCategory.objects.create(
            name="Sales", version=self.income_version, level=5
        )

        # Mock request with essential context
        self.request = Mock()
        self.request.user = self.user
        self.request.workspace = self.workspace
        self.request.target_user = self.user
        # The serializer uses these cached querysets for security and performance
        self.request._cached_expense_categories = ExpenseCategory.objects.filter(
            id=self.expense_category.id
        )
        self.request._cached_income_categories = IncomeCategory.objects.filter(
            id=self.income_category.id
        )

    def test_serializer_initialization_with_workspace_querysets(self):
        """Test serializer initializes with workspace-scoped category querysets."""
        serializer = TransactionSerializer(context={"request": self.request})
        self.assertEqual(
            serializer.fields["expense_category"].queryset.model, ExpenseCategory
        )
        self.assertEqual(
            serializer.fields["income_category"].queryset.model, IncomeCategory
        )

    @patch(
        "finance.serializers.TransactionService._validate_transaction_data",
        return_value=None,
    )
    def test_valid_transaction_creation(self, mock_validate):
        """Test successful creation of a valid expense transaction."""
        mock_validate.__name__ = "mock_validate_transaction"
        data = {
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": 100.00,
            "original_currency": "EUR",
            "date": "2023-01-01",
        }
        serializer = TransactionSerializer(data=data, context={"request": self.request})

        self.assertTrue(serializer.is_valid(raise_exception=True))

        # Mock the service call for isolation
        with patch.object(
            serializer, "handle_service_call", return_value=None
        ) as mock_handle:
            instance = serializer.save()

        # Check that the underlying model instance was created with correct data
        self.assertEqual(instance.user, self.user)
        self.assertEqual(instance.workspace, self.workspace)
        self.assertEqual(instance.type, "expense")
        # Assert that the service validation was called
        mock_validate.assert_called_once()

    def test_invalid_category_level_validation(self):
        """Test rejection of transactions using a non-leaf category (level != 5)."""
        # Create a category with an invalid level
        parent_category = ExpenseCategory.objects.create(
            name="Parent Category", version=self.expense_version, level=4
        )
        data = {
            "type": "expense",
            "expense_category": parent_category.id,
            "original_amount": 50.00,
            "original_currency": "USD",
            "date": "2023-01-10",
        }
        serializer = TransactionSerializer(data=data, context={"request": self.request})

        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("Only Level 5 categories are allowed", str(context.exception))

    @patch(
        "finance.serializers.TransactionService._validate_transaction_data",
        side_effect=DRFValidationError("Service validation failed"),
    )
    def test_service_layer_validation_failure(self, mock_validate):
        """Test that service-layer validation failures are converted to DRF exceptions."""
        mock_validate.__name__ = "mock_validate_transaction"
        data = {
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": 100.00,
            "original_currency": "EUR",
            "date": "2023-01-01",
        }
        serializer = TransactionSerializer(data=data, context={"request": self.request})

        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("Service validation failed", str(context.exception))
        mock_validate.assert_called_once()

    def test_cross_workspace_category_access_blocked(self):
        """Test prevention of using a category from another workspace."""
        other_workspace = Workspace.objects.create(
            name="Other Workspace", owner=self.owner
        )
        other_version = ExpenseCategoryVersion.objects.create(
            workspace=other_workspace, name="Other V1", created_by=self.owner
        )
        other_category = ExpenseCategory.objects.create(
            name="Other's Category", version=other_version, level=5
        )

        data = {
            "type": "expense",
            "expense_category": other_category.id,  # This ID is not in the request's cached queryset
            "original_amount": 100.00,
            "original_currency": "EUR",
            "date": "2023-01-01",
        }
        serializer = TransactionSerializer(data=data, context={"request": self.request})

        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        # DRF's PrimaryKeyRelatedField raises this error when the object is not in the queryset
        self.assertIn("Invalid pk", str(context.exception))
        self.assertIn("expense_category", context.exception.detail)

    @patch(
        "finance.serializers.TransactionService._validate_transaction_data",
        return_value=None,
    )
    @patch("finance.serializers.TagService.assign_tags_to_transaction")
    def test_transaction_creation_with_tags(self, mock_assign_tags, mock_validate):
        """Test that tags are correctly assigned during transaction creation."""
        mock_validate.__name__ = "mock_validate_transaction"
        mock_assign_tags.__name__ = "mock_assign_tags"
        data = {
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": 100.00,
            "original_currency": "EUR",
            "date": "2023-01-01",
            "tags": ["urgent", "project-x"],  # Passing tags
        }
        serializer = TransactionSerializer(data=data, context={"request": self.request})

        self.assertTrue(serializer.is_valid(raise_exception=True))
        instance = serializer.save()

        # Assert that the tag service was called with the correct arguments
        mock_assign_tags.assert_called_once_with(
            transaction_instance=instance, tag_names=["urgent", "project-x"]
        )

    @patch(
        "finance.serializers.TransactionService._validate_transaction_data",
        return_value=None,
    )
    @patch("finance.serializers.TagService.get_or_create_tags")
    def test_transaction_update_with_tags(self, mock_get_or_create_tags, mock_validate):
        """Test that tags are correctly updated on an existing transaction."""
        mock_validate.__name__ = "mock_validate_transaction"
        mock_get_or_create_tags.__name__ = "mock_get_or_create_tags"
        # Create initial transaction
        transaction = Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            type="expense",
            expense_category=self.expense_category,
            original_amount=50.0,
            original_currency="USD",
            date=date(2023, 1, 5),
        )
        # Mock the return of the tag service
        mock_get_or_create_tags.return_value = []

        update_data = {
            "original_amount": 55.00,
            "tags": ["reviewed", "final"],  # New set of tags
        }
        serializer = TransactionSerializer(
            instance=transaction,
            data=update_data,
            context={"request": self.request},
            partial=True,
        )

        self.assertTrue(serializer.is_valid(raise_exception=True))
        serializer.save()

        # Assert that the tag service was called to fetch the new tags
        mock_get_or_create_tags.assert_called_once_with(
            workspace=transaction.workspace, tag_names=["reviewed", "final"]
        )
        # The serializer's `update` calls `instance.tags.set()`, which we can't easily mock
        # without a more complex setup. The call to the service is a good indicator.

    def test_transaction_update_without_tags_preserves_existing_tags(self):
        """Test that updating a transaction without the 'tags' key preserves existing tags."""
        # Arrange: Create a transaction and assign some tags to it
        transaction = Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            type="expense",
            expense_category=self.expense_category,
            original_amount=75.0,
            original_currency="EUR",
            date=date(2023, 1, 15),
        )
        tag1 = Tags.objects.create(workspace=self.workspace, name="important")
        tag2 = Tags.objects.create(workspace=self.workspace, name="q1")
        transaction.tags.set([tag1, tag2])

        # Act: Update a different field on the transaction, without providing the 'tags' key
        update_data = {"original_amount": 80.00}
        serializer = TransactionSerializer(
            instance=transaction,
            data=update_data,
            context={"request": self.request},
            partial=True,
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        serializer.save()

        # Assert: Check that the original tags are still present
        transaction.refresh_from_db()
        self.assertEqual(transaction.tags.count(), 2)
        self.assertIn(tag1, transaction.tags.all())
        self.assertIn(tag2, transaction.tags.all())

    def test_original_currency_validation(self):
        """Test validation for the original_currency field."""
        # Test valid currency
        data_valid = {
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": 100.00,
            "original_currency": "CZK",
            "date": "2023-01-01",
        }
        serializer_valid = TransactionSerializer(
            data=data_valid, context={"request": self.request}
        )
        self.assertTrue(serializer_valid.is_valid(raise_exception=True))

        # Test invalid currency
        data_invalid = {
            "type": "expense",
            "expense_category": self.expense_category.id,
            "original_amount": 100.00,
            "original_currency": "BTC",
            "date": "2023-01-01",
        }
        serializer_invalid = TransactionSerializer(
            data=data_invalid, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer_invalid.is_valid(raise_exception=True)
        self.assertIn("original_currency", context.exception.detail)

    def test_get_tag_list_serialization(self):
        transaction = Transaction.objects.create(
            user=self.user,
            workspace=self.workspace,
            type="expense",
            expense_category=self.expense_category,
            original_amount=50.0,
            original_currency="USD",
            date=date(2023, 1, 5),
        )
        tag1 = Tags.objects.create(workspace=self.workspace, name="tag1")
        tag2 = Tags.objects.create(workspace=self.workspace, name="tag2")
        transaction.tags.set([tag1, tag2])

        serializer = TransactionSerializer(instance=transaction)
        self.assertEqual(sorted(serializer.data["tag_list"]), ["tag1", "tag2"])


class TestTransactionListSerializer(TestCase):
    """
    Tests for TransactionListSerializer optimized for list views.

    Covers lightweight serialization, read-only field enforcement,
    and performance-optimized category name retrieval for transaction listings.
    """

    def setUp(self):
        """Set up test transaction instance."""
        self.owner = User.objects.create_user(
            email="owner@test.com", password="testpass123", username="owner"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner
        )
        self.transaction = Transaction.objects.create(
            user=self.owner,
            workspace=self.workspace,
            type="expense",
            original_amount=100.00,
            original_currency="EUR",
            amount_domestic=100.00,
            date=date(2023, 1, 1),
        )

    def test_lightweight_serialization(self):
        """Test minimal field serialization for performance optimization."""
        serializer = TransactionListSerializer(instance=self.transaction)

        data = serializer.data
        self.assertEqual(data["type"], "expense")
        self.assertEqual(float(data["original_amount"]), 100.00)  # ← Konvertuj na float
        self.assertEqual(data["workspace"], self.workspace.id)

    def test_category_name_for_expense(self):
        """Test category name formatting for expense transactions."""
        self.transaction.expense_category_id = 1
        serializer = TransactionListSerializer(instance=self.transaction)

        category_name = serializer.get_category_name(self.transaction)
        self.assertEqual(category_name, "Expense Category #1")

    def test_category_name_for_income(self):
        """Test category name formatting for income transactions."""
        self.transaction.income_category_id = 2
        serializer = TransactionListSerializer(instance=self.transaction)

        category_name = serializer.get_category_name(self.transaction)
        self.assertEqual(category_name, "Income Category #2")

    def test_category_name_when_no_category(self):
        """Test category name handling for transactions without categories."""
        serializer = TransactionListSerializer(instance=self.transaction)

        category_name = serializer.get_category_name(self.transaction)
        self.assertIsNone(category_name)

    def test_all_fields_are_read_only(self):
        """Test enforcement of read-only fields for list optimization."""
        serializer = TransactionListSerializer()

        for field_name, field in serializer.fields.items():
            self.assertTrue(field.read_only, f"Field {field_name} should be read-only")


class TestCategorySerializers(TestCase):
    """
    Tests for ExpenseCategorySerializer and IncomeCategorySerializer.

    Covers category serialization, validation, workspace security,
    and hierarchical category management with proper access controls.
    """

    def setUp(self):
        """Set up test categories, versions, and workspace context."""
        self.owner = User.objects.create_user(
            email="owner@test.com", password="testpass123", username="owner"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner
        )
        self.expense_version = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace, name="Expense Version", created_by=self.owner
        )
        self.income_version = IncomeCategoryVersion.objects.create(
            workspace=self.workspace, name="Income Version", created_by=self.owner
        )
        self.expense_category = ExpenseCategory.objects.create(
            name="Test Expense", version=self.expense_version, level=1
        )
        self.income_category = IncomeCategory.objects.create(
            name="Test Income", version=self.income_version, level=1
        )

        self.request = Mock()
        self.request.workspace = self.workspace

    def test_expense_category_serialization(self):
        """Test serialization of expense category with all fields."""
        serializer = ExpenseCategorySerializer(instance=self.expense_category)

        data = serializer.data
        self.assertEqual(data["name"], "Test Expense")
        self.assertEqual(data["level"], 1)

    def test_income_category_serialization(self):
        """Test serialization of income category with all fields."""
        serializer = IncomeCategorySerializer(instance=self.income_category)

        data = serializer.data
        self.assertEqual(data["name"], "Test Income")
        self.assertEqual(data["level"], 1)

    def test_expense_category_validation(self):
        """Test validation and whitespace stripping for expense category names."""
        serializer = ExpenseCategorySerializer(
            data={
                "name": "  New Expense  ",
                "level": 1,
                "version": self.expense_version.id,
            },
            context={"request": self.request},
        )

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data["name"], "New Expense")

    def test_income_category_validation(self):
        """Test validation and whitespace stripping for income category names."""
        serializer = IncomeCategorySerializer(
            data={
                "name": "  New Income  ",
                "level": 1,
                "version": self.income_version.id,
            },
            context={"request": self.request},
        )

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data["name"], "New Income")

    def test_category_name_too_short_validation(self):
        """Test rejection of overly short category names."""
        serializer = ExpenseCategorySerializer(
            data={"name": "A"}, context={"request": self.request}
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("name", serializer.errors)

    def test_workspace_validation_in_category_mixin(self):
        """Test prevention of cross-workspace category assignments."""
        other_workspace = Workspace.objects.create(
            name="Other Workspace", owner=self.owner
        )
        other_version = ExpenseCategoryVersion.objects.create(
            workspace=other_workspace, name="Other Version", created_by=self.owner
        )

        serializer = ExpenseCategorySerializer(
            data={"name": "Test Category", "version": other_version.id},
            context={"request": self.request},
        )

        self.assertFalse(serializer.is_valid())


class TestTagSerializer(TestCase):
    """Tests for the TagSerializer."""

    def setUp(self):
        """Set up a user, workspace, and mock request."""
        self.owner = User.objects.create_user(
            username="owner", email="owner@test.com", password="password"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner
        )
        self.request = Mock()
        self.request.workspace = self.workspace

    def test_valid_tag_serialization(self):
        """Test that a tag is serialized correctly."""
        tag = Tags.objects.create(workspace=self.workspace, name="test tag")
        serializer = TagSerializer(instance=tag)
        data = serializer.data
        self.assertEqual(data["name"], "test tag")
        self.assertEqual(data["workspace"], self.workspace.id)

    def test_valid_name_validation(self):
        """Test validation of a valid tag name."""
        serializer = TagSerializer(
            data={"name": "  valid tag  "}, context={"request": self.request}
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        self.assertEqual(serializer.validated_data["name"], "valid tag")

    def test_name_too_long_validation(self):
        """Test that a tag name longer than 50 characters is invalid."""
        long_name = "a" * 51
        serializer = TagSerializer(
            data={"name": long_name}, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn(
            "Ensure this field has no more than 50 characters.", str(context.exception)
        )

    def test_empty_name_validation(self):
        """Test that an empty tag name is invalid."""
        serializer = TagSerializer(data={"name": ""}, context={"request": self.request})
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("Tag name cannot be empty.", str(context.exception))

    def test_whitespace_name_validation(self):
        """Test that a tag name with only whitespace is invalid."""
        serializer = TagSerializer(
            data={"name": "   "}, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("Tag name cannot be empty.", str(context.exception))

    @patch("finance.serializers.TagService.get_or_create_tags")
    def test_create_uses_get_or_create_service(self, mock_get_or_create_tags):
        """Test that the create method uses the TagService for get-or-create logic."""
        # Arrange
        tag_name = "new-tag"
        mock_tag = Tags(id=1, workspace=self.workspace, name=tag_name)
        mock_get_or_create_tags.return_value = [mock_tag]

        serializer = TagSerializer(
            data={"name": tag_name}, context={"request": self.request}
        )

        # Act
        self.assertTrue(serializer.is_valid(raise_exception=True))
        created_tag = serializer.save()

        # Assert
        mock_get_or_create_tags.assert_called_once_with(
            workspace=self.workspace, tag_names=[tag_name]
        )
        self.assertEqual(created_tag, mock_tag)
        self.assertEqual(
            Tags.objects.count(), 0
        )  # Service is mocked, so no object is actually created

    def test_create_actually_creates_tag(self):
        """Test the get-or-create logic for a new tag."""
        self.assertEqual(Tags.objects.count(), 0)
        serializer = TagSerializer(
            data={"name": "new tag"}, context={"request": self.request}
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        serializer.save()
        self.assertEqual(Tags.objects.count(), 1)
        self.assertTrue(Tags.objects.filter(name="new tag").exists())

    def test_create_returns_existing_tag(self):
        """Test the get-or-create logic for an existing tag."""
        existing_tag = Tags.objects.create(
            workspace=self.workspace, name="existing tag"
        )
        self.assertEqual(Tags.objects.count(), 1)

        serializer = TagSerializer(
            data={"name": "  EXISTING TAG  "},  # Test normalization
            context={"request": self.request},
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))
        returned_tag = serializer.save()

        self.assertEqual(Tags.objects.count(), 1)
        self.assertEqual(returned_tag, existing_tag)


class TestTransactionDraftSerializer(TestCase):
    """Tests for the TransactionDraftSerializer."""

    def setUp(self):
        """Set up user, workspace, categories, and a mock request."""
        self.owner = User.objects.create_user(
            username="owner", email="owner@test.com", password="password"
        )
        self.user = User.objects.create_user(
            username="user", email="user@test.com", password="password"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.owner
        )

        self.expense_version = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace, name="V1", created_by=self.owner
        )
        self.expense_category_lvl5 = ExpenseCategory.objects.create(
            name="Supplies", version=self.expense_version, level=5
        )
        self.expense_category_lvl4 = ExpenseCategory.objects.create(
            name="General", version=self.expense_version, level=4
        )

        self.request = Mock()
        self.request.user = self.user
        self.request.workspace = self.workspace
        self.request.target_user = self.user
        # Mock cached categories for validation
        self.request._cached_expense_categories = [
            self.expense_category_lvl5,
            self.expense_category_lvl4,
        ]
        self.request._cached_income_categories = []

        self.valid_tx_data = [
            {
                "type": "expense",
                "expense_category_id": self.expense_category_lvl5.id,
                "original_amount": 10,
                "original_currency": "USD",
                "date": "2023-01-01",
            }
        ]

    def test_valid_draft_creation(self):
        """Test creating a valid transaction draft."""
        data = {"draft_type": "expense", "transactions_data": self.valid_tx_data}
        serializer = TransactionDraftSerializer(
            data=data, context={"request": self.request}
        )
        self.assertTrue(serializer.is_valid(raise_exception=True))

    def test_draft_type_mismatch_validation(self):
        """Test validation fails if draft_type and transaction type mismatch."""
        data = {
            "draft_type": "income",  # Mismatch
            "transactions_data": self.valid_tx_data,
        }
        serializer = TransactionDraftSerializer(
            data=data, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("does not match the draft_type", str(context.exception))

    def test_changing_draft_type_on_update_is_invalid(self):
        """Test that changing the draft_type of an existing draft is not allowed."""
        draft = TransactionDraft.objects.create(
            user=self.user,
            workspace=self.workspace,
            draft_type="expense",
            transactions_data=[],
        )
        serializer = TransactionDraftSerializer(
            instance=draft,
            data={"draft_type": "income"},
            context={"request": self.request},
            partial=True,
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn(
            "Changing the type of an existing draft is not allowed",
            str(context.exception),
        )

    def test_invalid_category_level_in_draft(self):
        """Test validation fails if a transaction in the draft uses a non-leaf category."""
        invalid_tx_data = [
            {
                "type": "expense",
                "expense_category_id": self.expense_category_lvl4.id,  # Invalid level
                "original_amount": 20,
                "original_currency": "EUR",
                "date": "2023-02-01",
            }
        ]
        data = {"draft_type": "expense", "transactions_data": invalid_tx_data}
        serializer = TransactionDraftSerializer(
            data=data, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("is not at the lowest level", str(context.exception))

    def test_malformed_transaction_data_in_draft(self):
        """Test validation fails if a transaction in the draft is missing the 'type' key."""
        malformed_tx_data = [
            {
                # Missing 'type'
                "expense_category_id": self.expense_category_lvl5.id,
                "original_amount": 30,
                "original_currency": "USD",
                "date": "2023-03-01",
            }
        ]
        data = {"draft_type": "expense", "transactions_data": malformed_tx_data}
        serializer = TransactionDraftSerializer(
            data=data, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("must have a type", str(context.exception))

    def test_both_categories_in_draft_is_invalid(self):
        """Test validation fails if a transaction in the draft has both category types."""
        invalid_tx_data = [
            {
                "type": "expense",
                "expense_category_id": self.expense_category_lvl5.id,
                "income_category_id": 1,  # Dummy ID for an income category
                "original_amount": 40,
                "original_currency": "EUR",
                "date": "2023-04-01",
            }
        ]
        data = {"draft_type": "expense", "transactions_data": invalid_tx_data}
        serializer = TransactionDraftSerializer(
            data=data, context={"request": self.request}
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn(
            "cannot have both expense and income categories", str(context.exception)
        )

    def test_update_without_draft_type_uses_instance_type(self):
        """Test that updating transactions_data without passing draft_type validates against the instance's draft_type."""
        # Arrange: Create an 'expense' draft
        draft = TransactionDraft.objects.create(
            user=self.user,
            workspace=self.workspace,
            draft_type="expense",
            transactions_data=[],
        )
        # This transaction has the wrong type ('income')
        mismatched_tx_data = [
            {
                "type": "income",
                "original_amount": 100,
                "original_currency": "USD",
                "date": "2023-01-01",
            }
        ]

        # Act & Assert: Attempt to update the draft with mismatched data.
        # The serializer should use the instance's 'expense' type for validation.
        serializer = TransactionDraftSerializer(
            instance=draft,
            data={"transactions_data": mismatched_tx_data},
            context={"request": self.request},
            partial=True,
        )
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("does not match the draft_type 'expense'", str(context.exception))

    @patch("finance.serializers.DraftService.save_draft")
    def test_create_delegates_to_service(self, mock_save_draft):
        """Test that the create method delegates to the DraftService."""
        mock_save_draft.__name__ = "mock_save_draft"
        mock_draft = TransactionDraft(id=1)
        mock_save_draft.return_value = mock_draft

        data = {"draft_type": "expense", "transactions_data": self.valid_tx_data}
        serializer = TransactionDraftSerializer(
            data=data, context={"request": self.request}
        )

        self.assertTrue(serializer.is_valid(raise_exception=True))
        created_draft = serializer.save()

        mock_save_draft.assert_called_once_with(
            user=self.user,
            workspace_id=self.workspace.id,
            draft_type="expense",
            transactions_data=self.valid_tx_data,
        )
        self.assertEqual(created_draft, mock_draft)

    @patch("finance.models.TransactionDraft.save")
    def test_update_saves_instance(self, mock_instance_save):
        """Test that the update method correctly modifies and saves the instance."""
        draft = TransactionDraft.objects.create(
            user=self.user,
            workspace=self.workspace,
            draft_type="expense",
            transactions_data=[],
        )
        mock_instance_save.reset_mock()

        updated_data = {"transactions_data": self.valid_tx_data}

        serializer = TransactionDraftSerializer(
            instance=draft,
            data=updated_data,
            context={"request": self.request},
            partial=True,
        )

        self.assertTrue(serializer.is_valid(raise_exception=True))
        updated_instance = serializer.save()

        # Check that the instance field was updated
        self.assertEqual(updated_instance.transactions_data, self.valid_tx_data)
        # Check that the instance's save method was called
        mock_instance_save.assert_called_once()
        self.assertEqual(updated_instance, draft)


class TestWorkspaceAdminSerializer(TestCase):
    """Tests for the WorkspaceAdminSerializer."""

    def setUp(self):
        """Set up users, workspace, and a workspace admin instance."""
        self.superuser = User.objects.create_superuser(
            username="superuser", email="super@test.com", password="password"
        )
        self.regular_user = User.objects.create_user(
            username="regular", email="regular@test.com", password="password"
        )
        self.admin_user = User.objects.create_user(
            username="admin", email="admin@test.com", password="password"
        )

        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.superuser
        )

        self.workspace_admin = WorkspaceAdmin.objects.create(
            user=self.admin_user,
            workspace=self.workspace,
            assigned_by=self.superuser,
            can_impersonate=False,
            can_manage_users=False,
        )

        self.request = Mock()

    def test_serialization(self):
        """Test that the serializer correctly serializes a WorkspaceAdmin instance."""
        serializer = WorkspaceAdminSerializer(instance=self.workspace_admin)
        data = serializer.data

        self.assertEqual(data["user_id"], self.admin_user.id)
        self.assertEqual(data["username"], self.admin_user.username)
        self.assertEqual(data["workspace_id"], self.workspace.id)
        self.assertEqual(data["assigned_by_username"], self.superuser.username)
        self.assertFalse(data["can_impersonate"])
        self.assertTrue(data["is_active"])

    def test_non_superuser_cannot_modify_permissions(self):
        """Test that a non-superuser's attempt to modify permissions is rejected."""
        self.request.user = self.regular_user

        serializer = WorkspaceAdminSerializer(
            instance=self.workspace_admin,
            data={"can_impersonate": True},
            context={"request": self.request},
            partial=True,
        )

        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn(
            "Only superusers can modify admin permissions.", str(context.exception)
        )

    def test_superuser_can_modify_permissions(self):
        """Test that a superuser can successfully modify permissions."""
        self.request.user = self.superuser

        serializer = WorkspaceAdminSerializer(
            instance=self.workspace_admin,
            data={"can_impersonate": True, "can_manage_users": True},
            context={"request": self.request},
            partial=True,
        )

        self.assertTrue(serializer.is_valid(raise_exception=True))
        self.assertTrue(serializer.validated_data["can_impersonate"])
        self.assertTrue(serializer.validated_data["can_manage_users"])

    def test_create_method_raises_error(self):
        """Test that the create method is blocked and raises a ValidationError."""
        serializer = WorkspaceAdminSerializer(
            data={}, context={"request": self.request}
        )

        with self.assertRaises(DRFValidationError) as context:
            serializer.create({})
        self.assertIn("Use the assign-admin endpoint", str(context.exception))


class TestCategoryVersionSerializers(TestCase):
    """Tests for the category version serializers."""

    def setUp(self):
        """Set up a user, workspace, and category versions."""
        self.user = User.objects.create_user(
            username="testuser", email="test@test.com", password="password"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace", owner=self.user
        )

        self.expense_version = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace,
            name="Expense V1",
            description="First version of expenses",
            created_by=self.user,
            levels_count=5,
        )
        self.income_version = IncomeCategoryVersion.objects.create(
            workspace=self.workspace,
            name="Income V1",
            description="First version of incomes",
            created_by=self.user,
            levels_count=3,
        )

    def test_expense_category_version_serialization(self):
        """Test the serialization of an ExpenseCategoryVersion instance."""
        serializer = ExpenseCategoryVersionSerializer(instance=self.expense_version)
        data = serializer.data

        self.assertEqual(data["id"], self.expense_version.id)
        self.assertEqual(data["workspace"], self.workspace.id)
        self.assertEqual(data["name"], "Expense V1")
        self.assertEqual(data["description"], "First version of expenses")
        self.assertEqual(data["levels_count"], 5)
        self.assertEqual(data["created_by"], self.user.id)
        self.assertTrue(data["is_active"])
        self.assertIn("created_at", data)

    def test_income_category_version_serialization(self):
        """Test the serialization of an IncomeCategoryVersion instance."""
        serializer = IncomeCategoryVersionSerializer(instance=self.income_version)
        data = serializer.data

        self.assertEqual(data["id"], self.income_version.id)
        self.assertEqual(data["workspace"], self.workspace.id)
        self.assertEqual(data["name"], "Income V1")
        self.assertEqual(data["description"], "First version of incomes")
        self.assertEqual(data["levels_count"], 3)
        self.assertEqual(data["created_by"], self.user.id)
        self.assertTrue(data["is_active"])
        self.assertIn("created_at", data)


class TestExchangeRateSerializer(TestCase):
    """
    Tests for the ExchangeRateSerializer.
    """

    def setUp(self):
        """Set up an exchange rate instance for testing."""
        self.exchange_rate = ExchangeRate.objects.create(
            currency="USD", rate_to_eur="0.95", date="2023-10-26"
        )

    def test_valid_serialization(self):
        """Test successful serialization of an ExchangeRate instance."""
        serializer = ExchangeRateSerializer(instance=self.exchange_rate)
        data = serializer.data
        self.assertEqual(data["currency"], "USD")
        self.assertEqual(
            data["rate_to_eur"], "0.950000"
        )  # Decimal fields are serialized as strings
        self.assertEqual(data["date"], "2023-10-26")

    def test_valid_currency_validation(self):
        """Test validation of supported currency codes."""
        data = {"currency": "GBP", "rate_to_eur": "1.15", "date": "2023-10-27"}
        serializer = ExchangeRateSerializer(data=data)
        self.assertTrue(serializer.is_valid(raise_exception=True))

    def test_invalid_currency_validation(self):
        """Test rejection of invalid currency codes."""
        data = {"currency": "XYZ", "rate_to_eur": "1.0", "date": "2023-10-27"}
        serializer = ExchangeRateSerializer(data=data)
        with self.assertRaises(DRFValidationError) as context:
            serializer.is_valid(raise_exception=True)
        self.assertIn("currency", context.exception.detail)

    def test_positive_rate_validation(self):
        """Test validation of a positive exchange rate."""
        data = {"currency": "USD", "rate_to_eur": "0.000001", "date": "2023-10-27"}
        serializer = ExchangeRateSerializer(data=data)
        self.assertTrue(serializer.is_valid(raise_exception=True))

    def test_non_positive_rate_validation(self):
        """Test rejection of a zero or negative exchange rate."""
        # Test with zero
        data_zero = {"currency": "USD", "rate_to_eur": "0.0", "date": "2023-10-27"}
        serializer_zero = ExchangeRateSerializer(data=data_zero)
        with self.assertRaises(DRFValidationError) as context:
            serializer_zero.is_valid(raise_exception=True)
        self.assertIn("rate_to_eur", context.exception.detail)
        self.assertIn(
            "must be positive", str(context.exception.detail["rate_to_eur"][0])
        )

        # Test with negative
        data_negative = {"currency": "USD", "rate_to_eur": "-1.0", "date": "2023-10-27"}
        serializer_negative = ExchangeRateSerializer(data=data_negative)
        with self.assertRaises(DRFValidationError) as context:
            serializer_negative.is_valid(raise_exception=True)
        self.assertIn("rate_to_eur", context.exception.detail)
        self.assertIn(
            "must be positive", str(context.exception.detail["rate_to_eur"][0])
        )
