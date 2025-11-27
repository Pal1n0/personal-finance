# tests/unit/test_models.py
from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError
from unittest.mock import Mock, patch
from django.db import IntegrityError, transaction
from django.utils import timezone

from finance.models import (
    ExchangeRate,
    ExpenseCategory,
    ExpenseCategoryProperty,
    ExpenseCategoryVersion,
    IncomeCategory,
    IncomeCategoryProperty,
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

# =============================================================================
# USER SETTINGS TESTS
# =============================================================================


class TestUserSettings:
    """Testy pre UserSettings model"""

    def test_user_settings_creation(self, user_settings, test_user):
        """Test vytvorenia UserSettings"""
        assert user_settings.user == test_user
        assert user_settings.language == "sk"
        assert str(user_settings) == f"{test_user.username} settings"

    def test_user_settings_default_language(self, test_user):
        """Test predvoleného jazyka"""
        settings = test_user.settings
        assert settings.language == "en"

    def test_user_settings_language_choices(self, user_settings):
        """Test platných jazykových voľieb"""
        valid_languages = ["en", "cs", "sk"]
        assert user_settings.language in valid_languages

    def test_user_settings_string_representation(self, user_settings, test_user):
        """Test string reprezentácie"""
        expected = f"{test_user.username} settings"
        assert str(user_settings) == expected

    def test_user_settings_clean_method_execution(self, user_settings):
        """Test that the clean method is executed."""
        # Just call full_clean; if it doesn't raise an error, it means it executed.
        user_settings.full_clean()
        # No assert needed beyond not raising an exception, as the clean method has no side effects beyond logging.



# =============================================================================
# WORKSPACE TESTS
# =============================================================================


class TestWorkspace:
    """Testy pre Workspace model"""

    def test_workspace_creation(self, test_workspace, test_user):
        """Test vytvorenia workspace"""
        assert test_workspace.name == "Test Workspace"
        assert test_workspace.owner == test_user
        assert test_workspace.is_active is True
        assert str(test_workspace) == f"Test Workspace (Owner: {test_user.username})"

    def test_workspace_validation_name_too_short(self, test_user):
        """Test validácie príliš krátkeho názvu"""
        workspace = Workspace(name="A", owner=test_user)
        with pytest.raises(ValidationError) as exc_info:
            workspace.full_clean()
        assert "Workspace name must be at least 2 characters long" in str(
            exc_info.value
        )

    def test_workspace_validation_empty_name(self, test_user):
        """Test validácie prázdneho názvu"""
        workspace = Workspace(name="   ", owner=test_user)
        with pytest.raises(ValidationError) as exc_info:
            workspace.full_clean()
        assert "Workspace name must be at least 2 characters long" in str(
            exc_info.value
        )

    def test_workspace_string_representation(self, test_workspace, test_user):
        """Test string reprezentácie workspace"""
        expected = f"Test Workspace (Owner: {test_user.username})"
        assert str(test_workspace) == expected

    def test_workspace_owner_auto_membership(self, test_user, test_workspace):
        """Test že owner automaticky dostane membership s rolou 'owner'"""
        membership = WorkspaceMembership.objects.get(
            workspace=test_workspace, user=test_user
        )
        assert membership.role == "owner"

    def test_workspace_validate_owner_consistency_owner_role_not_owner(
        self, test_workspace, test_user
    ):
        """Test _validate_owner_consistency keby owner nemá rolu 'owner'"""
        membership = WorkspaceMembership.objects.get(
            workspace=test_workspace, user=test_user
        )
        membership.role = "editor"  # Zmeníme rolu ownera
        membership.save()

        with pytest.raises(ValidationError) as exc_info:
            test_workspace.full_clean()
        assert "Workspace owner must have 'owner' role in membership." in str(
            exc_info.value
        )

    def test_workspace_validate_owner_consistency_owner_no_membership(
        self, test_workspace, test_user
    ):
        """Test _validate_owner_consistency keby owner nemá členstvo"""
        # Odstránime automaticky vytvorené členstvo
        WorkspaceMembership.objects.filter(
            workspace=test_workspace, user=test_user
        ).delete()

        with pytest.raises(ValidationError) as exc_info:
            test_workspace.full_clean()
        assert "Workspace owner must exist in workspace membership." in str(
            exc_info.value
        )

    def test_workspace_member_count_property(
        self, test_workspace, test_user, test_user2
    ):
        """Test the member_count property correctly returns the number of members."""
        # Initial owner membership exists (1 member: test_user)
        assert test_workspace.member_count == 1

        # Add another member (test_user2)
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )
        test_workspace.refresh_from_db()  # Refresh to get updated count
        assert test_workspace.member_count == 2

        # Remove a member (test_user2)
        WorkspaceMembership.objects.get(user=test_user2).delete()
        test_workspace.refresh_from_db()
        assert test_workspace.member_count == 1

    def test_is_workspace_admin_active_admin(
        self, test_workspace, superuser, test_user2
    ):
        """Test is_workspace_admin returns True for an active admin."""
        WorkspaceAdmin.objects.create(
            user=test_user2,
            workspace=test_workspace,
            assigned_by=superuser,
            is_active=True,
        )
        assert Workspace.is_workspace_admin(test_user2, test_workspace) is True

    def test_is_workspace_admin_inactive_admin(
        self, test_workspace, superuser, test_user2
    ):
        """Test is_workspace_admin returns False for an inactive admin."""
        WorkspaceAdmin.objects.create(
            user=test_user2,
            workspace=test_workspace,
            assigned_by=superuser,
            is_active=False,
        )
        assert Workspace.is_workspace_admin(test_user2, test_workspace) is False

    def test_is_workspace_admin_not_admin(self, test_workspace, test_user2):
        """Test is_workspace_admin returns False for a non-admin user."""
        assert Workspace.is_workspace_admin(test_user2, test_workspace) is False

    def test_workspace_change_owner_permission_denied(
        self, mocker, test_workspace, test_user, django_user_model
    ):
        """Test change_owner raises PermissionError if changed_by lacks permission."""
        # Create the missing user explicitly
        test_user3 = django_user_model.objects.create_user(
            username="test_user3",
            email="test3@example.com",
            password="password"
        )
        # Mock _can_change_ownership to return False
        mocker.patch(
            "finance.models.Workspace._can_change_ownership", return_value=False
        )

        with pytest.raises(
            PermissionError, match="User cannot change workspace ownership."
        ):
            test_workspace.change_owner(
                new_owner=test_user3, changed_by=test_user, old_owner_action="remove"
            )

    def test_workspace_change_owner_same_owner(self, test_workspace, test_user):
        """Test change_owner raises ValidationError if new_owner is same as current owner."""
        # test_user is already the owner
        with pytest.raises(
            ValidationError, match="New owner cannot be the same as current owner."
        ):
            test_workspace.change_owner(
                new_owner=test_user, changed_by=test_user, old_owner_action="leave"
            )

    def test_workspace_change_owner_invalid_old_owner_action(
        self, test_workspace, test_user, test_user2
    ):
        """Test change_owner raises ValidationError for an invalid old_owner_action."""
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )
        with pytest.raises(ValidationError) as exc_info:
            test_workspace.change_owner(
                new_owner=test_user2,
                changed_by=test_user,
                old_owner_action="invalid_action",
            )
        assert "old_owner_action must be one of: editor, viewer, remove" in str(
            exc_info.value
        )

    def test_workspace_change_owner_method(self, test_workspace, test_user2):
        """Test metódy change_owner - kompletný flow"""
        old_owner = test_workspace.owner

        # 1. Najprv over že new owner NIE JE členom - change_owner by mal zlyhať
        with pytest.raises(
            ValidationError, match="New owner must be a member of the workspace"
        ):
            test_workspace.change_owner(
                test_user2, old_owner, old_owner_action="editor"
            )

        # 2. Pridaj new ownera ako člena
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )

        # 3. Teraz by change_owner mal prejsť
        test_workspace.change_owner(test_user2, old_owner, old_owner_action="editor")

        # 4. Over že owner sa naozaj zmenil
        test_workspace.refresh_from_db()
        assert test_workspace.owner == test_user2

        # 5. Over že old owner má novú rolu
        old_owner_membership = WorkspaceMembership.objects.get(
            workspace=test_workspace, user=old_owner
        )
        assert old_owner_membership.role == "editor"

    def test_workspace_change_owner_remove_old_owner(
        self, test_workspace, test_user, test_user2, superuser
    ):
        """
        Test change_owner method with old_owner_action='remove'
        Verifies that the old owner's membership is deleted and admin status is deactivated.
        """
        old_owner = test_user # test_user is the initial owner from fixture
        new_owner = test_user2

        # Make new_owner a member first to allow ownership transfer
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=new_owner, role="editor"
        )
        # Make old_owner an admin so we can test deactivation
        WorkspaceAdmin.objects.create(
            user=old_owner,
            workspace=test_workspace,
            assigned_by=superuser,
            is_active=True,
        )

        # Perform the ownership change with "remove" action
        test_workspace.change_owner(
            new_owner=new_owner, changed_by=old_owner, old_owner_action="remove"
        )

        # Verify new owner
        test_workspace.refresh_from_db()
        assert test_workspace.owner == new_owner

        # Verify old owner's membership is removed
        assert not WorkspaceMembership.objects.filter(
            workspace=test_workspace, user=old_owner
        ).exists()

        # Verify old owner's admin status is deactivated
        old_owner_admin = WorkspaceAdmin.objects.get(
            workspace=test_workspace, user=old_owner
        )
        assert old_owner_admin.is_active is False

    def test_workspace_save_updates_membership_on_existing_workspace(self, test_workspace, test_user):
        """
        Test that saving an existing workspace calls _sync_owner_to_membership
        (implicitly verifying the is_new=False branch).
        """
        # Ensure _sync_owner_to_membership is called on update
        with patch.object(test_workspace, "_sync_owner_to_membership") as mock_sync:
            test_workspace.name = "Updated Name"
            test_workspace.save()
            mock_sync.assert_called_once_with(False)

    def test_change_owner_generic_exception(self, mocker, test_workspace, test_user, test_user2):
        """Test change_owner handles generic exceptions during processing."""
        # Make test_user2 a member so transfer can proceed
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )
        # Mock a critical step to raise an exception
        mocker.patch(
            "finance.models.WorkspaceMembership.objects.filter",
            side_effect=Exception("Database error during owner role update"),
        )
        mocker.patch(
            "finance.models.Workspace._can_change_ownership", return_value=True
        )

        with pytest.raises(Exception, match="Database error during owner role update"):
            test_workspace.change_owner(test_user2, test_user, old_owner_action="editor")

    def test_sync_owner_to_membership_generic_exception(self, mocker, test_workspace, test_user):
        """Test _sync_owner_to_membership handles generic exceptions."""
        mocker.patch(
            "finance.models.WorkspaceMembership.objects.update_or_create",
            side_effect=Exception("Membership DB error"),
        )
        with pytest.raises(Exception, match="Membership DB error"):
            test_workspace._sync_owner_to_membership(False) # is_new can be anything for this test

    def test_can_change_ownership_superuser(self, test_workspace, superuser):
        """Test _can_change_ownership returns True for a superuser."""
        assert test_workspace._can_change_ownership(superuser) is True

    def test_can_change_ownership_current_owner(self, test_workspace, test_user):
        """Test _can_change_ownership returns True for the current owner."""
        assert test_workspace._can_change_ownership(test_user) is True

    def test_can_change_ownership_workspace_admin_with_permission(self, test_workspace, superuser, test_user2):
        """Test _can_change_ownership returns True for a workspace admin with can_manage_users."""
        WorkspaceAdmin.objects.create(
            user=test_user2,
            workspace=test_workspace,
            assigned_by=superuser,
            is_active=True,
            can_manage_users=True,
        )
        assert test_workspace._can_change_ownership(test_user2) is True

    def test_can_change_ownership_workspace_admin_without_permission(self, test_workspace, superuser, test_user2):
        """Test _can_change_ownership returns False for a workspace admin without can_manage_users."""
        WorkspaceAdmin.objects.create(
            user=test_user2,
            workspace=test_workspace,
            assigned_by=superuser,
            is_active=True,
            can_manage_users=False, # Explicitly set to False
        )
        assert test_workspace._can_change_ownership(test_user2) is False

    def test_can_change_ownership_regular_member(self, test_workspace, test_user2):
        """Test _can_change_ownership returns False for a regular member."""
        # test_user2 is a regular member (editor in membership)
        # Ensure they are not owner or superuser, and no WorkspaceAdmin assignment
        assert test_workspace._can_change_ownership(test_user2) is False







    def test_get_user_role_in_workspace(
        self, test_workspace, test_user, workspace_member
    ):
        # Test pre owner
        assert (
            Workspace.get_user_role_in_workspace(test_user, test_workspace) == "owner"
        )
        # Test pre member
        assert (
            Workspace.get_user_role_in_workspace(workspace_member.user, test_workspace)
            == "editor"
        )

    def test_get_all_workspace_users_with_roles(self, test_workspace):
        users_data = test_workspace.get_all_workspace_users_with_roles()
        assert len(users_data) > 0


# =============================================================================
# WORKSPACE MEMBERSHIP TESTS
# =============================================================================


class TestWorkspaceMembership:
    """Testy pre WorkspaceMembership model"""

    def test_membership_creation(self, workspace_member, test_workspace, test_user2):
        """Test vytvorenia členstva"""
        assert workspace_member.workspace == test_workspace
        assert workspace_member.user == test_user2
        assert workspace_member.role == "editor"
        assert (
            str(workspace_member)
            == f"{test_user2.username} in {test_workspace.name} as editor"
        )

    def test_membership_default_role(self, test_workspace, test_user2):
        """Test predvolenej role"""
        # test_user2 by nemal byť owner workspace, takže môžeš vytvoriť membership
        membership = WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2
        )

        assert membership.role == "viewer"

    def test_membership_unique_constraint(self, test_workspace, test_user2):
        """Test unikátnosti členstva"""
        # Prvé členstvo
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="viewer"
        )

        # Pokus o duplicitné členstvo by malo spôsobiť IntegrityError
        with pytest.raises(IntegrityError):
            with transaction.atomic():
                WorkspaceMembership.objects.create(
                    workspace=test_workspace, user=test_user2, role="editor"
                )

    def test_membership_role_choices(self, workspace_member):
        """Test platných rolí"""
        valid_roles = ["editor", "viewer"]  # Iba editor a viewer
        assert workspace_member.role in valid_roles

    def test_owner_has_automatic_membership(self, test_workspace, test_user):
        """Test že owner má automaticky vytvorené členstvo"""
        # Owner by mal mať automaticky vytvorené členstvo s rolou 'owner'
        has_membership = WorkspaceMembership.objects.filter(
            workspace=test_workspace, user=test_user
        ).exists()

        assert has_membership, "Owner should have automatic workspace membership"

        # Over rolu
        membership = WorkspaceMembership.objects.get(
            workspace=test_workspace, user=test_user
        )
        assert membership.role == "owner"

    def test_membership_role_choices_only_editor_viewer(self, workspace_member):
        """Test že sú povolené iba role editor a viewer"""
        valid_roles = ["editor", "viewer"]
        assert workspace_member.role in valid_roles

        # Test neplatnej role
        with pytest.raises(ValidationError) as exc_info:
            workspace_member.role = "invalid_role"
            workspace_member.full_clean()

        assert "is not a valid choice" in str(exc_info.value)

    def test_workspace_membership_unique_owner_per_workspace(
        self, test_workspace, test_user2
    ):
        """Test that only one owner role can exist per workspace."""
        # test_workspace already has an owner (test_user)

        # Attempt to create a second owner membership for a different user
        with pytest.raises(IntegrityError) as exc_info:
            with transaction.atomic():
                WorkspaceMembership.objects.create(
                    workspace=test_workspace, user=test_user2, role="owner"
                )
        assert (
            "duplicate key value violates unique constraint" in str(exc_info.value)
            or "UNIQUE constraint failed" in str(exc_info.value)
        )

    def test_workspace_membership_clean_duplicate_membership(
        self, test_workspace, test_user2
    ):
        """Test clean() raises ValidationError if user is already a member."""
        WorkspaceMembership.objects.create(
            workspace=test_workspace, user=test_user2, role="editor"
        )
        duplicate_membership = WorkspaceMembership(
            workspace=test_workspace, user=test_user2, role="viewer"
        )
        with pytest.raises(ValidationError) as exc_info:
            duplicate_membership.clean()
        assert "User is already a member of this workspace." in str(exc_info.value)

    def test_workspace_membership_clean_owner_as_regular_member(
        self, test_workspace, test_user
    ):
        """Test clean() raises ValidationError if workspace owner is added as regular membership."""
        # test_user is the owner, and already has an 'owner' membership.
        # This tests if someone tries to create another membership for the owner with a non-owner role.
        membership_for_owner = WorkspaceMembership(
            workspace=test_workspace, user=test_user, role="editor"
        )
        with pytest.raises(ValidationError) as exc_info:
            membership_for_owner.clean()
        assert "User is already a member of this workspace." in str(
            exc_info.value
        )

    def test_workspace_owner_cannot_be_regular_member(self, test_workspace, test_user):
        """Test že owner nemôže byť pridaný ako regular member"""
        # Owner je už automaticky v memberships, takže testujeme validáciu
        membership = WorkspaceMembership.objects.get(
            workspace=test_workspace, user=test_user
        )

        # Pokus o zmenu roly owner na editor by mal zlyhať
        with pytest.raises(ValidationError):
            membership.role = "editor"
            membership.clean()  # Toto by malo vyhodiť ValidationError


# =============================================================================
# WORKSPACE SETTINGS TESTS
# =============================================================================


class TestWorkspaceSettings:
    """Testy pre WorkspaceSettings model"""

    def test_workspace_settings_creation(self, workspace_settings, test_workspace):
        """Test vytvorenia nastavení workspace"""
        assert workspace_settings.workspace == test_workspace
        assert workspace_settings.domestic_currency == "EUR"
        assert workspace_settings.fiscal_year_start == 1
        assert workspace_settings.display_mode == "month"
        assert workspace_settings.accounting_mode is False
        assert str(workspace_settings) == f"{test_workspace.name} settings"

    def test_workspace_settings_default_values(self, test_workspace):
        """Test predvolených hodnôt"""
        settings = test_workspace.settings
        assert settings.domestic_currency == "EUR"
        assert settings.fiscal_year_start == 1
        assert settings.display_mode == "month"
        assert settings.accounting_mode is False

    def test_workspace_settings_currency_choices(self, workspace_settings):
        """Test platných mien"""
        valid_currencies = ["EUR", "USD", "GBP", "CHF", "PLN"]
        assert workspace_settings.domestic_currency in valid_currencies

    def test_workspace_settings_display_mode_choices(self, workspace_settings):
        """Test platných módov zobrazenia"""
        valid_modes = ["month", "day"]
        assert workspace_settings.display_mode in valid_modes

    def test_workspace_settings_clean_invalid_fiscal_year_start(self, workspace_settings):
        """Test clean() raises ValidationError for an invalid fiscal_year_start."""
        workspace_settings.fiscal_year_start = 13 # Invalid month
        with pytest.raises(ValidationError) as exc_info:
            workspace_settings.full_clean()
        assert "Invalid fiscal year start month." in str(exc_info.value)



# =============================================================================
# EXPENSE CATEGORY VERSION TESTS
# =============================================================================


class TestExpenseCategoryVersion:
    """Testy pre ExpenseCategoryVersion model"""

    def test_expense_version_creation(
        self, expense_category_version, test_workspace, test_user
    ):
        """Test vytvorenia verzie expense kategórií"""
        assert expense_category_version.workspace == test_workspace
        assert expense_category_version.name == "Expense Categories v1"
        assert expense_category_version.created_by == test_user
        assert expense_category_version.is_active is True
        assert str(expense_category_version) == f"{test_workspace.name} - Expense"

    def test_expense_version_validation_name_too_short(self, test_workspace, test_user):
        """Test validácie príliš krátkeho názvu verzie"""
        version = ExpenseCategoryVersion(
            workspace=test_workspace, name="A", created_by=test_user
        )
        with pytest.raises(ValidationError) as exc_info:
            version.full_clean()
        assert "Version name must be at least 2 characters long" in str(exc_info.value)


# =============================================================================
# INCOME CATEGORY VERSION TESTS
# =============================================================================


class TestIncomeCategoryVersion:
    """Testy pre IncomeCategoryVersion model"""

    def test_income_version_creation(
        self, income_category_version, test_workspace, test_user
    ):
        """Test vytvorenia verzie income kategórií"""
        assert income_category_version.workspace == test_workspace
        assert income_category_version.name == "Income Categories v1"
        assert income_category_version.created_by == test_user
        assert income_category_version.is_active is True
        assert str(income_category_version) == f"{test_workspace.name} - Income"

    def test_income_version_validation_name_too_short(self, test_workspace, test_user):
        """Test validácie príliš krátkeho názvu verzie"""
        version = IncomeCategoryVersion(
            workspace=test_workspace, name="A", created_by=test_user
        )
        with pytest.raises(ValidationError) as exc_info:
            version.full_clean()
        assert "Version name must be at least 2 characters long" in str(exc_info.value)



# =============================================================================
# EXPENSE CATEGORY TESTS
# =============================================================================


class TestExpenseCategory:
    """Testy pre ExpenseCategory model"""

    def test_expense_category_creation(
        self, expense_root_category, expense_category_version
    ):
        assert expense_root_category.version == expense_category_version
        assert expense_root_category.name == "Potraviny"
        assert expense_root_category.level == 1
        assert str(expense_root_category) == "Potraviny (Level 1)"

    def test_expense_category_is_root_property(
        self, expense_root_category, expense_child_category
    ):
        """Test root property"""
        assert expense_root_category.is_root is True
        assert expense_child_category.is_root is False

    def test_expense_category_is_leaf_property(
        self, expense_root_category, expense_child_category
    ):
        """Test leaf property"""
        assert expense_root_category.is_leaf is False  # Má child
        # Vytvoríme leaf kategóriu
        leaf_category = ExpenseCategory.objects.create(
            version=expense_root_category.version, name="Leaf Category", level=3
        )
        assert leaf_category.is_leaf is True

    def test_expense_category_add_child_success(self, expense_category_version):
        parent = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent", level=1
        )
        child = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child", level=2
        )
        parent.add_child(child)
        assert child in parent.children.all()

    def test_get_descendants_error_handling(self, mocker, expense_category_version):
        """Test that get_descendants handles exceptions gracefully and returns an empty set."""
        root = ExpenseCategory.objects.create(
            version=expense_category_version, name="Root", level=1
        )
        # Mock the children.all() method to raise an exception
        mocker.patch.object(
            root.children, "all", side_effect=Exception("Mocked children error")
        )

        descendants = root.get_descendants()
        assert descendants == set()

    def test_is_ancestor_of_error_handling(self, mocker, expense_category_version):
        """Test that _is_ancestor_of handles exceptions gracefully and returns False."""
        cat1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Cat1", level=1
        )
        # FIXED: Create cat2 before using it
        cat2 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Cat2", level=2
        )

        # You likely wanted to mock here to trigger the error,
        # ensuring the exception happens during the check.
        mocker.patch.object(cat1.children, "all", side_effect=Exception("Mocked error"))

        # Ensure the mocked method is called during ancestry check within _is_ancestor_of
        result = cat1._is_ancestor_of(cat2)
        assert result is False

    def test_expense_category_add_child_with_existing_parent(
        self, expense_category_version
    ):
        """Test pokusu o pridanie child kategórie ktorá už má parenta"""
        parent1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent1", level=1
        )
        parent2 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent2", level=1
        )
        child = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child", level=2
        )

        parent1.add_child(child)

        with pytest.raises(ValidationError) as exc_info:
            parent2.add_child(child)

        assert "already has a parent" in str(exc_info.value)

    def test_expense_category_validation_invalid_level(self, expense_category_version):
        """
        Test validácie neplatnej úrovne.
        Pozor: expense_category_version má levels_count=5, čiže povolené sú 1-5.
        Skúsime level 6.
        """
        category = ExpenseCategory(
            version=expense_category_version, name="Test", level=6
        )
        with pytest.raises(ValidationError) as exc_info:
            category.full_clean()

        # Validácia vráti správu v závislosti od levels_count
        # Keďže levels_count=5, validný range je 1..5
        assert "Category level must be between 1 and 5" in str(exc_info.value)

    def test_expense_category_validation_name_too_short(self, expense_category_version):
        """
        Test validácie príliš krátkeho názvu.
        Musíme použiť validný level (napr. 1), inak dostaneme chybu aj o leveli.
        """
        # Nastavíme validný level 1 (pretože levels_count=5, min_level=1)
        category = ExpenseCategory(version=expense_category_version, name="A", level=1)

        with pytest.raises(ValidationError) as exc_info:
            category.full_clean()

        # Keďže môže nastať viacero chýb (napr. ak by level nebol ok),
        # pozrieme sa priamo do slovníka chýb, ak je dostupný
        if hasattr(exc_info.value, "message_dict"):
            assert (
                "Category name must be at least 2 characters long"
                in exc_info.value.message_dict["__all__"][0]
            )
        else:
            assert "Category name must be at least 2 characters long" in str(
                exc_info.value
            )

    def test_category_circular_reference_prevention(self, expense_category_version):
        cat1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Cat1", level=1
        )
        cat2 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Cat2", level=2
        )
        cat1.add_child(cat2)

        with pytest.raises(ValidationError):
            cat2.add_child(cat1)

    def test_get_descendants(self, expense_category_version):
        """Test the get_descendants method."""
        root = ExpenseCategory.objects.create(
            version=expense_category_version, name="Root", level=1
        )
        child1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child1", level=2
        )
        child2 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child2", level=2
        )
        grandchild1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="GC1", level=3
        )

        root.children.add(child1, child2)
        child1.children.add(grandchild1)

        # Test without self
        descendants = root.get_descendants(include_self=False)
        assert descendants == {child1, child2, grandchild1}

        # Test with self
        descendants_with_self = root.get_descendants(include_self=True)
        assert descendants_with_self == {root, child1, child2, grandchild1}

        # Test leaf node
        leaf = ExpenseCategory.objects.create(
            version=expense_category_version, name="Leaf", level=5
        )
        assert leaf.get_descendants() == set()

        # Test intermediate node
        assert child1.get_descendants() == {grandchild1}

    def test_category_validation_root_with_parent(self, expense_category_version):
        """Test that a root category (level 1) cannot have a parent."""
        root1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Root1", level=1
        )
        root2 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Root2", level=1
        )

        # Manually add parent relationship, bypassing add_child
        root2.parents.add(root1)
        with pytest.raises(
            ValidationError, match="Level 1 category cannot have a parent"
        ):
            root2.full_clean()

    def test_category_validation_non_root_without_parent(
        self, expense_category_version
    ):
        """Test that a non-root category must have exactly one parent."""
        child = ExpenseCategory(version=expense_category_version, name="Child", level=2)
        child.save()  # No parent assigned
        with pytest.raises(
            ValidationError, match="Non-root categories must have exactly one parent"
        ):
            child.full_clean()

    def test_category_validation_leaf_with_children(self, expense_category_version):
        """Test that a leaf category (level 5) cannot have children."""
        parent_level4 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent Level 4", level=4
        )
        leaf = ExpenseCategory.objects.create(
            version=expense_category_version, name="Leaf", level=5
        )
        parent_level4.add_child(leaf)

        # Now, try to add a child to the leaf category (which is invalid)
        child_to_leaf = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child to Leaf", level=6
        ) # This child will have a level higher than the leaf, which is a different error condition later
        leaf.children.add(child_to_leaf)

        with pytest.raises(ValidationError) as exc_info:
            leaf.full_clean()

        assert (
            f"Leaf category '{leaf.name}' (level 5) should not have children"
            in exc_info.value.messages
        )

    def test_category_validation_non_leaf_without_children(
        self, expense_category_version
    ):
        """Test that a non-leaf category must have at least one child."""
        parent = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent", level=1
        )
        non_leaf = ExpenseCategory.objects.create(
            version=expense_category_version, name="Non-leaf", level=4
        )
        non_leaf.parents.add(parent)  # Satisfy parent requirement
        parent.children.add(non_leaf)  # Satisfy parent's child requirement

        with pytest.raises(ValidationError) as exc_info:
            non_leaf.full_clean()

        assert (
            f"Non-leaf category '{non_leaf.name}' (level 4) must have at least one child"
            in exc_info.value.messages
        )

    def test_category_validation_child_with_other_parent(
        self, expense_category_version
    ):
        """Test that a child cannot have another parent besides the current one being cleaned."""
        parent1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent1", level=1
        )
        parent2 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent2", level=1
        )
        child = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child", level=2
        )

        parent1.add_child(child) # child now has parent1

        # Now, try to add parent2 as an additional parent to child (this is not direct,
        # but the clean method of parent2 should catch if child is trying to be
        # a child of parent2 while already having parent1)
        # This scenario is a bit tricky to trigger via parent2.full_clean() directly
        # if the child relationship is not explicit.
        # The validation happens during parent.full_clean() when iterating its children.
        # So we create a transient state that clean() should catch.
        parent2.children.add(child) # Add child to parent2's children set for clean() to check

        with pytest.raises(ValidationError) as exc_info:
            parent2.full_clean()
        assert (
            f"Child '{child.name}' already has another parent"
            in exc_info.value.messages
        )

    def test_category_validation_child_level_not_higher_than_parent(
        self, expense_category_version
    ):
        """Test that a child category must have a higher level than its parent."""
        parent = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent", level=2
        )
        child_invalid_level = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child Invalid Level", level=2
        )
        # We want to test that adding a child with a non-higher level raises ValidationError
        # The 'Non-leaf category must have at least one child' validation requires the parent to have a child.
        # So, first add a valid child to 'parent' to make it a non-leaf.
        valid_child = ExpenseCategory.objects.create(
            version=expense_category_version, name="Valid Child", level=3
        )
        parent.children.add(valid_child)

        with pytest.raises(ValidationError) as exc_info:
            parent.add_child(child_invalid_level) # Attempt to add a child with same level
        assert "Child category must have higher level than parent" in str(exc_info.value)

    def test_is_ancestor_of_no_potential_child_id(self, expense_category_version):
        """Test _is_ancestor_of returns False if potential_child has no ID."""
        cat = ExpenseCategory.objects.create(
            version=expense_category_version, name="Cat", level=1
        )
        mock_child = Mock(id=None) # Mock child with no ID
        assert cat._is_ancestor_of(mock_child) is False

    # TODO: Refactor this test to avoid globally patching collections.deque, as it causes INTERNALERRORs in pytest.
    # def test_is_ancestor_of_depth_limit_reached(self, expense_category_version, mocker):
    #     """Test _is_ancestor_of logs warning when depth limit is reached."""
    #     root = ExpenseCategory.objects.create(
    #         version=expense_category_version, name="Root", level=1
    #     )
    #     child = ExpenseCategory.objects.create(
    #         version=expense_category_version, name="Child", level=2
    #     )
    #     # Create a mock deque object
    #     mock_deque_instance = Mock()
    #     # Configure popleft to return 'child' 101 times, simulating a deep chain
    #     mock_deque_instance.popleft.side_effect = [child] * 101
    #     # Configure extend to do nothing or capture arguments if needed for more complex tests
    #     mock_deque_instance.extend.return_value = None

    #     # Patch the collections.deque constructor in finance.models to return our mock deque
    #     mocker.patch("finance.models.collections.deque", return_value=mock_deque_instance)
    #     # Prevent actual DB query for children
    #     mocker.patch("finance.models.ExpenseCategory.children.all", return_value=[])

    #     with patch("finance.models.logger") as mock_logger:
    #         root._is_ancestor_of(child) # Call with arbitrary child, just to trigger path
    #         mock_logger.warning.assert_called_with(
    #             "Ancestry check depth limit reached",
    #             extra=frozenset({
    #                 ('root_category_id', root.id),
    #                 ('target_category_id', child.id),
    #                 ('nodes_checked', 101),
    #                 ('max_depth', 100),
    #                 ('action', 'ancestry_check_depth_limit'),
    #                 ('component', 'ExpenseCategory')
    #             }),
    #         )

    def test_clean_invalid_level_hierarchy_existing_relationship(self, expense_category_version):
        """Test clean() raises ValidationError for invalid level hierarchy in existing relationships."""
        parent = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent", level=1
        )
        child_invalid_level = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child Invalid Level", level=1
        )
        parent.children.add(child_invalid_level) # Create the invalid relationship

        with pytest.raises(ValidationError) as exc_info:
            parent.full_clean() # Validate the parent, which checks its children
        assert "Child category must have higher level than parent" in str(exc_info.value)
            
    def test_clean_circular_reference_existing_data(self, expense_category_version):
        """Test clean() raises ValidationError for circular reference in existing data."""
        cat1 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Cat1", level=1
        )
        cat2 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Cat2", level=2
        )
        cat1.children.add(cat2)
        cat2.children.add(cat1) # Manually create circular reference
            
        with pytest.raises(ValidationError) as exc_info:
            cat1.full_clean()
        assert "Level 1 category cannot have a parent" in str(exc_info.value)
            
            
            # =============================================================================
            # INCOME CATEGORY TESTS (podobné ako expense)
            # =============================================================================


class TestIncomeCategory:
    """Testy pre IncomeCategory model"""

    def test_income_category_creation(
        self, income_root_category, income_category_version
    ):
        """Test vytvorenia income kategórie"""
        assert income_root_category.version == income_category_version
        assert income_root_category.name == "Príjmy"
        assert income_root_category.level == 1
        assert str(income_root_category) == "Príjmy (Level 1)"

    def test_income_category_is_root_property(
        self, income_root_category, income_child_category
    ):
        """Test is_root property for income categories."""
        assert income_root_category.is_root is True
        assert income_child_category.is_root is False

    def test_income_category_is_leaf_property(
        self, income_root_category, income_child_category
    ):
        """Test is_leaf property for income categories."""
        assert income_root_category.is_leaf is False  # Has child

        # Create a leaf category
        leaf_category = IncomeCategory.objects.create(
            version=income_root_category.version, name="Leaf Income Category", level=3
        )
        assert leaf_category.is_leaf is True

    def test_income_category_add_child_success(self, income_category_version):
        parent = IncomeCategory.objects.create(
            version=income_category_version, name="Parent Income", level=1
        )
        child = IncomeCategory.objects.create(
            version=income_category_version, name="Child Income", level=2
        )
        parent.add_child(child)
        assert child in parent.children.all()

    def test_income_category_add_child_with_existing_parent(
        self, income_category_version
    ):
        """Test attempt to add a child category that already has a parent."""
        parent1 = IncomeCategory.objects.create(
            version=income_category_version, name="Parent1 Income", level=1
        )
        parent2 = IncomeCategory.objects.create(
            version=income_category_version, name="Parent2 Income", level=1
        )
        child = IncomeCategory.objects.create(
            version=income_category_version, name="Child Income", level=2
        )

        parent1.add_child(child)

        with pytest.raises(ValidationError) as exc_info:
            parent2.add_child(child)

        assert "already has a parent" in str(exc_info.value)

    def test_income_category_validation_invalid_level(self, income_category_version):
        """Test validation of invalid level for income category."""
        category = IncomeCategory(
            version=income_category_version, name="Test Income", level=6
        )
        with pytest.raises(ValidationError) as exc_info:
            category.full_clean()
        assert "Category level must be between 1 and 5" in str(exc_info.value)

    def test_income_category_circular_reference_prevention(self, income_category_version):
        cat1 = IncomeCategory.objects.create(
            version=income_category_version, name="IncomeCat1", level=1
        )
        cat2 = IncomeCategory.objects.create(
            version=income_category_version, name="IncomeCat2", level=2
        )
        cat1.add_child(cat2)

        with pytest.raises(ValidationError):
            cat2.add_child(cat1)

    def test_income_category_hierarchy(
        self, income_root_category, income_child_category
    ):
        """Test hierarchie income kategórií"""
        assert income_child_category in income_root_category.children.all()
        assert income_root_category in income_child_category.parents.all()

    def test_get_descendants_income(self, income_category_version):
        """Test the get_descendants method for IncomeCategory."""
        root = IncomeCategory.objects.create(
            version=income_category_version, name="Root", level=1
        )
        child1 = IncomeCategory.objects.create(
            version=income_category_version, name="Child1", level=2
        )
        grandchild1 = IncomeCategory.objects.create(
            version=income_category_version, name="GC1", level=3
        )

        root.children.add(child1)
        child1.children.add(grandchild1)

        descendants = root.get_descendants(include_self=False)
        assert descendants == {child1, grandchild1}

    def test_get_descendants_error_handling_income(self, mocker, income_category_version):
        """Test that get_descendants handles exceptions gracefully and returns an empty set for IncomeCategory."""
        root = IncomeCategory.objects.create(
            version=income_category_version, name="Root Income", level=1
        )
        # Mock the children.all() method to raise an exception
        mocker.patch.object(
            root.children, "all", side_effect=Exception("Mocked children error")
        )

        descendants = root.get_descendants()
        assert descendants == set()

    def test_is_ancestor_of_error_handling_income(self, mocker, income_category_version):
        """Test that _is_ancestor_of handles exceptions gracefully."""
        cat1 = IncomeCategory.objects.create(
            version=income_category_version, name="IncomeCat1", level=1
        )
        cat2 = IncomeCategory.objects.create(
            version=income_category_version, name="IncomeCat2", level=2
        )

        # FIXED: Patch the 'all' method on the specific instance's manager
        mocker.patch.object(
            cat1.children,
            "all",
            side_effect=Exception("Mocked ancestor error")
        )

        # Ensure the mocked method is called during ancestry check within _is_ancestor_of
        result = cat1._is_ancestor_of(cat2)

        # Assuming the method catches the exception and returns False
        assert result is False

    def test_income_category_validation_root_with_parent(self, income_category_version):
        """Test that a root income category (level 1) cannot have a parent."""
        root1 = IncomeCategory.objects.create(
            version=income_category_version, name="Root1", level=1
        )
        root2 = IncomeCategory.objects.create(
            version=income_category_version, name="Root2", level=1
        )

        root2.parents.add(root1)
        with pytest.raises(
            ValidationError, match="Level 1 category cannot have a parent"
        ):
            root2.full_clean()


    def test_income_category_validation_non_leaf_without_children(
        self, income_category_version
    ):
        """Test that a non-leaf income category must have at least one child."""
        parent = IncomeCategory.objects.create(
            version=income_category_version, name="Parent Income", level=1
        )
        non_leaf = IncomeCategory.objects.create(
            version=income_category_version, name="Non-leaf Income", level=4
        )
        non_leaf.parents.add(parent)
        parent.children.add(non_leaf)

        with pytest.raises(ValidationError) as exc_info:
            non_leaf.full_clean()

        assert (
            f"Non-leaf category '{non_leaf.name}' (level 4) must have at least one child"
            in exc_info.value.messages
        )

    def test_income_category_validation_leaf_with_children(self, income_category_version):
        """Test that a leaf income category (level 5) cannot have children."""
        parent_level4 = IncomeCategory.objects.create(
            version=income_category_version, name="Parent Income Level 4", level=4
        )
        leaf = IncomeCategory.objects.create(
            version=income_category_version, name="Leaf Income", level=5
        )
        parent_level4.add_child(leaf)

        child_to_leaf = IncomeCategory.objects.create(
            version=income_category_version, name="Child to Leaf Income", level=6
        )
        leaf.children.add(child_to_leaf)

        with pytest.raises(ValidationError) as exc_info:
            leaf.full_clean()

        assert (
            f"Leaf category '{leaf.name}' (level 5) should not have children"
            in exc_info.value.messages
        )

    def test_income_category_validation_child_with_other_parent(
        self, income_category_version
    ):
        """Test that a child income category cannot have another parent besides the current one being cleaned."""
        parent1 = IncomeCategory.objects.create(
            version=income_category_version, name="Income Parent1", level=1
        )
        parent2 = IncomeCategory.objects.create(
            version=income_category_version, name="Income Parent2", level=1
        )
        child = IncomeCategory.objects.create(
            version=income_category_version, name="Income Child", level=2
        )

        parent1.add_child(child)
        parent2.children.add(child)

        with pytest.raises(ValidationError) as exc_info:
            parent2.full_clean()
        assert (
            f"Child '{child.name}' already has another parent"
            in exc_info.value.messages
        )

    def test_income_category_validation_child_level_not_higher_than_parent(
        self, income_category_version
    ):
        """Test that a child income category must have a higher level than its parent."""
        parent = IncomeCategory.objects.create(
            version=income_category_version, name="Income Parent", level=2
        )
        child_invalid_level = IncomeCategory.objects.create(
            version=income_category_version, name="Income Child Invalid Level", level=2
        )
        # We want to test that adding a child with a non-higher level raises ValidationError
        # The 'Non-leaf category must have at least one child' validation requires the parent to have a child.
        # So, first add a valid child to 'parent' to make it a non-leaf.
        valid_child = IncomeCategory.objects.create(
            version=income_category_version, name="Income Valid Child", level=3
        )
        parent.children.add(valid_child)

        with pytest.raises(ValidationError) as exc_info:
            parent.add_child(child_invalid_level) # Attempt to add a child with same level
        assert "Child category must have higher level than parent" in str(exc_info.value)

    def test_clean_invalid_level_hierarchy_existing_income_relationship(self, income_category_version):
        """Test clean() raises ValidationError for invalid level hierarchy in existing IncomeCategory relationships."""
        parent = IncomeCategory.objects.create(
            version=income_category_version, name="Income Parent", level=1
        )
        child_invalid_level = IncomeCategory.objects.create(
            version=income_category_version, name="Income Child Invalid Level", level=1
        )
        parent.children.add(child_invalid_level) # Create the invalid relationship

        with pytest.raises(ValidationError) as exc_info:
            parent.full_clean() # Validate the parent, which checks its children
        assert "Child category must have higher level than parent" in str(exc_info.value)

    def test_clean_circular_income_reference_existing_data(self, income_category_version):
        """Test clean() raises ValidationError for circular reference in existing IncomeCategory data."""
        cat1 = IncomeCategory.objects.create(
            version=income_category_version, name="Income Cat1", level=1
        )
        cat2 = IncomeCategory.objects.create(
            version=income_category_version, name="Income Cat2", level=2
        )
        cat1.children.add(cat2)
        cat2.children.add(cat1) # Manually create circular reference

        with pytest.raises(ValidationError) as exc_info:
            cat1.full_clean()
        assert "Level 1 category cannot have a parent" in str(exc_info.value)




# =============================================================================
# CATEGORY PROPERTY TESTS
# =============================================================================


class TestExpenseCategoryProperty:
    """Testy pre ExpenseCategoryProperty"""

    def test_expense_property_creation(
        self, expense_category_property, expense_root_category
    ):
        """Test vytvorenia expense property"""
        assert expense_category_property.category == expense_root_category
        assert expense_category_property.property_type == "cost"
        assert str(expense_category_property) == f"{expense_root_category.name} - cost"

    def test_expense_property_choices(self, expense_category_property):
        """Test platných property typov"""
        valid_types = ["cost", "expense"]
        assert expense_category_property.property_type in valid_types


class TestIncomeCategoryProperty:
    """Testy pre IncomeCategoryProperty"""

    def test_income_property_creation(
        self, income_category_property, income_root_category
    ):
        """Test vytvorenia income property"""
        assert income_category_property.category == income_root_category
        assert income_category_property.property_type == "income"
        assert str(income_category_property) == f"{income_root_category.name} - income"


# =============================================================================
# EXCHANGE RATE TESTS
# =============================================================================


class TestExchangeRate:
    """Testy pre ExchangeRate model"""

    @pytest.mark.django_db
    def test_exchange_rate_creation(self, exchange_rate_usd):
        """Test vytvorenia výmenného kurzu"""
        assert exchange_rate_usd.currency == "USD"
        assert exchange_rate_usd.rate_to_eur == Decimal("0.85")
        assert str(exchange_rate_usd) == f"USD - 0.85 ({exchange_rate_usd.date})"

    @pytest.mark.django_db
    def test_exchange_rate_validation_positive_rate(self):
        """Test validácie kladného kurzu"""
        from django.core.exceptions import ValidationError
        from django.utils import timezone

        from finance.models import ExchangeRate

        rate = ExchangeRate(
            currency="USD", rate_to_eur=-0.5, date=timezone.now().date()  # Záporný kurz
        )
        with pytest.raises(ValidationError) as exc_info:
            rate.full_clean()

        assert "Exchange rate must be positive" in str(exc_info.value)

    @pytest.mark.django_db
    def test_exchange_rate_validation_currency_length(self):
        """Test validácie dĺžky kódu meny"""
        from django.core.exceptions import ValidationError
        from django.utils import timezone

        from finance.models import ExchangeRate

        rate = ExchangeRate(
            currency="US", rate_to_eur=1.0, date=timezone.now().date()  # Príliš krátky
        )
        with pytest.raises(ValidationError) as exc_info:
            rate.full_clean()

        assert "Currency code must be 3 characters long" in str(exc_info.value)

    @pytest.mark.django_db
    def test_exchange_rate_unique_constraint(self, exchange_rate_usd):
        """Test unikátnosti kurzu pre dátum a menu"""
        with pytest.raises(Exception):  # Môže byť IntegrityError alebo ValidationError
            ExchangeRate.objects.create(
                currency=exchange_rate_usd.currency,
                rate_to_eur=0.90,
                date=exchange_rate_usd.date,
            )


# =============================================================================
# TAGS TESTS (Nové)
# =============================================================================


class TestTags:
    """Testy pre Tags model"""

    def test_tag_creation(self, tag_potraviny):
        assert tag_potraviny.name == "potraviny"

    def test_tag_lowercase_enforced(self, test_workspace):
        tag = Tags.objects.create(workspace=test_workspace, name="BigLetter")
        assert tag.name == "bigletter"

    def test_tag_unique_constraint(self, test_workspace):
        """Test that tag names are unique within a workspace."""
        Tags.objects.create(workspace=test_workspace, name="unique-tag")
        with pytest.raises(IntegrityError):
            with transaction.atomic():
                Tags.objects.create(workspace=test_workspace, name="unique-tag")

    def test_tag_unique_in_different_workspaces(self, test_workspace, test_user2):
        """Test that the same tag name can exist in different workspaces."""
        workspace2 = Workspace.objects.create(name="Workspace 2", owner=test_user2)
        Tags.objects.create(workspace=test_workspace, name="shared-tag")
        try:
            Tags.objects.create(workspace=workspace2, name="shared-tag")
        except IntegrityError:
            pytest.fail("Should be able to create same tag in a different workspace.")


# =============================================================================
# TRANSACTION TESTS
# =============================================================================


class TestTransaction:
    """Testy pre Transaction model"""

    def test_expense_transaction_creation(
        self, expense_transaction, test_user, test_workspace
    ):
        """Test vytvorenia expense transakcie s tagmi"""
        assert expense_transaction.user == test_user
        assert expense_transaction.workspace == test_workspace
        assert expense_transaction.type == "expense"
        assert expense_transaction.original_amount == 100.50

        # Overenie M2M tagov
        tag_names = list(expense_transaction.tags.values_list("name", flat=True))
        assert "potraviny" in tag_names
        assert "nakup" in tag_names

    def test_income_transaction_creation(
        self, income_transaction, test_user, test_workspace
    ):
        """Test vytvorenia income transakcie"""
        assert income_transaction.user == test_user
        assert income_transaction.workspace == test_workspace
        assert income_transaction.type == "income"
        assert income_transaction.original_amount == 2000.00

    def test_transaction_category_property(
        self, expense_transaction, income_transaction
    ):
        """Test category property"""
        assert expense_transaction.category == expense_transaction.expense_category
        assert income_transaction.category == income_transaction.income_category

    def test_transaction_validation_both_categories(
        self, test_user, test_workspace, expense_root_category, income_root_category
    ):
        """Test validácie - obe kategórie naraz"""
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            income_category=income_root_category,
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert "Transaction can have only one category type" in str(exc_info.value)

    def test_transaction_validation_no_category(self, test_user, test_workspace):
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert "Transaction must have one category" in str(exc_info.value)

    def test_transaction_validation_type_category_mismatch(
        self, test_user, test_workspace, income_root_category
    ):
        """Test validácie - nesúlad typu a kategórie"""
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type="expense",  # Expense type
            income_category=income_root_category,  # Income category
            original_amount=100.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert "Expense transaction cannot have income category" in str(exc_info.value)

    def test_transaction_validation_negative_amount(
        self, test_user, test_workspace, expense_root_category
    ):
        """Test validácie - záporná suma"""
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=-50.00,  # Záporná suma
            original_currency="EUR",
            date=timezone.now().date(),
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert "Transaction amount must be positive" in str(exc_info.value)

    def test_transaction_month_calculation(
        self, test_user, test_workspace, expense_root_category
    ):
        """Test automatického výpočtu mesiaca"""
        test_date = timezone.datetime(2024, 1, 15).date()
        expected_month = timezone.datetime(2024, 1, 1).date()

        transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=100.00,
            original_currency="EUR",
            date=test_date,
        )

        assert transaction.month == expected_month

    def test_transaction_save_method_month_calculation_on_update(
        self, test_user, test_workspace, expense_root_category
    ):
        """Test that the 'month' field is recalculated when 'date' is updated."""
        initial_date = timezone.datetime(2024, 1, 15).date()
        updated_date = timezone.datetime(2024, 2, 20).date()
        expected_month_after_update = timezone.datetime(2024, 2, 1).date()

        transaction_obj = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=100.00,
            original_currency="EUR",
            date=initial_date,
        )

        assert transaction_obj.month == timezone.datetime(2024, 1, 1).date()

        # Update the date and save
        transaction_obj.date = updated_date
        transaction_obj.save()
        transaction_obj.refresh_from_db()

        assert transaction_obj.month == expected_month_after_update

    def test_transaction_needs_recalculation_for_new_instance(
        self, test_user, test_workspace, expense_root_category
    ):
        """Test _needs_recalculation returns True for a new, unsaved transaction."""
        new_transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=50.00,
            original_currency="EUR",
            date=timezone.now().date(),
        )
        assert new_transaction._needs_recalculation() is True

    def test_recalculate_domestic_amount_with_logging_error_handling(
        self, mocker, expense_transaction
    ):
        """
        Test that _recalculate_domestic_amount_with_logging handles exceptions
        and sets amount_domestic to original_amount.
        """
        original_amount = expense_transaction.original_amount
        # Mock the external service function to raise an exception
        mocker.patch(
            "finance.utils.currency_utils.recalculate_transactions_domestic_amount",
            side_effect=Exception("Mocked currency conversion error"),
        )
        # Ensure initial domestic amount is different for the test
        expense_transaction.amount_domestic = Decimal("1.00")
        expense_transaction.save()
        expense_transaction.refresh_from_db()

        # Call the method that includes error handling
        expense_transaction._recalculate_domestic_amount_with_logging()
        expense_transaction.save() # Save to persist the change from the method
        expense_transaction.refresh_from_db()

        # Verify that amount_domestic was reset to original_amount
        assert expense_transaction.amount_domestic == original_amount

    def test_transaction_string_representation(self, expense_transaction, test_user):
        """Test string reprezentácie transakcie"""
        expected = f"{test_user} | expense | {expense_transaction.amount_domestic} EUR"
        assert str(expense_transaction) == expected

    def test_transaction_domestic_recalculation(
        self, transaction_usd_currency, exchange_rate_usd
    ):
        """Test automatického prepočtu domácej sumy"""

        # Pôvodná hodnota (vytvorená vo fixture): 100 USD * 0.85 = 85.00 EUR
        original_domestic = transaction_usd_currency.amount_domestic
        assert original_domestic == Decimal("85.00")

        # Zmena pôvodnej sumy na 150 USD
        transaction_usd_currency.original_amount = 150.00
        transaction_usd_currency.save()

        # Overenie prepočtu: 150 * 0.85 = 127.50
        transaction_usd_currency.refresh_from_db()

        assert transaction_usd_currency.amount_domestic == Decimal("127.50")

    def test_transaction_recalculation_on_currency_change(
        self, transaction_usd_currency, exchange_rate_usd
    ):
        """Test that recalculation is triggered on original_currency change."""
        # Add a rate for GBP for the transaction's date
        gbp_rate = Decimal("0.75")
        ExchangeRate.objects.create(
            currency="GBP", rate_to_eur=gbp_rate, date=transaction_usd_currency.date
        )

        transaction_usd_currency.original_currency = "GBP"
        transaction_usd_currency.save()
        transaction_usd_currency.refresh_from_db()

        expected_amount = Decimal(transaction_usd_currency.original_amount) * gbp_rate
        assert transaction_usd_currency.amount_domestic == expected_amount.quantize(
            Decimal("0.01")
        )

    def test_transaction_recalculation_on_date_change(
        self, transaction_usd_currency, exchange_rate_usd
    ):
        """Test that recalculation is triggered on date change."""
        # Add a new rate for a different date
        new_date = transaction_usd_currency.date - timezone.timedelta(days=1)
        new_rate = Decimal("0.90")
        ExchangeRate.objects.create(currency="USD", rate_to_eur=new_rate, date=new_date)

        transaction_usd_currency.date = new_date
        transaction_usd_currency.save()
        transaction_usd_currency.refresh_from_db()

        expected_amount = Decimal(transaction_usd_currency.original_amount) * new_rate
        assert transaction_usd_currency.amount_domestic == expected_amount.quantize(
            Decimal("0.01")
        )

    def test_transaction_no_recalculation_on_other_fields(
        self, transaction_usd_currency, exchange_rate_usd
    ):
        """Test that recalculation is not triggered on irrelevant field changes."""
        # amount_domestic is 85.00 initially
        assert transaction_usd_currency.amount_domestic == Decimal("85.00")

        # We need to spy on the recalculation method.
        # For now, we'll just check if the value changes. A mock would be better.
        transaction_usd_currency.note_manual = "A new note"
        transaction_usd_currency.save()
        transaction_usd_currency.refresh_from_db()

        # The amount should not have changed
        assert transaction_usd_currency.amount_domestic == Decimal("85.00")

    # =============================================================================


# TRANSACTION DRAFT TESTS
# =============================================================================


class TestTransactionDraft:
    """Testy pre TransactionDraft model"""

    def test_draft_creation(self, transaction_draft, test_user, test_workspace):
        """Test vytvorenia draftu"""
        assert transaction_draft.user == test_user
        assert transaction_draft.workspace == test_workspace
        assert transaction_draft.draft_type == "expense"
        assert len(transaction_draft.transactions_data) == 1
        assert transaction_draft.transactions_data[0]["original_amount"] == 50.00

    def test_draft_transactions_count(self, transaction_draft):
        """Test počtu transakcií v drafte"""
        assert transaction_draft.get_transactions_count() == 1

    def test_draft_string_representation(self, transaction_draft, test_user):
        """Test string reprezentácie draftu"""
        expected = f"Draft: {test_user} | expense | 1 transactions"
        assert str(transaction_draft) == expected

    def test_draft_validation_invalid_data_structure(self, test_user, test_workspace):
        """Test validácie neplatnej štruktúry dát"""
        draft = TransactionDraft(
            user=test_user,
            workspace=test_workspace,
            transactions_data="not a list",  # Nesprávny typ
            draft_type="expense",
        )
        with pytest.raises(ValidationError) as exc_info:
            draft.full_clean()
        assert "Transactions data must be a list" in str(exc_info.value)

    def test_draft_validation_invalid_transaction_type(self, test_user, test_workspace):
        """Test validácie neplatného typu transakcie"""
        draft_data = [{"type": "invalid_type", "original_amount": 100}]
        draft = TransactionDraft(
            user=test_user,
            workspace=test_workspace,
            transactions_data=draft_data,
            draft_type="expense",
        )
        with pytest.raises(ValidationError) as exc_info:
            draft.full_clean()
        assert "Invalid transaction type" in str(exc_info.value)

    def test_draft_validation_transaction_data_item_not_dict(
        self, test_user, test_workspace
    ):
        """Test clean() raises ValidationError if an item in transactions_data is not a dictionary."""
        draft_data = [
            {"original_amount": 100, "type": "expense"},
            "not a dictionary",  # Invalid item
        ]
        draft = TransactionDraft(
            user=test_user,
            workspace=test_workspace,
            transactions_data=draft_data,
            draft_type="expense",
        )
        with pytest.raises(ValidationError) as exc_info:
            draft.full_clean()
        assert "Transaction at index 1 must be a dictionary" in str(exc_info.value)

    def test_draft_unique_constraint(self, test_user, test_workspace):
        """Test unikátnosti draftu pre user/workspace/type - NEMÔŽE existovať duplikát"""

        # Vytvor prvý draft
        draft1 = TransactionDraft.objects.create(
            user=test_user,
            workspace=test_workspace,
            transactions_data=[{"type": "expense", "original_amount": 50}],
            draft_type="expense",
        )

        # Pokus o vytvorenie druhého draftu - malo by ZLYHAŤ
        with transaction.atomic():
            try:
                draft2 = TransactionDraft.objects.create(
                    user=test_user,
                    workspace=test_workspace,
                    draft_type="expense",
                    transactions_data=[{"type": "expense", "original_amount": 100}],
                )
                # Ak prejde create, tak test zlyhá
                assert False, "Druhý draft bol vytvorený, čo porušuje unique constraint"
            except (IntegrityError, ValidationError):
                # Očakávaná chyba - test prejde
                pass

        # Over že existuje stále len jeden draft
        drafts_count = TransactionDraft.objects.filter(
            user=test_user, workspace=test_workspace, draft_type="expense"
        ).count()

        assert drafts_count == 1
        assert draft1.transactions_data[0]["original_amount"] == 50

    def test_draft_atomic_replacement(self, test_user, test_workspace):
        """Test že API endpoint správne nahrádza draft (atomic replace)"""
        # Vytvor prvý draft
        draft1 = TransactionDraft.objects.create(
            user=test_user,
            workspace=test_workspace,
            transactions_data=[{"type": "expense", "original_amount": 50}],
            draft_type="expense",
        )

        # Simuluj atomic replacement (ako to robí API)
        with transaction.atomic():
            TransactionDraft.objects.filter(
                user=test_user, workspace=test_workspace, draft_type="expense"
            ).delete()

            draft2 = TransactionDraft.objects.create(
                user=test_user,
                workspace=test_workspace,
                transactions_data=[{"type": "expense", "original_amount": 100}],
                draft_type="expense",
            )

        # Over že máme nový draft
        drafts_count = TransactionDraft.objects.filter(
            user=test_user, workspace=test_workspace, draft_type="expense"
        ).count()

        assert drafts_count == 1
        assert draft2.transactions_data[0]["original_amount"] == 100
        assert draft2.id != draft1.id  # Nový ID


# =============================================================================
# COMPLEX SCENARIO TESTS
# =============================================================================


class TestComplexScenarios:
    """Testy pre komplexné scenáre a vzťahy"""

    def test_complete_workspace_hierarchy(self, complete_workspace_setup):
        """Test kompletného workspace hierarchy"""
        setup = complete_workspace_setup

        # Overenie základných vzťahov
        assert setup["workspace"].owner == setup["user"]
        assert setup["expense_transaction"].workspace == setup["workspace"]

        # Check tags via count/exists
        assert setup["expense_transaction"].tags.count() == 2

    def test_multiple_transactions_same_workspace(self, complete_workspace_setup):
        setup = complete_workspace_setup

        new_transaction = Transaction.objects.create(
            user=setup["user"],
            workspace=setup["workspace"],
            type="expense",
            expense_category=setup["expense_category"],
            original_amount=75.25,
            original_currency="EUR",
            amount_domestic=75.25,
            date=timezone.now().date(),
            month=timezone.now().date().replace(day=1),
        )
        # Pridanie tagu (nie je povinné, ale pre úplnosť)
        tag, _ = Tags.objects.get_or_create(workspace=setup["workspace"], name="extra")
        new_transaction.tags.add(tag)

        transactions = Transaction.objects.filter(workspace=setup["workspace"])
        assert transactions.count() >= 2


class TestWorkspaceAdmin:
    def test_workspace_admin_creation(
        self, workspace_admin, test_user2, test_workspace
    ):
        assert workspace_admin.user == test_user2
        assert workspace_admin.workspace == test_workspace
        assert workspace_admin.is_active is True

    def test_workspace_admin_unique_constraint(self, workspace_admin):
        # Test že user nemôže byť duplicitne admin v tom istom workspace
        with pytest.raises(IntegrityError):
            WorkspaceAdmin.objects.create(
                user=workspace_admin.user,
                workspace=workspace_admin.workspace,
                assigned_by=workspace_admin.assigned_by,
                is_active=True,
            )

    def test_workspace_admin_deactivation(self, workspace_admin, superuser):
        workspace_admin.deactivate(superuser)
        assert workspace_admin.is_active is False
        assert workspace_admin.deactivated_at is not None

    def test_workspace_admin_clean_validation(
        self, test_user, test_user2, test_workspace
    ):
        """Test that only a superuser can assign an admin."""
        with pytest.raises(
            ValidationError, match="Only superusers can assign workspace admins."
        ):
            admin_assignment = WorkspaceAdmin(
                user=test_user2,
                workspace=test_workspace,
                assigned_by=test_user,  # Not a superuser
            )
            admin_assignment.clean()

    def test_workspace_admin_clean_duplicate_active_admin(
        self, superuser, test_user2, test_workspace
    ):
        """
        Test that creating an active WorkspaceAdmin for a user/workspace pair
        that already has an active one raises a ValidationError from clean().
        """
        # Create an initial active admin
        WorkspaceAdmin.objects.create(
            user=test_user2,
            workspace=test_workspace,
            assigned_by=superuser,
            is_active=True,
        )

        # Attempt to create another active admin for the same user/workspace
        duplicate_admin = WorkspaceAdmin(
            user=test_user2,
            workspace=test_workspace,
            assigned_by=superuser,
            is_active=True,
        )
        with pytest.raises(ValidationError) as exc_info:
            duplicate_admin.clean()
        assert "User is already an active admin for this workspace." in str(
            exc_info.value
        )

    def test_can_impersonate_users_property(self, workspace_admin, superuser):
        """Test the can_impersonate_users property."""
        # 1. Admin is active and can impersonate
        workspace_admin.can_impersonate = True
        workspace_admin.is_active = True
        workspace_admin.save()
        assert workspace_admin.can_impersonate_users is True

        # 2. Admin is active but cannot impersonate
        workspace_admin.can_impersonate = False
        workspace_admin.save()
        assert workspace_admin.can_impersonate_users is False

        # 3. Admin is not active
        workspace_admin.is_active = False
        workspace_admin.can_impersonate = True
        workspace_admin.save()
        assert workspace_admin.can_impersonate_users is False

    def test_deactivate_by_non_superuser(self, workspace_admin, test_user):
        """Test that deactivation fails if the deactivator is not a superuser."""
        with pytest.raises(
            ValidationError, match="Only superusers can deactivate workspace admins."
        ):
            workspace_admin.deactivate(test_user)
