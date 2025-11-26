# tests/unit/test_models.py
from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError
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
        parent = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent", level=1
        )
        leaf = ExpenseCategory.objects.create(
            version=expense_category_version, name="Leaf", level=5
        )
        leaf.parents.add(parent)
        parent.children.add(leaf)  # Make parent valid

        # The leaf now has a parent. Now let's give it a child, which should be invalid.
        child = ExpenseCategory.objects.create(
            version=expense_category_version, name="ImpossibleChild", level=4
        )
        leaf.children.add(child)

        with pytest.raises(ValidationError) as exc_info:
            leaf.full_clean()

        # Check for either of the expected errors, as order isn't guaranteed
        messages = exc_info.value.messages
        assert (
            "Leaf category 'Leaf' (level 5) should not have children" in messages
            or "Child category must have higher level than parent" in messages
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
            "Non-leaf category 'Non-leaf' (level 4) must have at least one child"
            in exc_info.value.message_dict["__all__"]
        )


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
            version=income_category_version, name="Parent", level=1
        )
        non_leaf = IncomeCategory.objects.create(
            version=income_category_version, name="Non-leaf", level=4
        )
        non_leaf.parents.add(parent)  # Satisfy parent requirement
        parent.children.add(non_leaf)  # Satisfy parent's child requirement

        with pytest.raises(ValidationError) as exc_info:
            non_leaf.full_clean()

        assert (
            "Non-leaf category 'Non-leaf' (level 4) must have at least one child"
            in exc_info.value.message_dict["__all__"]
        )


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
