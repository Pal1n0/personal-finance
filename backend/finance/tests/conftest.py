# tests/conftest.py
from datetime import date
from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
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

User = get_user_model()

# =============================================================================
# USER FIXTURES
# =============================================================================


@pytest.fixture
def test_user(db):
    """Základný testovací používateľ"""
    return User.objects.create_user(
        username="testuser", email="test@example.com", password="testpass123"
    )


@pytest.fixture
def test_user2(db):
    """Druhý testovací používateľ"""
    return User.objects.create_user(
        username="testuser2", email="test2@example.com", password="testpass123"
    )


@pytest.fixture
def superuser(db):
    """Superuser pre admin operácie"""
    return User.objects.create_superuser(
        username="superuser", email="admin@example.com", password="adminpass123"
    )


@pytest.fixture
def user_settings(db, test_user):
    """UserSettings pre testovacieho používateľa"""
    # UserSettings sú vytvorené automaticky signálom.
    # Ak je potrebné zmeniť predvolený jazyk, urob to tu.
    settings = test_user.settings
    settings.language = "sk"
    settings.save()
    return settings


# =============================================================================
# WORKSPACE FIXTURES
# =============================================================================


@pytest.fixture
def test_workspace(db, test_user):
    """Základný workspace"""
    return Workspace.objects.create(
        name="Test Workspace", description="Test workspace description", owner=test_user
    )


@pytest.fixture
def workspace_settings(db, test_workspace):
    """Nastavenia pre workspace (Domestic Currency: EUR)"""
    # WorkspaceSettings sú vytvorené automaticky signálom.
    # Ak je potrebné zmeniť predvolené hodnoty, urob to tu.
    settings = test_workspace.settings
    settings.domestic_currency = "EUR"
    settings.fiscal_year_start = 1
    settings.display_mode = "month"
    settings.accounting_mode = False
    settings.save()
    return settings


@pytest.fixture
def workspace_member(db, test_workspace, test_user2):
    """Člen workspace s rolou editor"""
    return WorkspaceMembership.objects.create(
        workspace=test_workspace, user=test_user2, role="editor"
    )


@pytest.fixture
def workspace_admin(db, test_workspace, test_user2, superuser):
    """Workspace admin assignment"""
    return WorkspaceAdmin.objects.create(
        user=test_user2,
        workspace=test_workspace,
        assigned_by=superuser,
        is_active=True,
        can_manage_users=True,
    )


# =============================================================================
# TAGS FIXTURES
# =============================================================================


@pytest.fixture
def tag_potraviny(db, test_workspace):
    return Tags.objects.create(workspace=test_workspace, name="potraviny")


@pytest.fixture
def tag_nakup(db, test_workspace):
    return Tags.objects.create(workspace=test_workspace, name="nakup")


# =============================================================================
# CATEGORY VERSION FIXTURES
# =============================================================================


@pytest.fixture
def expense_category_version(db, test_workspace, test_user):
    """Verzia expense kategórií (levels_count=5)"""
    return ExpenseCategoryVersion.objects.create(
        workspace=test_workspace,
        name="Expense Categories v1",
        description="Initial expense categories",
        created_by=test_user,
        is_active=True,
        levels_count=5,
    )


@pytest.fixture
def income_category_version(db, test_workspace, test_user):
    """Verzia income kategórií (levels_count=5)"""
    return IncomeCategoryVersion.objects.create(
        workspace=test_workspace,
        name="Income Categories v1",
        description="Initial income categories",
        created_by=test_user,
        is_active=True,
        levels_count=5,
    )


# =============================================================================
# EXPENSE CATEGORY FIXTURES
# =============================================================================


@pytest.fixture
def expense_root_category(db, expense_category_version):
    """Root expense kategória (Level 1)"""
    return ExpenseCategory.objects.create(
        version=expense_category_version, name="Potraviny", level=1, is_active=True
    )


@pytest.fixture
def expense_child_category(db, expense_category_version, expense_root_category):
    """Child expense kategória (Level 2)"""
    child = ExpenseCategory.objects.create(
        version=expense_category_version,
        name="Ovocie a Zelenina",
        level=2,
        is_active=True,
    )
    expense_root_category.children.add(child)
    return child


@pytest.fixture
def expense_leaf_category(db, expense_category_version):
    """Leaf expense kategória (Level 5)"""
    return ExpenseCategory.objects.create(
        name="Leaf Category", level=5, version=expense_category_version, is_active=True
    )


@pytest.fixture
def expense_category_property(db, expense_root_category):
    """Vlastnosť expense kategórie"""
    return ExpenseCategoryProperty.objects.create(
        category=expense_root_category, property_type="cost"
    )


# =============================================================================
# INCOME CATEGORY FIXTURES
# =============================================================================


@pytest.fixture
def income_root_category(db, income_category_version):
    """Root income kategória (Level 1)"""
    return IncomeCategory.objects.create(
        version=income_category_version, name="Príjmy", level=1, is_active=True
    )


@pytest.fixture
def income_child_category(db, income_category_version, income_root_category):
    """Child income kategória (Level 2)"""
    child = IncomeCategory.objects.create(
        version=income_category_version, name="Mzda", level=2, is_active=True
    )
    income_root_category.children.add(child)
    return child


@pytest.fixture
def income_category_property(db, income_root_category):
    """Vlastnosť income kategórie"""
    return IncomeCategoryProperty.objects.create(
        category=income_root_category, property_type="income"
    )


# =============================================================================
# EXCHANGE RATE FIXTURES
# =============================================================================


@pytest.fixture
def exchange_rate_eur(db):
    """EUR exchange rate (bázová mena)"""
    return ExchangeRate.objects.create(
        currency="EUR", rate_to_eur=1.0, date=timezone.now().date()
    )


@pytest.fixture
def exchange_rate_usd(db):
    """
    USD kurz pre dátum 2025-11-08.
    Dôležité: Dátum sa musí zhodovať s transakciou 'transaction_usd_currency'.
    """
    return ExchangeRate.objects.create(
        currency="USD",
        rate_to_eur=Decimal("0.85"),
        date=date(2025, 11, 8),
    )


# =============================================================================
# TRANSACTION FIXTURES
# =============================================================================


@pytest.fixture
def expense_transaction(
    db,
    test_user,
    test_workspace,
    expense_root_category,
    workspace_settings,
    tag_potraviny,
    tag_nakup,
):
    """
    Vytvorí transakciu a priradí jej tagy cez M2M vzťah.
    Vyžaduje workspace_settings pre korektný prepočet.
    """
    transaction = Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type="expense",
        expense_category=expense_root_category,
        original_amount=100.50,
        original_currency="EUR",
        amount_domestic=100.50,
        date=date(2025, 11, 8),
        month=date(2025, 11, 1),
        note_manual="Nákup potravín",
    )
    # M2M priradenie musí byť oddelene
    transaction.tags.add(tag_potraviny, tag_nakup)
    return transaction


@pytest.fixture
def expense_transaction_without_tags(
    db,
    test_user,
    test_workspace,
    expense_root_category,
    workspace_settings,
):
    """
    Vytvorí transakciu bez tagov.
    """
    transaction = Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type="expense",
        expense_category=expense_root_category,
        original_amount=100.50,
        original_currency="EUR",
        amount_domestic=100.50,
        date=date(2025, 11, 8),
        month=date(2025, 11, 1),
        note_manual="Nákup potravín",
    )
    return transaction


@pytest.fixture
def income_transaction(
    db, test_user, test_workspace, income_root_category, workspace_settings
):
    """Income transakcia"""
    return Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type="income",
        income_category=income_root_category,
        original_amount=2000.00,
        original_currency="EUR",
        amount_domestic=2000.00,
        date=timezone.now().date(),
        month=timezone.now().date().replace(day=1),
    )


@pytest.fixture
def transaction_with_expense(
    db, expense_leaf_category, test_user, test_workspace, workspace_settings
):
    """Fixture pre transakciu s expense kategóriou (Leaf)"""
    transaction = Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type="expense",
        expense_category=expense_leaf_category,
        original_amount=100.00,
        original_currency="EUR",
        amount_domestic=100.00,
        date=date(2025, 11, 8),
        month=date(2025, 11, 1),
        note_manual="Test transaction with leaf category",
    )
    return transaction


@pytest.fixture
def transaction_usd_currency(
    db,
    test_user,
    test_workspace,
    expense_root_category,
    workspace_settings,
    exchange_rate_usd,
):
    """
    Transakcia v USD mene.
    CRITICAL: Vyžaduje 'workspace_settings' a 'exchange_rate_usd' argumenty, aby nastavenia a kurz existovali
    pred spustením Transaction.save(), ktorý volá konverziu meny.
    """
    return Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type="expense",
        expense_category=expense_root_category,
        original_amount=100.00,
        original_currency="USD",
        amount_domestic=85.00,  # 100 * 0.85 (kurz z 2025-11-08)
        date=date(2025, 11, 8),
        month=date(2025, 11, 1),
    )


# =============================================================================
# TRANSACTION DRAFT FIXTURES
# =============================================================================


@pytest.fixture
def transaction_draft(db, test_user, test_workspace):
    """Draft transakcií"""
    draft_data = [
        {
            "type": "expense",
            "original_amount": 50.00,
            "original_currency": "EUR",
            "date": "2024-01-15",
            "note_manual": "Test draft transaction",
        }
    ]
    return TransactionDraft.objects.create(
        user=test_user,
        workspace=test_workspace,
        transactions_data=draft_data,
        draft_type="expense",
    )


# =============================================================================
# COMPLEX SCENARIO FIXTURES
# =============================================================================


@pytest.fixture
def complete_workspace_setup(
    db,
    test_user,
    test_workspace,
    workspace_settings,
    expense_category_version,
    income_category_version,
    expense_root_category,
    income_root_category,
    expense_transaction,
    income_transaction,
):
    """Kompletná fixture so všetkými závislosťami"""
    return {
        "user": test_user,
        "workspace": test_workspace,
        "workspace_settings": workspace_settings,
        "expense_version": expense_category_version,
        "income_version": income_category_version,
        "expense_category": expense_root_category,
        "income_category": income_root_category,
        "expense_transaction": expense_transaction,
        "income_transaction": income_transaction,
    }


@pytest.fixture
def transaction_with_different_date(
    db, test_user, test_workspace, expense_root_category
):
    """Transakcia s iným dátumom pre testovanie recalculácie"""
    return Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type="expense",
        expense_category=expense_root_category,
        original_amount=100.00,
        original_currency="USD",
        amount_domestic=85.00,
        date=date(2024, 1, 15),  # Iný dátum
        month=date(2024, 1, 1),
    )


# =============================================================================
# CATEGORY HIERARCHY FIXTURES - NOVÉ
# =============================================================================


@pytest.fixture
def expense_category_hierarchy(db, expense_category_version):
    """Komplexná hierarchia expense kategórií"""
    level1 = ExpenseCategory.objects.create(
        version=expense_category_version, name="Level 1 Root", level=1
    )

    level2 = ExpenseCategory.objects.create(
        version=expense_category_version, name="Level 2 Child", level=2
    )

    level3 = ExpenseCategory.objects.create(
        version=expense_category_version, name="Level 3 Leaf", level=3
    )

    # Vytvor hierarchiu
    level1.children.add(level2)
    level2.children.add(level3)

    return {"level1": level1, "level2": level2, "level3": level3}


@pytest.fixture
def income_category_hierarchy(db, income_category_version):
    """Komplexná hierarchia income kategórií"""
    level1 = IncomeCategory.objects.create(
        version=income_category_version, name="Level 1 Root", level=1
    )

    level2 = IncomeCategory.objects.create(
        version=income_category_version, name="Level 2 Child", level=2
    )

    level3 = IncomeCategory.objects.create(
        version=income_category_version, name="Level 3 Leaf", level=3
    )

    # Vytvor hierarchiu
    level1.children.add(level2)
    level2.children.add(level3)

    return {"level1": level1, "level2": level2, "level3": level3}


# =============================================================================
# TRANSACTION DRAFT SCENARIO FIXTURES - NOVÉ
# =============================================================================


@pytest.fixture
def transaction_draft_multiple_items(db, test_user, test_workspace):
    """Draft s viacerými transakciami"""
    draft_data = [
        {
            "type": "expense",
            "original_amount": 50.00,
            "original_currency": "EUR",
            "date": "2024-01-15",
            "note_manual": "First transaction",
        },
        {
            "type": "expense",
            "original_amount": 25.50,
            "original_currency": "USD",
            "date": "2024-01-16",
            "note_manual": "Second transaction",
        },
    ]
    return TransactionDraft.objects.create(
        user=test_user,
        workspace=test_workspace,
        transactions_data=draft_data,
        draft_type="expense",
    )


@pytest.fixture
def transaction_draft_income(db, test_user, test_workspace):
    """Draft pre income transakcie"""
    draft_data = [
        {
            "type": "income",
            "original_amount": 1000.00,
            "original_currency": "EUR",
            "date": "2024-01-15",
            "note_manual": "Salary",
        }
    ]
    return TransactionDraft.objects.create(
        user=test_user,
        workspace=test_workspace,
        transactions_data=draft_data,
        draft_type="income",
    )


# =============================================================================
# EDGE CASE FIXTURES - NOVÉ
# =============================================================================


@pytest.fixture
def workspace_minimal_name(db, test_user):
    """Workspace s minimálnym povoleným názvom"""
    return Workspace.objects.create(name="AB", owner=test_user)  # Presne 2 znaky


@pytest.fixture
def category_minimal_name(db, expense_category_version):
    """Kategória s minimálnym povoleným názvom"""
    return ExpenseCategory.objects.create(
        version=expense_category_version, name="AB", level=1  # Presne 2 znaky
    )


@pytest.fixture
def exchange_rate_high_precision(db):
    """Exchange rate s vysokou presnosťou"""
    return ExchangeRate.objects.create(
        currency="JPY", rate_to_eur=Decimal("0.006123"), date=timezone.now().date()
    )


# =============================================================================
# BULK DATA FIXTURES - NOVÉ
# =============================================================================


@pytest.fixture
def multiple_transactions_batch(db, test_user, test_workspace, expense_root_category):
    """Viacero transakcií pre batch testovanie"""
    transactions = []
    for i in range(5):
        transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=Decimal(10.00 + i * 5),
            original_currency="EUR",
            amount_domestic=Decimal(10.00 + i * 5),
            date=date(2025, 11, i + 1),
            month=date(2025, 11, 1),
        )
        transactions.append(transaction)
    return transactions


@pytest.fixture
def multiple_exchange_rates(db):
    """Viacero exchange rates pre rôzne meny a dátumy"""
    rates = []
    currencies = ["USD", "GBP", "CHF", "PLN"]

    for i, currency in enumerate(currencies):
        rate = ExchangeRate.objects.create(
            currency=currency,
            rate_to_eur=Decimal(0.8 + i * 0.1),  # Rôzne rates
            date=date(2025, 11, 1),
        )
        rates.append(rate)

    return rates
