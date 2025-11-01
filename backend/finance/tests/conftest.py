# tests/conftest.py
import pytest
from decimal import Decimal
from datetime import date
from django.contrib.auth import get_user_model
from django.utils import timezone
from finance.models import (
    UserSettings, Workspace, WorkspaceMembership, WorkspaceSettings,
    ExpenseCategoryVersion, ExpenseCategory, IncomeCategoryVersion, IncomeCategory,
    ExpenseCategoryProperty, IncomeCategoryProperty, ExchangeRate, Transaction,
    TransactionDraft
)

User = get_user_model()

# =============================================================================
# USER FIXTURES
# =============================================================================

@pytest.fixture
def test_user(db):
    """Základný testovací používateľ"""
    return User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )

@pytest.fixture
def test_user2(db):
    """Druhý testovací používateľ"""
    return User.objects.create_user(
        username='testuser2', 
        email='test2@example.com',
        password='testpass123'
    )

@pytest.fixture
def user_settings(db, test_user):
    """UserSettings pre testovacieho používateľa"""
    return UserSettings.objects.create(
        user=test_user,
        language='sk'
    )

# =============================================================================
# WORKSPACE FIXTURES  
# =============================================================================

@pytest.fixture
def test_workspace(db, test_user):
    """Základný workspace"""
    return Workspace.objects.create(
        name='Test Workspace',
        description='Test workspace description',
        owner=test_user
    )

@pytest.fixture
def workspace_settings(db, test_workspace):
    """Nastavenia pre workspace"""
    return WorkspaceSettings.objects.create(
        workspace=test_workspace,
        domestic_currency='EUR',
        fiscal_year_start=1,
        display_mode='month',
        accounting_mode=False
    )

@pytest.fixture
def workspace_member(db, test_workspace, test_user2):
    """Člen workspace s rolou editor"""
    return WorkspaceMembership.objects.create(
        workspace=test_workspace,
        user=test_user2,
        role='editor'
    )

# =============================================================================
# CATEGORY VERSION FIXTURES
# =============================================================================

@pytest.fixture
def expense_category_version(db, test_workspace, test_user):
    """Verzia expense kategórií"""
    return ExpenseCategoryVersion.objects.create(
        workspace=test_workspace,
        name='Expense Categories v1',
        description='Initial expense categories',
        created_by=test_user,
        is_active=True
    )

@pytest.fixture
def income_category_version(db, test_workspace, test_user):
    """Verzia income kategórií"""
    return IncomeCategoryVersion.objects.create(
        workspace=test_workspace,
        name='Income Categories v1', 
        description='Initial income categories',
        created_by=test_user,
        is_active=True
    )

# =============================================================================
# EXPENSE CATEGORY FIXTURES
# =============================================================================

@pytest.fixture
def expense_root_category(db, expense_category_version):
    """Root expense kategória"""
    category = ExpenseCategory.objects.create(
        version=expense_category_version,
        name='Potraviny',
        level=1,
        is_active=True
    )
    return category

@pytest.fixture
def expense_child_category(db, expense_category_version, expense_root_category):
    """Child expense kategória"""
    child = ExpenseCategory.objects.create(
        version=expense_category_version,
        name='Ovocie a Zelenina',
        level=2,
        is_active=True
    )
    expense_root_category.children.add(child)
    return child

@pytest.fixture
def expense_category_property(db, expense_root_category):
    """Vlastnosť expense kategórie"""
    return ExpenseCategoryProperty.objects.create(
        category=expense_root_category,
        property_type='cost'
    )

# =============================================================================
# INCOME CATEGORY FIXTURES  
# =============================================================================

@pytest.fixture
def income_root_category(db, income_category_version):
    """Root income kategória"""
    category = IncomeCategory.objects.create(
        version=income_category_version,
        name='Príjmy',
        level=1, 
        is_active=True
    )
    return category

@pytest.fixture
def income_child_category(db, income_category_version, income_root_category):
    """Child income kategória"""
    child = IncomeCategory.objects.create(
        version=income_category_version,
        name='Mzda',
        level=2,
        is_active=True
    )
    income_root_category.children.add(child)
    return child

@pytest.fixture
def income_category_property(db, income_root_category):
    """Vlastnosť income kategórie"""
    return IncomeCategoryProperty.objects.create(
        category=income_root_category,
        property_type='income'
    )

# =============================================================================
# EXCHANGE RATE FIXTURES
# =============================================================================

@pytest.fixture
def exchange_rate_eur(db):
    """EUR exchange rate (bázová mena)"""
    return ExchangeRate.objects.create(
        currency='EUR',
        rate_to_eur=1.0,
        date=timezone.now().date()
    )

@pytest.fixture
def exchange_rate_usd(db):
    """USD exchange rate"""
    return ExchangeRate.objects.create(
        currency='USD',
        rate_to_eur=0.85,
        date=timezone.now().date()
    )

# =============================================================================
# TRANSACTION FIXTURES
# =============================================================================

@pytest.fixture
def expense_transaction(db, test_user, test_workspace, expense_root_category, workspace_settings):
    return Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type='expense',
        expense_category=expense_root_category,
        original_amount=100.50,
        original_currency='EUR',
        amount_domestic=100.50,
        date=timezone.now().date(),
        month=timezone.now().date().replace(day=1),
        tags=['potraviny', 'nakup'],
        note_manual='Nákup potravín'  
    )

@pytest.fixture  
def income_transaction(db, test_user, test_workspace, income_root_category, workspace_settings):
    return Transaction.objects.create(
        user=test_user,
        workspace=test_workspace,
        type='income',
        income_category=income_root_category,
        original_amount=2000.00,
        original_currency='EUR',
        amount_domestic=2000.00,
        date=timezone.now().date(),
        month=timezone.now().date().replace(day=1)
    )

# =============================================================================
# TRANSACTION DRAFT FIXTURES
# =============================================================================

@pytest.fixture
def transaction_draft(db, test_user, test_workspace):
    """Draft transakcií"""
    draft_data = [
        {
            'type': 'expense',
            'original_amount': 50.00,
            'original_currency': 'EUR',
            'date': '2024-01-15',
            'note_manual': 'Test draft transaction'
        }
    ]
    return TransactionDraft.objects.create(
        user=test_user,
        workspace=test_workspace,
        transactions_data=draft_data,
        draft_type='expense'
    )

# =============================================================================
# COMPLEX SCENARIO FIXTURES
# =============================================================================

@pytest.fixture
def complete_workspace_setup(
    db, test_user, test_workspace, workspace_settings,
    expense_category_version, income_category_version,
    expense_root_category, income_root_category,
    expense_transaction, income_transaction
):
    """Kompletná fixture so všetkými závislosťami"""
    return {
        'user': test_user,
        'workspace': test_workspace,
        'workspace_settings': workspace_settings,
        'expense_version': expense_category_version,
        'income_version': income_category_version,
        'expense_category': expense_root_category,
        'income_category': income_root_category,
        'expense_transaction': expense_transaction,
        'income_transaction': income_transaction
    }

# finance/tests/conftest.py

@pytest.fixture
def expense_child_category(db, expense_category_version, expense_root_category):
    """Child expense kategória"""
    child = ExpenseCategory.objects.create(
        version=expense_category_version,
        name='Ovocie a Zelenina',
        level=2,
        is_active=True
    )
    expense_root_category.children.add(child)
    return child

@pytest.fixture
def income_child_category(db, income_category_version, income_root_category):
    """Child income kategória"""
    child = IncomeCategory.objects.create(
        version=income_category_version,
        name='Mzda',
        level=2,
        is_active=True
    )
    income_root_category.children.add(child)
    return child

# finance/tests/conftest.py
@pytest.fixture
def exchange_rate_usd(db):
    """USD exchange rate"""
    return ExchangeRate.objects.create(
        currency='USD',
        rate_to_eur=Decimal('0.85'),
        date=timezone.now().date()
    )

@pytest.fixture
def exchange_rate_gbp(db):
    """GBP exchange rate"""
    return ExchangeRate.objects.create(
        currency='GBP',
        rate_to_eur=Decimal('0.75'),
        date=timezone.now().date()
    )

@pytest.fixture
def workspace_settings_other_currency(db, test_workspace):
    """Workspace settings s inou menou"""
    return WorkspaceSettings.objects.create(
        workspace=test_workspace,
        domestic_currency='USD',  # Iná mena ako EUR
        fiscal_year_start=1,
        display_mode='month',
        accounting_mode=False
    )

@pytest.fixture
def exchange_rate_gbp(db):
    """GBP exchange rate"""
    return ExchangeRate.objects.create(
        currency='GBP',
        rate_to_eur=Decimal('0.75'),
        date=timezone.now().date()
    )

@pytest.fixture
def income_root_category(db, income_category_version):
    """Root income kategória"""
    return IncomeCategory.objects.create(
        version=income_category_version,
        name='Príjmy',
        level=1,
        is_active=True
    )

@pytest.fixture
def exchange_rate_usd():
    """Exchange rate pre USD"""
    from finance.models import ExchangeRate
    return ExchangeRate.objects.create(
        currency='USD',
        rate_to_eur=Decimal('0.85'),
        date=date(2025, 11, 1)
    )

@pytest.fixture
def exchange_rate_gbp():
    """Exchange rate pre GBP"""
    from finance.models import ExchangeRate
    return ExchangeRate.objects.create(
        currency='GBP',
        rate_to_eur=Decimal('0.75'),
        date=date(2025, 11, 1)
    )

@pytest.fixture
def exchange_rate_usd_2024():
    """Exchange rate pre USD pre dátum 2024-01-15"""
    from finance.models import ExchangeRate
    return ExchangeRate.objects.create(
        currency='USD',
        rate_to_eur=Decimal('0.85'),
        date=date(2024, 1, 15)
    )

@pytest.fixture
def exchange_rate_gbp_2024():
    """Exchange rate pre GBP pre dátum 2024-01-15"""
    from finance.models import ExchangeRate
    return ExchangeRate.objects.create(
        currency='GBP',
        rate_to_eur=Decimal('0.75'),
        date=date(2024, 1, 15)
    )

@pytest.fixture
def exchange_rate_usd_2024_20():
    """Exchange rate pre USD pre dátum 2024-01-20"""
    from finance.models import ExchangeRate
    return ExchangeRate.objects.create(
        currency='USD',
        rate_to_eur=Decimal('0.85'),
        date=date(2024, 1, 20)
    )

@pytest.fixture
def exchange_rate_usd_jan15():
    return ExchangeRate.objects.create(
        currency='USD', rate_to_eur=Decimal('0.85'), date=date(2024, 1, 15)
    )

@pytest.fixture  
def exchange_rate_usd_jan20():
    return ExchangeRate.objects.create(
        currency='USD', rate_to_eur=Decimal('0.90'), date=date(2024, 1, 20)  # Iný rate!
    )

@pytest.fixture
def exchange_rate_usd_2024_jan20():
    """Exchange rate pre USD pre dátum 2024-01-20"""
    from finance.models import ExchangeRate
    return ExchangeRate.objects.create(
        currency='USD',
        rate_to_eur=Decimal('0.86'),  # Iný rate ako pre 2024-01-15
        date=date(2024, 1, 20)
    )