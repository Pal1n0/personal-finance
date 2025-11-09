# tests/unit/test_models.py
import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from decimal import Decimal
from finance.models import (
    UserSettings, Workspace, WorkspaceMembership, WorkspaceSettings,
    ExpenseCategoryVersion, ExpenseCategory, IncomeCategoryVersion, IncomeCategory,
    ExpenseCategoryProperty, IncomeCategoryProperty, ExchangeRate, Transaction,
    TransactionDraft
)

# =============================================================================
# USER SETTINGS TESTS
# =============================================================================

class TestUserSettings:
    """Testy pre UserSettings model"""
    
    def test_user_settings_creation(self, user_settings, test_user):
        """Test vytvorenia UserSettings"""
        assert user_settings.user == test_user
        assert user_settings.language == 'sk'
        assert str(user_settings) == f"{test_user.username} settings"
    
    def test_user_settings_default_language(self, test_user):
        """Test predvoleného jazyka"""
        settings = UserSettings.objects.create(user=test_user)
        assert settings.language == 'en'
    
    def test_user_settings_language_choices(self, user_settings):
        """Test platných jazykových voľieb"""
        valid_languages = ['en', 'cs', 'sk']
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
        assert test_workspace.name == 'Test Workspace'
        assert test_workspace.owner == test_user
        assert test_workspace.is_active is True
        assert str(test_workspace) == f"Test Workspace (Owner: {test_user.username})"
    
    def test_workspace_validation_name_too_short(self, test_user):
        """Test validácie príliš krátkeho názvu"""
        workspace = Workspace(
            name='A',
            owner=test_user
        )
        with pytest.raises(ValidationError) as exc_info:
            workspace.full_clean()
        assert 'Workspace name must be at least 2 characters long' in str(exc_info.value)
    
    def test_workspace_validation_empty_name(self, test_user):
        """Test validácie prázdneho názvu"""
        workspace = Workspace(
            name='   ',
            owner=test_user
        )
        with pytest.raises(ValidationError) as exc_info:
            workspace.full_clean()
        assert 'Workspace name must be at least 2 characters long' in str(exc_info.value)
    
    def test_workspace_string_representation(self, test_workspace, test_user):
        """Test string reprezentácie workspace"""
        expected = f"Test Workspace (Owner: {test_user.username})"
        assert str(test_workspace) == expected

# =============================================================================
# WORKSPACE MEMBERSHIP TESTS
# =============================================================================

class TestWorkspaceMembership:
    """Testy pre WorkspaceMembership model"""
    
    def test_membership_creation(self, workspace_member, test_workspace, test_user2):
        """Test vytvorenia členstva"""
        assert workspace_member.workspace == test_workspace
        assert workspace_member.user == test_user2
        assert workspace_member.role == 'editor'
        assert str(workspace_member) == f"{test_user2.username} in {test_workspace.name} as editor"
    
    def test_membership_default_role(self, test_workspace, test_user):
        """Test predvolenej role"""
        membership = WorkspaceMembership.objects.create(
            workspace=test_workspace,
            user=test_user
        )
        assert membership.role == 'viewer'
    
    def test_membership_unique_constraint(self, test_workspace, test_user):
        """Test unikátnosti členstva"""
        # Prvé členstvo
        WorkspaceMembership.objects.create(
            workspace=test_workspace,
            user=test_user,
            role='admin'
        )
        
        # Pokus o duplicitné členstvo
        with pytest.raises(ValidationError) as exc_info:
            membership = WorkspaceMembership(
                workspace=test_workspace,
                user=test_user,
                role='editor'
            )
            membership.full_clean()
        
        assert 'User is already a member of this workspace' in str(exc_info.value)
    
    def test_membership_role_choices(self, workspace_member):
        """Test platných rolí"""
        valid_roles = ['admin', 'editor', 'viewer']
        assert workspace_member.role in valid_roles

    def test_membership_cannot_add_owner(self):
        with self.assertRaises(ValidationError) as context:
            membership = WorkspaceMembership(
                workspace=self.workspace,
                user=self.owner,  # 🚨 Trying to add owner as regular member
                role='editor'
            )
            membership.full_clean()
        self.assertIn('Workspace owner should not be added as a regular membership', str(context.exception))

    def test_membership_role_choices_only_editor_viewer(self):
        valid_roles = ['editor', 'viewer']  # 🚨 Only these two now
        self.assertIn(self.membership.role, valid_roles)

# =============================================================================
# WORKSPACE SETTINGS TESTS
# =============================================================================

class TestWorkspaceSettings:
    """Testy pre WorkspaceSettings model"""
    
    def test_workspace_settings_creation(self, workspace_settings, test_workspace):
        """Test vytvorenia nastavení workspace"""
        assert workspace_settings.workspace == test_workspace
        assert workspace_settings.domestic_currency == 'EUR'
        assert workspace_settings.fiscal_year_start == 1
        assert workspace_settings.display_mode == 'month'
        assert workspace_settings.accounting_mode is False
        assert str(workspace_settings) == f"{test_workspace.name} settings"
    
    def test_workspace_settings_default_values(self, test_workspace):
        """Test predvolených hodnôt"""
        settings = WorkspaceSettings.objects.create(workspace=test_workspace)
        assert settings.domestic_currency == 'EUR'
        assert settings.fiscal_year_start == 1
        assert settings.display_mode == 'month'
        assert settings.accounting_mode is False
    
    def test_workspace_settings_currency_choices(self, workspace_settings):
        """Test platných mien"""
        valid_currencies = ['EUR', 'USD', 'GBP', 'CHF', 'PLN']
        assert workspace_settings.domestic_currency in valid_currencies
    
    def test_workspace_settings_display_mode_choices(self, workspace_settings):
        """Test platných módov zobrazenia"""
        valid_modes = ['month', 'day']
        assert workspace_settings.display_mode in valid_modes

# =============================================================================
# EXPENSE CATEGORY VERSION TESTS
# =============================================================================

class TestExpenseCategoryVersion:
    """Testy pre ExpenseCategoryVersion model"""
    
    def test_expense_version_creation(self, expense_category_version, test_workspace, test_user):
        """Test vytvorenia verzie expense kategórií"""
        assert expense_category_version.workspace == test_workspace
        assert expense_category_version.name == 'Expense Categories v1'
        assert expense_category_version.created_by == test_user
        assert expense_category_version.is_active is True
        assert str(expense_category_version) == f"{test_workspace.name} - Expense"
    
    def test_expense_version_validation_name_too_short(self, test_workspace, test_user):
        """Test validácie príliš krátkeho názvu verzie"""
        version = ExpenseCategoryVersion(
            workspace=test_workspace,
            name='A',
            created_by=test_user
        )
        with pytest.raises(ValidationError) as exc_info:
            version.full_clean()
        assert 'Version name must be at least 2 characters long' in str(exc_info.value)

# =============================================================================
# EXPENSE CATEGORY TESTS
# =============================================================================

class TestExpenseCategory:
    """Testy pre ExpenseCategory model"""
    
    def test_expense_category_creation(self, expense_root_category, expense_category_version):
        """Test vytvorenia expense kategórie"""
        assert expense_root_category.version == expense_category_version
        assert expense_root_category.name == 'Potraviny'
        assert expense_root_category.level == 1
        assert expense_root_category.is_active is True
        assert str(expense_root_category) == 'Potraviny (Level 1)'
    
    def test_expense_category_is_root_property(self, expense_root_category, expense_child_category):
        """Test root property"""
        assert expense_root_category.is_root is True
        assert expense_child_category.is_root is False
    
    def test_expense_category_is_leaf_property(self, expense_root_category, expense_child_category):
        """Test leaf property"""
        assert expense_root_category.is_leaf is False  # Má child
        # Vytvoríme leaf kategóriu
        leaf_category = ExpenseCategory.objects.create(
            version=expense_root_category.version,
            name='Leaf Category',
            level=3
        )
        assert leaf_category.is_leaf is True
    
    def test_expense_category_add_child_success(self, expense_category_version):
        """Test úspešného pridania child kategórie"""
        parent = ExpenseCategory.objects.create(
            version=expense_category_version,
            name='Parent',
            level=1
        )
        child = ExpenseCategory.objects.create(
            version=expense_category_version,
            name='Child',
            level=2
        )
        
        parent.add_child(child)
        assert child in parent.children.all()
    
    def test_expense_category_add_child_with_existing_parent(self, expense_category_version):
        """Test pokusu o pridanie child kategórie ktorá už má parenta"""
        parent1 = ExpenseCategory.objects.create(
            version=expense_category_version,
            name='Parent1',
            level=1
        )
        parent2 = ExpenseCategory.objects.create(
            version=expense_category_version,
            name='Parent2', 
            level=1
        )
        child = ExpenseCategory.objects.create(
            version=expense_category_version,
            name='Child',
            level=2
        )
        
        parent1.add_child(child)
        
        with pytest.raises(ValidationError) as exc_info:
            parent2.add_child(child)
        
        assert 'already has a parent' in str(exc_info.value)
    
    def test_expense_category_validation_invalid_level(self, expense_category_version):
        """Test validácie neplatnej úrovne"""
        category = ExpenseCategory(
            version=expense_category_version,
            name='Test',
            level=6  # Neplatná úroveň
        )
        with pytest.raises(ValidationError) as exc_info:
            category.full_clean()
        assert 'Category level must be between 1 and 5' in str(exc_info.value)
    
    def test_expense_category_validation_name_too_short(self, expense_category_version):
        """Test validácie príliš krátkeho názvu"""
        category = ExpenseCategory(
            version=expense_category_version,
            name='A',
            level=1
        )
        with pytest.raises(ValidationError) as exc_info:
            category.full_clean()
        assert 'Category name must be at least 2 characters long' in str(exc_info.value)

# =============================================================================
# INCOME CATEGORY TESTS (podobné ako expense)
# =============================================================================

class TestIncomeCategory:
    """Testy pre IncomeCategory model"""
    
    def test_income_category_creation(self, income_root_category, income_category_version):
        """Test vytvorenia income kategórie"""
        assert income_root_category.version == income_category_version
        assert income_root_category.name == 'Príjmy'
        assert income_root_category.level == 1
        assert str(income_root_category) == 'Príjmy (Level 1)'
    
    def test_income_category_hierarchy(self, income_root_category, income_child_category):
        """Test hierarchie income kategórií"""
        assert income_child_category in income_root_category.children.all()
        assert income_root_category in income_child_category.parents.all()

# =============================================================================
# CATEGORY PROPERTY TESTS
# =============================================================================

class TestExpenseCategoryProperty:
    """Testy pre ExpenseCategoryProperty"""
    
    def test_expense_property_creation(self, expense_category_property, expense_root_category):
        """Test vytvorenia expense property"""
        assert expense_category_property.category == expense_root_category
        assert expense_category_property.property_type == 'cost'
        assert str(expense_category_property) == f"{expense_root_category.name} - cost"
    
    def test_expense_property_choices(self, expense_category_property):
        """Test platných property typov"""
        valid_types = ['cost', 'expense']
        assert expense_category_property.property_type in valid_types

class TestIncomeCategoryProperty:
    """Testy pre IncomeCategoryProperty"""
    
    def test_income_property_creation(self, income_category_property, income_root_category):
        """Test vytvorenia income property"""
        assert income_category_property.category == income_root_category
        assert income_category_property.property_type == 'income'
        assert str(income_category_property) == f"{income_root_category.name} - income"

# =============================================================================
# EXCHANGE RATE TESTS
# =============================================================================

class TestExchangeRate:
    """Testy pre ExchangeRate model"""
    @pytest.mark.django_db
    def test_exchange_rate_creation(self, exchange_rate_usd):
        """Test vytvorenia výmenného kurzu"""
        assert exchange_rate_usd.currency == 'USD'
        assert exchange_rate_usd.rate_to_eur == Decimal('0.85')
        assert str(exchange_rate_usd) == f"USD - 0.85 ({exchange_rate_usd.date})"
    
    @pytest.mark.django_db
    def test_exchange_rate_validation_positive_rate(self):
        """Test validácie kladného kurzu"""
        from finance.models import ExchangeRate
        from django.core.exceptions import ValidationError
        from django.utils import timezone
        
        rate = ExchangeRate(
            currency='USD',
            rate_to_eur=-0.5,  # Záporný kurz
            date=timezone.now().date()
        )
        with pytest.raises(ValidationError) as exc_info:
            rate.full_clean()
        
        assert 'Exchange rate must be positive' in str(exc_info.value)
    
    @pytest.mark.django_db  
    def test_exchange_rate_validation_currency_length(self):
        """Test validácie dĺžky kódu meny"""
        from finance.models import ExchangeRate
        from django.core.exceptions import ValidationError
        from django.utils import timezone
        
        rate = ExchangeRate(
            currency='US',  # Príliš krátky
            rate_to_eur=1.0,
            date=timezone.now().date()
        )
        with pytest.raises(ValidationError) as exc_info:
            rate.full_clean()
        
        assert 'Currency code must be 3 characters long' in str(exc_info.value)
        
    @pytest.mark.django_db
    def test_exchange_rate_unique_constraint(self, exchange_rate_usd):
        """Test unikátnosti kurzu pre dátum a menu"""
        with pytest.raises(Exception):  # Môže byť IntegrityError alebo ValidationError
            ExchangeRate.objects.create(
                currency=exchange_rate_usd.currency,
                rate_to_eur=0.90,
                date=exchange_rate_usd.date
            )

# =============================================================================
# TRANSACTION TESTS
# =============================================================================

class TestTransaction:
    """Testy pre Transaction model"""
    
    def test_expense_transaction_creation(self, expense_transaction, test_user, test_workspace):
        """Test vytvorenia expense transakcie"""
        assert expense_transaction.user == test_user
        assert expense_transaction.workspace == test_workspace
        assert expense_transaction.type == 'expense'
        assert expense_transaction.original_amount == 100.50
        assert expense_transaction.tags == ['potraviny', 'nakup']
        assert 'potraviny' in expense_transaction.tags
    
    def test_income_transaction_creation(self, income_transaction, test_user, test_workspace):
        """Test vytvorenia income transakcie"""
        assert income_transaction.user == test_user
        assert income_transaction.workspace == test_workspace
        assert income_transaction.type == 'income'
        assert income_transaction.original_amount == 2000.00
    
    def test_transaction_category_property(self, expense_transaction, income_transaction):
        """Test category property"""
        assert expense_transaction.category == expense_transaction.expense_category
        assert income_transaction.category == income_transaction.income_category
    
    def test_transaction_validation_both_categories(self, test_user, test_workspace, expense_root_category, income_root_category):
        """Test validácie - obe kategórie naraz"""
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            income_category=income_root_category,
            original_amount=100.00,
            original_currency='EUR',
            date=timezone.now().date()
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert 'Transaction can have only one category type' in str(exc_info.value)
    
    def test_transaction_validation_no_category(self, test_user, test_workspace):
        """Test validácie - žiadna kategória"""
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            original_amount=100.00,
            original_currency='EUR',
            date=timezone.now().date()
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert 'Transaction must have one category' in str(exc_info.value)
    
    def test_transaction_validation_type_category_mismatch(self, test_user, test_workspace, income_root_category):
        """Test validácie - nesúlad typu a kategórie"""
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type='expense',  # Expense type
            income_category=income_root_category,  # Income category
            original_amount=100.00,
            original_currency='EUR',
            date=timezone.now().date()
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert 'Expense transaction cannot have income category' in str(exc_info.value)
    
    def test_transaction_validation_negative_amount(self, test_user, test_workspace, expense_root_category):
        """Test validácie - záporná suma"""
        transaction = Transaction(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=-50.00,  # Záporná suma
            original_currency='EUR',
            date=timezone.now().date()
        )
        with pytest.raises(ValidationError) as exc_info:
            transaction.full_clean()
        assert 'Transaction amount must be positive' in str(exc_info.value)
    
    def test_transaction_month_calculation(self, test_user, test_workspace, expense_root_category):
        """Test automatického výpočtu mesiaca"""
        test_date = timezone.datetime(2024, 1, 15).date()
        expected_month = timezone.datetime(2024, 1, 1).date()
        
        transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=100.00,
            original_currency='EUR',
            date=test_date
        )
        
        assert transaction.month == expected_month
    
    def test_transaction_string_representation(self, expense_transaction, test_user):
        """Test string reprezentácie transakcie"""
        expected = f"{test_user} | expense | {expense_transaction.amount_domestic} EUR"
        assert str(expense_transaction) == expected

# =============================================================================
# TRANSACTION DRAFT TESTS
# =============================================================================

class TestTransactionDraft:
    """Testy pre TransactionDraft model"""
    
    def test_draft_creation(self, transaction_draft, test_user, test_workspace):
        """Test vytvorenia draftu"""
        assert transaction_draft.user == test_user
        assert transaction_draft.workspace == test_workspace
        assert transaction_draft.draft_type == 'expense'
        assert len(transaction_draft.transactions_data) == 1
        assert transaction_draft.transactions_data[0]['original_amount'] == 50.00
    
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
            draft_type='expense'
        )
        with pytest.raises(ValidationError) as exc_info:
            draft.full_clean()
        assert 'Transactions data must be a list' in str(exc_info.value)
    
    def test_draft_validation_invalid_transaction_type(self, test_user, test_workspace):
        """Test validácie neplatného typu transakcie"""
        draft_data = [{'type': 'invalid_type', 'original_amount': 100}]
        draft = TransactionDraft(
            user=test_user,
            workspace=test_workspace,
            transactions_data=draft_data,
            draft_type='expense'
        )
        with pytest.raises(ValidationError) as exc_info:
            draft.full_clean()
        assert 'Invalid transaction type' in str(exc_info.value)
    
    def test_draft_unique_constraint(self, test_user, test_workspace):
        """Test unikátnosti draftu pre user/workspace/type - NEMÔŽE existovať duplikát"""
       
        # Vytvor prvý draft
        draft1 = TransactionDraft.objects.create(
            user=test_user,
            workspace=test_workspace,
            transactions_data=[{'type': 'expense', 'original_amount': 50}],
            draft_type='expense'
        )
        
        # Pokus o vytvorenie druhého draftu - malo by ZLYHAŤ
        with transaction.atomic():
            with pytest.raises(IntegrityError):
                TransactionDraft.objects.create(
                    user=test_user,
                    workspace=test_workspace,  
                    draft_type='expense',
                    transactions_data=[{'type': 'expense', 'original_amount': 100}]
                )
        
        # Refreshnúť prvý draft z databázy
        draft1.refresh_from_db()
        
        # Over že existuje stále len jeden draft
        drafts_count = TransactionDraft.objects.filter(
            user=test_user,
            workspace=test_workspace,
            draft_type='expense'
        ).count()
        
        assert drafts_count == 1
        assert draft1.transactions_data[0]['original_amount'] == 50

    def test_draft_atomic_replacement(self, test_user, test_workspace):
        """Test že API endpoint správne nahrádza draft (atomic replace)"""
        # Vytvor prvý draft
        draft1 = TransactionDraft.objects.create(
            user=test_user,
            workspace=test_workspace,
            transactions_data=[{'type': 'expense', 'original_amount': 50}],
            draft_type='expense'
        )
        
        # Simuluj atomic replacement (ako to robí API)
        with transaction.atomic():
            TransactionDraft.objects.filter(
                user=test_user,
                workspace=test_workspace,
                draft_type='expense'
            ).delete()
            
            draft2 = TransactionDraft.objects.create(
                user=test_user,
                workspace=test_workspace, 
                transactions_data=[{'type': 'expense', 'original_amount': 100}],
                draft_type='expense'
            )
        
        # Over že máme nový draft
        drafts_count = TransactionDraft.objects.filter(
            user=test_user,
            workspace=test_workspace,
            draft_type='expense'
        ).count()
        
        assert drafts_count == 1
        assert draft2.transactions_data[0]['original_amount'] == 100
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
        assert setup['workspace'].owner == setup['user']
        assert setup['workspace_settings'].workspace == setup['workspace']
        assert setup['expense_version'].workspace == setup['workspace']
        assert setup['income_version'].workspace == setup['workspace']
        
        # Overenie transakcií
        assert setup['expense_transaction'].workspace == setup['workspace']
        assert setup['income_transaction'].workspace == setup['workspace']
        assert setup['expense_transaction'].user == setup['user']
        assert setup['income_transaction'].user == setup['user']
    
    def test_multiple_transactions_same_workspace(self, complete_workspace_setup):
        """Test viacerých transakcií v rovnakom workspace"""
        setup = complete_workspace_setup
        
        # Pridanie ďalšej transakcie
        new_transaction = Transaction.objects.create(
            user=setup['user'],
            workspace=setup['workspace'],
            type='expense',
            expense_category=setup['expense_category'],
            original_amount=75.25,
            original_currency='EUR',
            amount_domestic=75.25,
            date=timezone.now().date(),
            month=timezone.now().date().replace(day=1)
        )
        
        # Overenie že obe transakcie sú v rovnakom workspace
        transactions = Transaction.objects.filter(workspace=setup['workspace'])
        assert transactions.count() >= 2
        assert setup['expense_transaction'] in transactions
        assert new_transaction in transactions