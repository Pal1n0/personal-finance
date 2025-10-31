# finance/tests/unit/test_currency_service.py
import pytest
from decimal import Decimal
from django.core.exceptions import ValidationError
from finance.services.currency_service import CurrencyService


class TestCurrencyService:
    """Testy pre CurrencyService"""
    
    def test_validate_currency_change_same_currency(self, workspace_settings):
        """Test validácie zmeny na rovnakú menu"""
        result = CurrencyService.validate_currency_change(
            workspace_settings, 
            workspace_settings.domestic_currency
        )
        
        assert result['success'] is True
        assert result['valid'] is False
        assert 'unchanged' in result['message'].lower()
    
    def test_validate_currency_change_valid(self, workspace_settings):
        """Test validácie platnej zmeny meny"""
        result = CurrencyService.validate_currency_change(
            workspace_settings, 
            'USD'
        )
        
        assert result['success'] is True
        assert result['valid'] is True
        assert result['new_currency'] == 'USD'
        assert 'valid' in result['message'].lower()
    
    def test_validate_currency_change_invalid(self, workspace_settings):
        """Test validácie neplatnej meny"""
        result = CurrencyService.validate_currency_change(
            workspace_settings, 
            'INVALID'
        )
        
        assert result['success'] is False
        assert result['valid'] is False
        assert 'invalid' in result['message'].lower()
        assert 'INVALID' in result['message']
    
    def test_change_workspace_currency_same_currency(self, workspace_settings):
        """Test zmeny na rovnakú menu - malo by preskočiť"""
        original_currency = workspace_settings.domestic_currency
        
        result = CurrencyService.change_workspace_currency(
            workspace_settings,
            original_currency
        )
        
        assert result['success'] is True
        assert result['changed'] is False
        assert result['transactions_updated'] == 0
        assert 'unchanged' in result['message'].lower()
        
        # Over že sa nič nezmenilo
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == original_currency
    
    def test_change_workspace_currency_invalid_currency(self, workspace_settings):
        """Test zmeny na neplatnú menu"""
        with pytest.raises(ValidationError) as exc_info:
            CurrencyService.change_workspace_currency(
                workspace_settings,
                'INVALID_CURRENCY'
            )
        
        assert 'Invalid currency' in str(exc_info.value)
        assert 'INVALID_CURRENCY' in str(exc_info.value)
    
    def test_change_workspace_currency_success(self, workspace_settings, expense_transaction, exchange_rate_usd):
        """Test úspešnej zmeny meny"""
        # Presvedčíme sa že máme transakciu s EUR
        assert workspace_settings.domestic_currency == 'EUR'
        assert expense_transaction.original_currency == 'EUR'
        
        result = CurrencyService.change_workspace_currency(
            workspace_settings,
            'USD'
        )
        
        assert result['success'] is True
        assert result['changed'] is True
        assert result['old_currency'] == 'EUR'
        assert result['new_currency'] == 'USD'
        assert result['transactions_updated'] >= 0  # Môže byť 0 ak žiadne transakcie nepotrebujú prepočet
        
        # Over že sa zmenila mena v settings
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == 'USD'
    
    def test_change_workspace_currency_atomic_rollback(self, workspace_settings, mocker):
        """Test že sa zmeny rollbacknú pri chybe"""
        original_currency = workspace_settings.domestic_currency
        
        # Mock TransactionService aby vyhodil chybu
        mocker.patch(
            'finance.services.transaction_service.TransactionService.recalculate_all_transactions_for_workspace',
            side_effect=Exception("Simulated failure")
        )
        
        with pytest.raises(ValidationError) as exc_info:
            CurrencyService.change_workspace_currency(
                workspace_settings,
                'USD'
            )
        
        assert 'failed' in str(exc_info.value).lower()
        assert 'rollback' in str(exc_info.value).lower()
        
        # Over že sa rollbacklo - mena by mala zostať pôvodná
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == original_currency
    
    def test_change_workspace_currency_with_transactions(self, workspace_settings, test_user, test_workspace, expense_root_category, exchange_rate_usd):
        """Test zmeny meny s transakciami v rôznych menách"""
        from finance.models import Transaction
        
        # Vytvoríme transakcie s rôznymi menami
        eur_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            amount_domestic=Decimal('100.00'),
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1)
        )
        
        usd_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='USD',
            amount_domestic=Decimal('85.00'),  # Predpokladaná hodnota
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1)
        )
        
        # Zmeníme menu z EUR na USD
        result = CurrencyService.change_workspace_currency(
            workspace_settings,
            'USD'
        )
        
        assert result['success'] is True
        assert result['changed'] is True
        assert result['transactions_updated'] == 2  # Obe transakcie by sa mali prepočítať
        
        # Refresh transactions
        eur_transaction.refresh_from_db()
        usd_transaction.refresh_from_db()
        
        # EUR transakcia by mala mať nový domestic amount v USD
        assert eur_transaction.amount_domestic != Decimal('100.00')
        # USD transakcia by mala mať domestic amount rovný original amount (rovnaká mena)
        assert usd_transaction.amount_domestic == Decimal('100.00')


class TestCurrencyServiceIntegration:
    """Integračné testy pre CurrencyService"""
    
    def test_complete_currency_change_flow(self, workspace_settings, test_workspace, test_user, expense_root_category, exchange_rate_usd, exchange_rate_gbp):
        """Test kompletného flow zmeny meny"""
        from finance.models import Transaction, ExchangeRate
        
        # Vytvoríme viacero transakcií s rôznymi menami
        transactions_data = [
            ('EUR', Decimal('100.00')),
            ('USD', Decimal('150.00')), 
            ('GBP', Decimal('200.00'))
        ]
        
        for currency, amount in transactions_data:
            Transaction.objects.create(
                user=test_user,
                workspace=test_workspace,
                type='expense',
                expense_category=expense_root_category,
                original_amount=amount,
                original_currency=currency,
                amount_domestic=amount,  # Dočasná hodnota
                date=exchange_rate_usd.date,
                month=exchange_rate_usd.date.replace(day=1)
            )
        
        # Over pôvodný stav
        assert workspace_settings.domestic_currency == 'EUR'
        eur_transactions = Transaction.objects.filter(workspace=test_workspace, original_currency='EUR')
        assert eur_transactions.count() == 1
        
        # Zmeníme menu na USD
        result = CurrencyService.change_workspace_currency(
            workspace_settings,
            'USD'
        )
        
        # Over výsledky
        assert result['success'] is True
        assert result['changed'] is True
        assert result['new_currency'] == 'USD'
        assert result['transactions_updated'] == 3  # Všetky 3 transakcie
        
        # Over že sa zmenila mena v settings
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == 'USD'
        
        # Over že transakcie majú správne domestic amounts
        transactions = Transaction.objects.filter(workspace=test_workspace)
        for tx in transactions:
            if tx.original_currency == 'USD':
                # USD transakcie by mali mať domestic_amount = original_amount
                assert tx.amount_domestic == tx.original_amount
            else:
                # Ostatné meny by mali mať prepočítané hodnoty
                assert tx.amount_domestic != tx.original_amount
                assert tx.amount_domestic > Decimal('0')