# finance/tests/unit/test_utils_currency.py
import pytest
from decimal import Decimal
from datetime import date, timedelta
from django.utils import timezone
from unittest.mock import patch
from finance.utils.currency_utils import (
    CurrencyConversionError,
    get_exchange_rates_for_range,
    find_closest_rate,
    convert_amount_to_domestic,
    recalculate_transactions_domestic_amount
)


class TestCurrencyConversionError:
    """Testy pre CurrencyConversionError exception"""
    
    def test_currency_conversion_error_creation(self):
        """Test vytvorenia CurrencyConversionError"""
        error = CurrencyConversionError(
            message="Conversion failed",
            currency="USD",
            tx_date=date(2024, 1, 15),
            transaction_id=123
        )
        assert error.message == "Conversion failed"
        assert error.currency == "USD"
        assert error.tx_date == date(2024, 1, 15)
        assert error.transaction_id == 123
        assert str(error) == "Conversion failed"


class TestGetExchangeRatesForRange:
    """Testy pre get_exchange_rates_for_range funkciu"""
    
    @pytest.mark.django_db
    def test_get_exchange_rates_basic(self, exchange_rate_usd, exchange_rate_eur):
        """Test získania exchange rates pre rozsah dátumov"""
        currencies = ['USD', 'EUR']
        date_from = timezone.now().date() - timedelta(days=7)
        date_to = timezone.now().date()
        
        rates = get_exchange_rates_for_range(currencies, date_from, date_to)
        
        assert 'USD' in rates
        assert len(rates['USD']) > 0
        # EUR by nemalo byť v rates, lebo je to base currency
        assert 'EUR' not in rates
    
    @pytest.mark.django_db
    def test_get_exchange_rates_missing_currency(self):
        """Test získania rates pre chýbajúcu menu"""
        currencies = ['NONEXISTENT']
        date_from = timezone.now().date() - timedelta(days=7)
        date_to = timezone.now().date()
        
        with pytest.raises(CurrencyConversionError) as exc_info:
            get_exchange_rates_for_range(currencies, date_from, date_to)
        
        assert 'No exchange rates found' in str(exc_info.value)
        assert 'NONEXISTENT' in str(exc_info.value)
    
    def test_get_exchange_rates_empty_currencies(self):
        """Test získania rates pre prázdny zoznam mien"""
        currencies = []
        date_from = timezone.now().date() - timedelta(days=7)
        date_to = timezone.now().date()
        
        rates = get_exchange_rates_for_range(currencies, date_from, date_to)
        
        assert rates == {}
    
    def test_get_exchange_rates_only_eur(self):
        """Test získania rates len pre EUR (base currency)"""
        currencies = ['EUR']
        date_from = timezone.now().date() - timedelta(days=7)
        date_to = timezone.now().date()
        
        rates = get_exchange_rates_for_range(currencies, date_from, date_to)
        
        # EUR by nemalo byť v rates, lebo je to base currency
        assert rates == {}


class TestFindClosestRate:
    """Testy pre find_closest_rate funkciu"""
    
    def test_find_closest_rate_exact_match(self):
        """Test nájdenia presne zhodného dátumu"""
        rates = {
            'USD': {
                date(2024, 1, 10): Decimal('0.85'),
                date(2024, 1, 15): Decimal('0.86'),
                date(2024, 1, 20): Decimal('0.87')
            }
        }
        
        result = find_closest_rate(rates, 'USD', date(2024, 1, 15))
        
        assert result == Decimal('0.86')
    
    def test_find_closest_rate_previous_day(self):
        """Test nájdenia najbližšieho predchádzajúceho dátumu"""
        rates = {
            'USD': {
                date(2024, 1, 10): Decimal('0.85'),
                date(2024, 1, 15): Decimal('0.86'),
                date(2024, 1, 20): Decimal('0.87')
            }
        }
        
        result = find_closest_rate(rates, 'USD', date(2024, 1, 18))
        
        assert result == Decimal('0.86')  # Mal by vrátiť 15.1, nie 20.1
    
    def test_find_closest_rate_currency_not_found(self):
        """Test hľadania rates pre neexistujúcu menu"""
        rates = {
            'USD': {
                date(2024, 1, 15): Decimal('0.86')
            }
        }
        
        with pytest.raises(CurrencyConversionError) as exc_info:
            find_closest_rate(rates, 'EUR', date(2024, 1, 15))
        
        assert 'No exchange rates available' in str(exc_info.value)
        assert 'EUR' in str(exc_info.value)
    
    def test_find_closest_rate_no_rates_before_date(self):
        """Test hľadania rates keď nie sú žiadne pred dátumom"""
        rates = {
            'USD': {
                date(2024, 1, 20): Decimal('0.87'),
                date(2024, 1, 25): Decimal('0.88')
            }
        }
        
        with pytest.raises(CurrencyConversionError) as exc_info:
            find_closest_rate(rates, 'USD', date(2024, 1, 15))
        
        assert 'No exchange rate found' in str(exc_info.value)
        assert 'on or before' in str(exc_info.value)


class TestConvertAmountToDomestic:
    """Testy pre convert_amount_to_domestic funkciu"""
    
    def test_convert_same_currency(self):
        """Test konverzie rovnakej meny"""
        rates = {
            'USD': {
                date(2024, 1, 15): Decimal('0.85')
            }
        }
        
        result = convert_amount_to_domestic(
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            domestic_currency='EUR',
            tx_date=date(2024, 1, 15),
            rates=rates
        )
        
        assert result == Decimal('100.00')
    
    def test_convert_to_eur(self):
        """Test konverzie do EUR"""
        rates = {
            'USD': {
                date(2024, 1, 15): Decimal('0.85')
            }
        }
        
        result = convert_amount_to_domestic(
            original_amount=Decimal('100.00'),
            original_currency='USD',
            domestic_currency='EUR',
            tx_date=date(2024, 1, 15),
            rates=rates
        )
        
        # 100 USD * 0.85 = 85 EUR
        expected = Decimal('100.00') * Decimal('0.85')
        assert result == expected.quantize(Decimal('0.0001'))
    
    def test_convert_from_eur(self):
        """Test konverzie z EUR"""
        rates = {
            'USD': {
                date(2024, 1, 15): Decimal('0.85')
            }
        }
        
        result = convert_amount_to_domestic(
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            domestic_currency='USD',
            tx_date=date(2024, 1, 15),
            rates=rates
        )
        
        # 100 EUR / 0.85 = 117.6470 USD
        expected = Decimal('100.00') / Decimal('0.85')
        assert result == expected.quantize(Decimal('0.0001'))
    
    def test_convert_cross_currency(self):
        """Test krížovej konverzie medzi dvoma menami"""
        rates = {
            'USD': {
                date(2024, 1, 15): Decimal('0.85')  # 1 USD = 0.85 EUR
            },
            'GBP': {
                date(2024, 1, 15): Decimal('0.75')  # 1 GBP = 0.75 EUR
            }
        }
        
        result = convert_amount_to_domestic(
            original_amount=Decimal('100.00'),
            original_currency='USD',
            domestic_currency='GBP',
            tx_date=date(2024, 1, 15),
            rates=rates
        )
        
        # 100 USD → EUR: 100 * 0.85 = 85 EUR
        # 85 EUR → GBP: 85 / 0.75 = 113.3333 GBP
        expected = (Decimal('100.00') * Decimal('0.85')) / Decimal('0.75')
        assert result == expected.quantize(Decimal('0.0001'))
    
    def test_convert_invalid_amount_type(self):
        """Test konverzie s neplatným typom sumy"""
        rates = {'USD': {date(2024, 1, 15): Decimal('0.85')}}
        
        with pytest.raises(ValueError) as exc_info:
            convert_amount_to_domestic(
                original_amount="100.00",  # String namiesto čísla
                original_currency='USD',
                domestic_currency='EUR',
                tx_date=date(2024, 1, 15),
                rates=rates
            )
        
        assert 'must be a numeric type' in str(exc_info.value)
    
    def test_convert_empty_currency(self):
        """Test konverzie s prázdnym kódom meny"""
        rates = {'USD': {date(2024, 1, 15): Decimal('0.85')}}
        
        with pytest.raises(ValueError) as exc_info:
            convert_amount_to_domestic(
                original_amount=Decimal('100.00'),
                original_currency='',
                domestic_currency='EUR',
                tx_date=date(2024, 1, 15),
                rates=rates
            )
        
        assert 'Currency codes cannot be empty' in str(exc_info.value)


class TestRecalculateTransactionsDomesticAmount:
    """Testy pre recalculate_transactions_domestic_amount funkciu"""
    
    def test_recalculate_empty_transactions(self, test_workspace, workspace_settings):
        """Test preprázdny zoznam transakcií"""
        transactions = []
        
        result = recalculate_transactions_domestic_amount(transactions, test_workspace)
        
        assert result == []
    
    def test_recalculate_same_currency(self, expense_transaction, test_workspace, workspace_settings):
        """Test prepočtu keď je mena rovnaká"""
        # expense_transaction má EUR a workspace má EUR - žiadna konverzia
        transactions = [expense_transaction]
        
        result = recalculate_transactions_domestic_amount(transactions, test_workspace)
        
        # Mala by vrátiť pôvodné transakcie bez zmien
        assert result == transactions
        assert result[0].amount_domestic == expense_transaction.original_amount
    
    def test_recalculate_different_currency_no_rates(self, test_workspace, workspace_settings, test_user, expense_root_category):
        """Test prepočtu s rôznou menou ale bez exchange rates"""
        from finance.models import Transaction
        
        # Vytvor transakciu s USD menou
        usd_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='USD',  # Rôzna mena
            amount_domestic=Decimal('0.00'),  # Pôvodne 0
            date=timezone.now().date(),
            month=timezone.now().date().replace(day=1)
        )
        
        transactions = [usd_transaction]
        
        # Toto by malo zlyhať, lebo nemáme exchange rates pre USD
        with pytest.raises(CurrencyConversionError) as exc_info:
            recalculate_transactions_domestic_amount(transactions, test_workspace)
        
        assert 'No exchange rates found' in str(exc_info.value)
        assert 'USD' in str(exc_info.value)
    
    def test_recalculate_with_exchange_rates(self, test_workspace, workspace_settings, test_user, expense_root_category, exchange_rate_usd):
        """Test prepočtu s exchange rates"""
        from finance.models import Transaction
        
        # Vytvor transakciu s USD menou
        usd_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='USD',
            amount_domestic=Decimal('0.00'),  # Pôvodne 0
            date=exchange_rate_usd.date,  # Použijeme dátum kedy máme rate
            month=exchange_rate_usd.date.replace(day=1)
        )
        
        transactions = [usd_transaction]
        
        result = recalculate_transactions_domestic_amount(transactions, test_workspace)
        
        # Over že domestic amount bol prepočítaný
        assert result[0].amount_domestic > Decimal('0.00')
        assert result[0].amount_domestic != usd_transaction.original_amount
    
    def test_recalculate_mixed_currencies(self, test_workspace, workspace_settings, test_user, expense_root_category, exchange_rate_usd, exchange_rate_gbp):
        """Test prepočtu zmiešaných mien"""
        from finance.models import Transaction
        
        # Vytvor exchange rates pre rôzne meny
        from finance.models import ExchangeRate
         
        # Vytvor transakcie s rôznymi menami
        eur_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            amount_domestic=Decimal('100.00'),
            date=timezone.now().date(),
            month=timezone.now().date().replace(day=1)
        )
        
        usd_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='USD',
            amount_domestic=Decimal('0.00'),
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1)
        )
        
        gbp_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='GBP',
            amount_domestic=Decimal('0.00'),
            date=exchange_rate_gbp.date,
            month=exchange_rate_gbp.date.replace(day=1)
        )
        
        transactions = [eur_transaction, usd_transaction, gbp_transaction]
        
        result = recalculate_transactions_domestic_amount(transactions, test_workspace)
        
        # EUR transakcia by mala zostať rovnaká
        assert result[0].amount_domestic == eur_transaction.original_amount
        
        # USD a GBP transakcie by mali byť prepočítané
        assert result[1].amount_domestic != usd_transaction.original_amount
        assert result[2].amount_domestic != gbp_transaction.original_amount
        
        # Over že všetky domestic amounts sú kladné
        for transaction in result:
            assert transaction.amount_domestic > Decimal('0.00')
    
    def test_recalculate_transactions_with_valid_dates(self, test_workspace, workspace_settings, test_user, expense_root_category, exchange_rate_usd):
        """Test prepočtu transakcií s platnými dátumami"""
        from finance.models import Transaction
        
        # Vytvor transakciu s platným dátumom kedy máme exchange rates
        transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='USD',
            amount_domestic=Decimal('0.00'),
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1)
        )
        
        transactions = [transaction]
        
        # Toto by malo prejsť
        result = recalculate_transactions_domestic_amount(transactions, test_workspace)
        
        assert result[0].amount_domestic > Decimal('0.00')
        assert result[0].amount_domestic != transaction.original_amount


class TestIntegrationScenarios:
    """Integračné testy pre komplexné scenáre"""
    
    def test_complete_currency_conversion_flow(self, test_workspace, workspace_settings, test_user, expense_root_category):
        """Test kompletného flow konverzie mien"""
        from finance.models import Transaction, ExchangeRate

        # Vytvor exchange rates
        usd_rate = ExchangeRate.objects.create(
            currency='USD',
            rate_to_eur=Decimal('0.85'),
            date=date(2024, 1, 15)
        )

        gbp_rate = ExchangeRate.objects.create(
            currency='GBP',
            rate_to_eur=Decimal('0.75'), 
            date=date(2024, 1, 15)
        )

        # SCENÁR 1: Nové transakcie - automatický prepočet
        eur_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='EUR',
            date=date(2024, 1, 15)
        )

        usd_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='USD',
            date=date(2024, 1, 15)
        )

        gbp_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type='expense',
            expense_category=expense_root_category,
            original_amount=Decimal('100.00'),
            original_currency='GBP',
            date=date(2024, 1, 15)
        )

        # SCENÁR 2: Manuálny prepočet existujúcich transakcií
        transactions = [eur_transaction, usd_transaction, gbp_transaction]
        result = recalculate_transactions_domestic_amount(transactions, test_workspace)

        # Over správnosť prepočtu
        assert result[0].amount_domestic == Decimal('100.00')  # EUR → EUR
        assert result[1].amount_domestic == Decimal('85.0000')  # USD → EUR
        assert result[2].amount_domestic == Decimal('75.0000')  # GBP → EUR

        # SCENÁR 3: Update transakcie - kontrola prepočtu
        usd_transaction.original_amount = Decimal('200.00')
        usd_transaction.save()
        
        usd_transaction.refresh_from_db()
        assert usd_transaction.amount_domestic == Decimal('170.0000')  # 200 USD → 170 EUR

class TestMissingCoverage:
    """Testy pre konkrétne nepokryté riadky"""
    
    @pytest.mark.django_db
    def test_get_exchange_rates_specific_error_branch(self):
        """Test konkrétnej error vetvy v get_exchange_rates_for_range"""
        # Toto by malo pokryť riadky 148-157
        currencies = ['NONEXISTENT_CURRENCY']
        date_from = date(2024, 1, 1)
        date_to = date(2024, 1, 31)
        
        with pytest.raises(CurrencyConversionError) as exc_info:
            get_exchange_rates_for_range(currencies, date_from, date_to)
        
        assert 'NONEXISTENT_CURRENCY' in str(exc_info.value)
    
    def test_convert_amount_specific_error_handling(self):
        """Test konkrétneho error handlingu v convert_amount_to_domestic"""
        # Toto by malo pokryť riadky 327-342
        rates = {
            'USD': {
                date(2024, 1, 15): Decimal('0.85')
            }
        }
        
        # Simuluj chybu v find_closest_rate
        with patch('finance.utils.currency_utils.find_closest_rate') as mock_find:
            mock_find.side_effect = CurrencyConversionError("Mocked rate error")
            
            with pytest.raises(CurrencyConversionError) as exc_info:
                convert_amount_to_domestic(
                    original_amount=Decimal('100.00'),
                    original_currency='USD',
                    domestic_currency='EUR', 
                    tx_date=date(2024, 1, 15),
                    rates=rates,
                    transaction_id=123
                )
            
            assert 'Mocked rate error' in str(exc_info.value)
            assert exc_info.value.transaction_id == 123