# finance/tests/unit/test_service_currency.py
from datetime import date
from decimal import Decimal
import logging
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError

from finance.models import Transaction, ExchangeRate
from finance.services.currency_service import CurrencyService
from finance.services.transaction_service import TransactionService


@pytest.fixture
def exchange_rate_usd_2025_11_08(db):
    return ExchangeRate.objects.create(currency="USD", rate_to_eur=Decimal("0.85"), date=date(2025, 11, 8))

@pytest.fixture
def exchange_rate_gbp(db):
    return ExchangeRate.objects.create(currency="GBP", rate_to_eur=Decimal("1.18"), date=date(2025, 11, 8))

@pytest.fixture
def exchange_rate_usd_2024(db):
    return ExchangeRate.objects.create(currency="USD", rate_to_eur=Decimal("0.92"), date=date(2024, 1, 1))

@pytest.fixture
def exchange_rate_usd_jan15(db):
    return ExchangeRate.objects.create(currency="USD", rate_to_eur=Decimal("0.85"), date=date(2024, 1, 15))

@pytest.fixture
def exchange_rate_usd_jan20(db):
    ExchangeRate.objects.filter(currency="USD", date=date(2024, 1, 20)).delete()
    return ExchangeRate.objects.create(currency="USD", rate_to_eur=Decimal("0.90"), date=date(2024, 1, 20))

@pytest.fixture
def exchange_rate_usd_2024_jan20(db):
    ExchangeRate.objects.filter(currency="USD", date=date(2024, 1, 20)).delete()
    return ExchangeRate.objects.create(currency="USD", rate_to_eur=Decimal("0.86"), date=date(2024, 1, 20))



class TestCurrencyService:
    """Testy pre CurrencyService"""

    def test_validate_currency_change_same_currency(self, workspace_settings):
        """Test validácie zmeny na rovnakú menu"""
        result = CurrencyService.validate_currency_change(
            workspace_settings, workspace_settings.domestic_currency
        )

        assert result["success"] is True
        assert result["valid"] is False
        assert "unchanged" in result["message"].lower()

    def test_validate_currency_change_valid(self, workspace_settings):
        """Test validácie platnej zmeny meny"""
        result = CurrencyService.validate_currency_change(workspace_settings, "USD")

        assert result["success"] is True
        assert result["valid"] is True
        assert result["new_currency"] == "USD"
        assert "valid" in result["message"].lower()

    def test_validate_currency_change_invalid(self, workspace_settings):
        """Test validácie neplatnej meny"""
        result = CurrencyService.validate_currency_change(workspace_settings, "INVALID")

        assert result["success"] is False
        assert result["valid"] is False
        assert "invalid" in result["message"].lower()
        assert "INVALID" in result["message"]

    @patch('finance.services.currency_service.logger')
    def test_change_workspace_currency_same_currency(self, mock_logger, workspace_settings):
        """Test zmeny na rovnakú menu - malo by preskočiť"""
        original_currency = workspace_settings.domestic_currency

        result = CurrencyService.change_workspace_currency(
            workspace_settings, original_currency
        )

        assert result["success"] is True
        assert result["changed"] is False
        assert result["transactions_updated"] == 0
        assert "unchanged" in result["message"].lower()

        # Check that logger.info was called with the correct message
        mock_logger.info.assert_called_once()
        call_args, _ = mock_logger.info.call_args
        assert "Currency change skipped - same currency" in call_args[0]

        # Over že sa nič nezmenilo
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == original_currency

    @patch('finance.services.currency_service.logger')
    def test_change_workspace_currency_invalid_currency(self, mock_logger, workspace_settings):
        """Test zmeny na neplatnú menu"""
        with pytest.raises(ValidationError) as exc_info:
            CurrencyService.change_workspace_currency(
                workspace_settings, "INVALID_CURRENCY"
            )

        assert "Invalid currency" in str(exc_info.value)
        assert "INVALID_CURRENCY" in str(exc_info.value)
        
        # Check that logger.error was called
        mock_logger.error.assert_called_once()
        call_args, _ = mock_logger.error.call_args
        assert "Invalid currency requested" in call_args[0]

    @patch('finance.services.currency_service.logger')
    def test_change_workspace_currency_success(
        self, mock_logger, workspace_settings, expense_transaction, exchange_rate_usd_2025_11_08
    ):
        """Test úspešnej zmeny meny"""
        # Presvedčíme sa že máme transakciu s EUR
        assert workspace_settings.domestic_currency == "EUR"
        assert expense_transaction.original_currency == "EUR"

        result = CurrencyService.change_workspace_currency(workspace_settings, "USD")

        assert result["success"] is True
        assert result["changed"] is True
        assert result["old_currency"] == "EUR"
        assert result["new_currency"] == "USD"
        assert (
            result["transactions_updated"] >= 0
        )  # Môže byť 0 ak žiadne transakcie nepotrebujú prepočet

        # Check for log messages
        info_calls = [call.args[0] for call in mock_logger.info.call_args_list]
        assert any("Starting atomic currency change process" in call for call in info_calls)
        assert any("Atomic currency change completed successfully" in call for call in info_calls)

        # Over že sa zmenila mena v settings
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == "USD"

    @patch('finance.services.currency_service.logger')
    def test_change_workspace_currency_atomic_rollback(
        self, mock_logger, workspace_settings, monkeypatch
    ):
        """Test že sa zmeny rollbacknú pri chybe"""
        original_currency = workspace_settings.domestic_currency

        # Mock TransactionService aby vyhodil chybu pomocou monkeypatch
        def mock_recalculate(*args, **kwargs):
            raise Exception("Simulated failure")

        monkeypatch.setattr(
            "finance.services.transaction_service.TransactionService.recalculate_all_transactions_for_workspace",
            mock_recalculate,
        )

        with pytest.raises(ValidationError) as exc_info:
            CurrencyService.change_workspace_currency(workspace_settings, "USD")

        # Získaj skutočnú chybovú správu
        error_message = (
            exc_info.value.args[0] if exc_info.value.args else str(exc_info.value)
        )
        assert "failed" in error_message.lower()
        assert "rolled back" in error_message.lower()

        # Check for log messages
        mock_logger.info.assert_called_with(
            "Starting atomic currency change process",
            extra={
                "workspace_settings_id": workspace_settings.id,
                "workspace_id": workspace_settings.workspace.id,
                "old_currency": original_currency,
                "new_currency": "USD",
                "currency_name": "US Dollar",
                "action": "atomic_currency_change_started",
                "component": "CurrencyService",
            },
        )
        mock_logger.error.assert_called_once()
        error_call_args, _ = mock_logger.error.call_args
        assert "Atomic currency change failed - transaction will roll back" in error_call_args[0]


        # Over že sa rollbacklo - mena by mala zostať pôvodná
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == original_currency

    def test_change_workspace_currency_with_transactions(
        self,
        workspace_settings,
        test_user,
        test_workspace,
        expense_root_category,
        exchange_rate_usd,
    ):
        """Test zmeny meny s transakciami v rôznych menách"""

        Transaction.objects.filter(workspace=test_workspace).delete()

        # Vytvoríme transakcie s rôznymi menami
        eur_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=Decimal("100.00"),
            original_currency="EUR",
            amount_domestic=Decimal("100.00"),
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1),
        )

        usd_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=Decimal("100.00"),
            original_currency="USD",
            amount_domestic=Decimal("85.00"),  # Predpokladaná hodnota
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1),
        )

        # Zmeníme menu z EUR na USD
        result = CurrencyService.change_workspace_currency(workspace_settings, "USD")

        assert result["success"] is True
        assert result["changed"] is True
        assert (
            result["transactions_updated"] == 2
        )  # Obe transakcie by sa mali prepočítať

        # Refresh transactions
        eur_transaction.refresh_from_db()
        usd_transaction.refresh_from_db()

        # EUR transakcia by mala mať nový domestic amount v USD
        assert eur_transaction.amount_domestic != Decimal("100.00")
        # USD transakcia by mala mať domestic amount rovný original amount (rovnaká mena)
        # POZOR: Po zmene meny na USD sa USD transakcia prepočíta podľa exchange rate!
        # Pôvodne: 100 USD * 0.85 (EUR/USD) = 85 EUR
        # Po zmene: 100 USD * 1.0 (USD/USD) = 100 USD
        assert usd_transaction.amount_domestic == Decimal("100.00")


class TestCurrencyServiceIntegration:
    """Integračné testy pre CurrencyService"""

    def test_complete_currency_change_flow(
        self,
        workspace_settings,
        test_workspace,
        test_user,
        expense_root_category,
        exchange_rate_usd,
        exchange_rate_gbp,
    ):
        """Test kompletného flow zmeny meny"""

        # Vytvoríme viacero transakcií s rôznymi menami
        transactions_data = [
            ("EUR", Decimal("100.00")),
            ("USD", Decimal("150.00")),
            ("GBP", Decimal("200.00")),
        ]

        for currency, amount in transactions_data:
            Transaction.objects.create(
                user=test_user,
                workspace=test_workspace,
                type="expense",
                expense_category=expense_root_category,
                original_amount=amount,
                original_currency=currency,
                amount_domestic=amount,  # Dočasná hodnota
                date=exchange_rate_usd.date,
                month=exchange_rate_usd.date.replace(day=1),
            )

        # Over pôvodný stav
        assert workspace_settings.domestic_currency == "EUR"
        eur_transactions = Transaction.objects.filter(
            workspace=test_workspace, original_currency="EUR"
        )
        assert eur_transactions.count() == 1

        # Zmeníme menu na USD
        result = CurrencyService.change_workspace_currency(workspace_settings, "USD")

        # Over výsledky
        assert result["success"] is True
        assert result["changed"] is True
        assert result["new_currency"] == "USD"
        assert result["transactions_updated"] == 3  # Všetky 3 transakcie

        # Over že sa zmenila mena v settings
        workspace_settings.refresh_from_db()
        assert workspace_settings.domestic_currency == "USD"

        # Over že transakcie majú správne domestic amounts
        transactions = Transaction.objects.filter(workspace=test_workspace)
        for tx in transactions:
            if tx.original_currency == "USD":
                # USD transakcie by mali mať domestic_amount = original_amount (rovnaká mena)
                assert tx.amount_domestic == tx.original_amount
            else:
                # Ostatné meny by mali mať prepočítané hodnoty
                assert tx.amount_domestic != tx.original_amount
                assert tx.amount_domestic > Decimal("0")


class TestTransactionService:
    """Testy pre TransactionService"""

    # ... existujúce testy ...

    def test_bulk_update_transactions_currency_change(
        self,
        test_user,
        test_workspace,
        expense_root_category,
        workspace_settings,
        exchange_rate_usd_jan15,
    ):
        """Test update transakcií so zmenou meny - malo by spustiť recalculáciu"""

        # Najprv vytvoríme transakciu
        existing_transactions = TransactionService.bulk_create_transactions(
            [
                {
                    "type": "expense",
                    "original_amount": Decimal("100.00"),
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),
                    "expense_category": expense_root_category.id,
                }
            ],
            test_workspace,
            test_user,
        )

        transaction = existing_transactions[0]
        original_domestic = transaction.amount_domestic

        # Update transakcie so zmenou meny
        sync_data = {
            "update": [
                {
                    "id": transaction.id,
                    "original_amount": Decimal("100.00"),
                    "original_currency": "USD",  # Zmena meny!
                    "date": date(2024, 1, 15),
                    "expense_category": expense_root_category.id,
                }
            ]
        }

        results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )

        assert len(results["updated"]) == 1
        assert results["errors"] == []

        # Refresh a overenie
        transaction.refresh_from_db()
        assert transaction.original_currency == "USD"
        # Domestic amount by sa mal prepočítať
        assert transaction.amount_domestic != original_domestic
        assert transaction.amount_domestic > Decimal("0")

    def test_bulk_update_transactions_amount_change(
        self, test_user, test_workspace, expense_root_category, workspace_settings
    ):
        """Test update transakcií so zmenou sumy - malo by spustiť recalculáciu"""

        # Najprv vytvoríme transakciu
        existing_transactions = TransactionService.bulk_create_transactions(
            [
                {
                    "type": "expense",
                    "original_amount": Decimal("100.00"),
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),
                    "expense_category": expense_root_category.id,
                }
            ],
            test_workspace,
            test_user,
        )

        transaction = existing_transactions[0]
        original_domestic = transaction.amount_domestic

        # Update transakcie so zmenou sumy
        sync_data = {
            "update": [
                {
                    "id": transaction.id,
                    "original_amount": Decimal("200.00"),  # Zmena sumy!
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),
                    "expense_category": expense_root_category.id,
                }
            ]
        }

        results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )

        assert len(results["updated"]) == 1
        assert results["errors"] == []

        # Refresh a overenie
        transaction.refresh_from_db()
        assert transaction.original_amount == Decimal("200.00")
        # Domestic amount by sa mal prepočítať
        assert transaction.amount_domestic != original_domestic
        assert transaction.amount_domestic > Decimal("0")

    def test_bulk_update_transactions_date_change(
        self,
        test_user,
        test_workspace,
        expense_root_category,
        workspace_settings,
        exchange_rate_usd_jan15,
        exchange_rate_usd_jan20,
    ):
        """Test update transakcií so zmenou dátumu - malo by spustiť recalculáciu (iný exchange rate)"""

        if workspace_settings.domestic_currency != "EUR":
            workspace_settings.domestic_currency = "EUR"
            workspace_settings.save()

        # Najprv vytvoríme transakciu s jedným dátumom
        existing_transactions = TransactionService.bulk_create_transactions(
            [
                {
                    "type": "expense",
                    "original_amount": Decimal("100.00"),
                    "original_currency": "USD",
                    "date": exchange_rate_usd_jan15.date,  # Dátum s rate 0.85
                    "expense_category": expense_root_category.id,
                }
            ],
            test_workspace,
            test_user,
        )

        transaction = existing_transactions[0]
        original_domestic = transaction.amount_domestic

        # Update transakcie so zmenou dátumu (na dátum s iným exchange rate)
        sync_data = {
            "update": [
                {
                    "id": transaction.id,
                    "original_amount": Decimal("100.00"),
                    "original_currency": "USD",
                    "date": exchange_rate_usd_jan20.date,  # Dátum s rate 0.90
                    "expense_category": expense_root_category.id,
                }
            ]
        }

        results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )

        assert len(results["updated"]) == 1
        assert results["errors"] == []

        # Refresh a overenie
        transaction.refresh_from_db()
        assert transaction.date == exchange_rate_usd_jan20.date
        # Domestic amount by sa mal prepočítať (iný exchange rate)
        assert transaction.amount_domestic != original_domestic
        assert transaction.amount_domestic > Decimal("0")
        expected_domestic = Decimal("90.0000")  # 100 USD × 0.90 = 90 EUR
        assert (
            transaction.amount_domestic == expected_domestic
        ), f"Expected {expected_domestic}, got {transaction.amount_domestic}"

    def test_bulk_update_transactions_no_recalculation_needed(
        self, test_user, test_workspace, expense_root_category, workspace_settings
    ):
        """Test update transakcií bez zmien ktoré vyžadujú recalculáciu"""

        # Najprv vytvoríme transakciu
        existing_transactions = TransactionService.bulk_create_transactions(
            [
                {
                    "type": "expense",
                    "original_amount": Decimal("100.00"),
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),
                    "expense_category": expense_root_category.id,
                    "note_manual": "Pôvodná poznámka",
                }
            ],
            test_workspace,
            test_user,
        )

        transaction = existing_transactions[0]
        original_domestic = transaction.amount_domestic

        # Update transakcie so zmenou len note_manual (nezmení sa recalculácia)
        sync_data = {
            "update": [
                {
                    "id": transaction.id,
                    "original_amount": Decimal("100.00"),
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),
                    "expense_category": expense_root_category.id,
                    "note_manual": "Nová poznámka",  # Len zmena poznámky
                }
            ]
        }

        results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )

        assert len(results["updated"]) == 1
        assert results["errors"] == []

        # Refresh a overenie
        transaction.refresh_from_db()
        assert transaction.note_manual == "Nová poznámka"
        # Domestic amount by mal ostať rovnaký (žiadna recalculácia)
        assert transaction.amount_domestic == original_domestic

    def test_bulk_sync_mixed_operations_with_recalculation(
        self,
        test_user,
        test_workspace,
        expense_root_category,
        workspace_settings,
        exchange_rate_usd_2024_jan20,
    ):
        """Test kombinácie create + update operácií kde niektoré vyžadujú recalculáciu"""

        # Najprv vytvoríme existujúcu transakciu - EUR nepotrebuje exchange rate
        existing_transactions = TransactionService.bulk_create_transactions(
            [
                {
                    "type": "expense",
                    "original_amount": Decimal("100.00"),
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),  # Priamo dátum, nie z fixture
                    "expense_category": expense_root_category.id,
                }
            ],
            test_workspace,
            test_user,
        )

        transaction_to_update = existing_transactions[0]
        original_domestic = transaction_to_update.amount_domestic

        # Bulk sync s kombináciou operácií
        sync_data = {
            "create": [
                {
                    "type": "expense",
                    "original_amount": Decimal("50.00"),
                    "original_currency": "USD",  # Nová transakcia - bude potrebovať recalculáciu
                    "date": exchange_rate_usd_2024_jan20.date,  # Použi dátum z fixture
                    "expense_category": expense_root_category.id,
                }
            ],
            "update": [
                {
                    "id": transaction_to_update.id,
                    "original_amount": Decimal(
                        "150.00"
                    ),  # Zmena sumy - bude potrebovať recalculáciu
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),  # Priamo dátum, nie z fixture
                    "expense_category": expense_root_category.id,
                }
            ],
        }

        results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )

        assert len(results["created"]) == 1
        assert len(results["updated"]) == 1
        assert results["errors"] == []

        # Refresh a overenie
        transaction_to_update.refresh_from_db()

        # Overenie že sa domestic amount zmenil (150 EUR namiesto 100 EUR)
        assert transaction_to_update.amount_domestic != original_domestic
        assert transaction_to_update.amount_domestic == Decimal(
            "150.0000"
        )  # 150 EUR × 1.00 = 150 EUR

        # Overenie novej transakcie
        new_transaction = Transaction.objects.get(id=results["created"][0])
        expected_new_domestic = Decimal("43.0000")  # 50 USD × 0.86 = 43 EUR
        assert new_transaction.amount_domestic == expected_new_domestic

    def test_change_workspace_currency_with_clean_transactions(
        self,
        workspace_settings,
        test_user,
        test_workspace,
        expense_root_category,
        exchange_rate_usd,
    ):
        """Test zmeny meny s čistým workspace (žiadne existujúce transakcie)"""
        # Vymaž existujúce transakcie pre čistý test
        Transaction.objects.filter(workspace=test_workspace).delete()

        # Vytvoríme presne 2 transakcie
        eur_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=Decimal("100.00"),
            original_currency="EUR",
            amount_domestic=Decimal("100.00"),
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1),
        )

        usd_transaction = Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=expense_root_category,
            original_amount=Decimal("100.00"),
            original_currency="USD",
            amount_domestic=Decimal("85.00"),
            date=exchange_rate_usd.date,
            month=exchange_rate_usd.date.replace(day=1),
        )

        # Zmeníme menu z EUR na USD
        result = CurrencyService.change_workspace_currency(workspace_settings, "USD")

        assert result["success"] is True
        assert result["changed"] is True
        assert result["transactions_updated"] == 2  # ✅ TERAZ PRESNÉ

        # Refresh transactions
        eur_transaction.refresh_from_db()
        usd_transaction.refresh_from_db()

        # Overíme že sa domestic amounts zmenili
        assert eur_transaction.amount_domestic != Decimal("100.00")
        assert usd_transaction.amount_domestic == Decimal("100.00")
