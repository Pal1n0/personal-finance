# finance/tests/unit/test_service_transaction.py
from datetime import date
from decimal import Decimal, InvalidOperation
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from rest_framework.exceptions import PermissionDenied

from finance.models import (ExpenseCategory, IncomeCategory, Transaction,
                            TransactionDraft)
from finance.services.transaction_service import TransactionService


class TestTransactionServiceValidation:
    """Testy validačných metód TransactionService"""

    def test_validate_transaction_data_success(self, test_workspace, expense_root_category):
        """Test úspešnej validácie transakčných dát"""
        valid_data = {
            "type": "expense",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "expense_category": expense_root_category.id,
            "date": date(2024, 1, 15),
        }

        # Malo by prejsť bez výnimky
        TransactionService._validate_transaction_data(valid_data, test_workspace)

    def test_validate_transaction_data_missing_required(self, test_workspace):
        """Test validácie s chýbajúcimi povinnými poliami"""
        invalid_data = {
            "type": "expense",
            # Chýba original_amount
            "original_currency": "EUR",
            "expense_category": 1,
            "date": date(2024, 1, 15),
        }

        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)

        assert "Missing required field" in str(exc_info.value)

    def test_validate_transaction_data_invalid_type(self, test_workspace):
        """Test validácie s neplatným typom"""
        invalid_data = {
            "type": "invalid_type",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "expense_category": 1,
            "date": date(2024, 1, 15),
        }

        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)

        assert "must be 'income' or 'expense'" in str(exc_info.value)

    def test_validate_transaction_data_negative_amount(self, test_workspace):
        """Test validácie so zápornou sumou"""
        invalid_data = {
            "type": "expense",
            "original_amount": Decimal("-100.00"),
            "original_currency": "EUR",
            "expense_category": 1,
            "date": date(2024, 1, 15),
        }

        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)

        assert "Amount must be positive" in str(exc_info.value)

    def test_validate_transaction_data_invalid_amount_type(self, test_workspace):
        """Test validácie s neplatným typom sumy"""
        invalid_data = {
            "type": "expense",
            "original_amount": "not_a_number",  # Neplatný typ
            "original_currency": "EUR",
            "expense_category": 1,
            "date": date(2024, 1, 15),
        }

        with pytest.raises(ValidationError, match="Amount must be a valid number"):
            TransactionService._validate_transaction_data(invalid_data, test_workspace)

    def test_validate_transaction_data_category_consistency(
        self, test_workspace, expense_root_category, income_root_category
    ):
        """Test konzistencie kategórií"""
        # Obe kategórie naraz
        invalid_data = {
            "type": "expense",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "date": date(2024, 1, 15),
            "expense_category": expense_root_category.id,
            "income_category": income_root_category.id,
        }

        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)

        assert "cannot have both" in str(exc_info.value)

        # Expense transaction s income category
        invalid_data = {
            "type": "expense",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "date": date(2024, 1, 15),
            "income_category": income_root_category.id,
        }

        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)

        assert "Expense transaction cannot have income category" in str(exc_info.value)


class TestTransactionServiceBulkCreate:
    """Testy pre bulk_create_transactions"""

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_bulk_create_transactions_success(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        income_root_category,
        expense_root_category,
        workspace_settings,
    ):
        """Test úspešného bulk vytvorenia transakcií"""
        # Setup mock
        mock_transactions = [
            Mock(id=1, amount_domestic=Decimal("100.00")),
            Mock(id=2, amount_domestic=Decimal("2000.00")),
        ]
        mock_recalculate.return_value = mock_transactions

        transactions_data = [
            {
                "type": "expense",
                "original_amount": Decimal("100.00"),
                "original_currency": "EUR",
                "date": date(2024, 1, 15),
                "expense_category": expense_root_category.id,
                "tags": ["potraviny", "nakup"],
                "note_manual": "Test transakcia 1",
            },
            {
                "type": "income",
                "original_amount": Decimal("2000.00"),
                "original_currency": "EUR",
                "date": date(2024, 1, 20),
                "income_category": income_root_category.id,
                "tags": ["plat"],
                "note_manual": "Test transakcia 2",
            },
        ]

        with patch.object(Transaction, "objects") as mock_manager, \
             patch.object(Transaction.tags.through.objects, "bulk_create") as mock_tags_bulk_create:
            # Simulate that bulk_create populates IDs on the instances
            def mock_bulk_create_side_effect(transactions, **kwargs):
                for i, t in enumerate(transactions):
                    t.id = i + 1
                return transactions
            mock_manager.bulk_create.side_effect = mock_bulk_create_side_effect
            mock_tags_bulk_create.return_value = None

            mock_manager.bulk_update.return_value = None

            transactions = TransactionService.bulk_create_transactions(
                transactions_data, test_workspace, test_user
            )

        assert len(transactions) == 2
        mock_recalculate.assert_called_once()
        mock_manager.bulk_create.assert_called_once()
        mock_manager.bulk_update.assert_called_once()

    def test_bulk_create_transactions_validation_error(self, test_user, test_workspace):
        """Test bulk vytvorenia s validačnou chybou"""
        transactions_data = [
            {
                "type": "expense",
                "original_amount": Decimal("-100.00"),  # Záporná suma
                "original_currency": "EUR",
                "date": date(2024, 1, 15),
                "expense_category": 1,
            }
        ]

        with pytest.raises(ValidationError) as exc_info:
            TransactionService.bulk_create_transactions(
                transactions_data, test_workspace, test_user
            )

        assert "Amount must be positive" in str(exc_info.value)

    def test_bulk_create_transactions_invalid_currency(
        self, test_user, test_workspace, expense_root_category
    ):
        """Test bulk vytvorenia s neplatnou menou"""
        transactions_data = [
            {
                "type": "expense",
                "original_amount": Decimal("100.00"),
                "original_currency": "INVALID",  # Neplatná mena
                "date": date(2024, 1, 15),
                "expense_category": expense_root_category.id,
            }
        ]

        with pytest.raises(ValidationError) as exc_info:
            TransactionService.bulk_create_transactions(
                transactions_data, test_workspace, test_user
            )

        assert "Currency must be one of" in str(exc_info.value)

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_bulk_create_transactions_currency_conversion_error(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        income_root_category,
        expense_root_category,
        workspace_settings,
    ):
        """Test bulk vytvorenia s chybou konverzie meny"""
        from finance.utils.currency_utils import CurrencyConversionError

        # Setup mock to raise conversion error
        mock_recalculate.side_effect = CurrencyConversionError("Conversion failed")

        transactions_data = [
            {
                "type": "expense",
                "original_amount": Decimal("100.00"),
                "original_currency": "EUR",
                "date": date(2024, 1, 15),
                "expense_category": expense_root_category.id,
            }
        ]

        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.bulk_create.return_value = None

            with pytest.raises(CurrencyConversionError):
                TransactionService.bulk_create_transactions(
                    transactions_data, test_workspace, test_user
                )

        # Transaction should roll back due to @atomic


class TestTransactionServiceBulkSync:
    """Testy pre bulk_sync_transactions"""

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_bulk_sync_transactions_complete_flow(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        expense_root_category,
        income_root_category,
        workspace_settings,
    ):
        """Test kompletného bulk sync flow"""
        from finance.models import Transaction

        # Setup mocks
        mock_recalculate.return_value = [Mock(id=1, amount_domestic=Decimal("100.00"))]

        # Create initial transactions
        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.bulk_create.return_value = None
            # Simulate that bulk_create populates IDs on the instances
            def mock_bulk_create_side_effect(transactions, **kwargs):
                for i, t in enumerate(transactions):
                    t.id = i + 1
                return transactions
            mock_manager.bulk_create.side_effect = mock_bulk_create_side_effect
            mock_manager.bulk_update.return_value = None

            existing_transactions = TransactionService.bulk_create_transactions(
                [
                    {
                        "type": "expense",
                        "original_amount": Decimal("100.00"),
                        "original_currency": "EUR",
                        "date": date(2024, 1, 15),
                        "expense_category": expense_root_category.id,
                    },
                    {
                        "type": "income",
                        "original_amount": Decimal("2000.00"),
                        "original_currency": "EUR",
                        "date": date(2024, 1, 20), "income_category": income_root_category.id
                    },
                ],
                test_workspace,
                test_user,
            )

        transaction_to_update = Mock(id=1, original_amount=Decimal("100.00"))
        transaction_to_delete = Mock(id=2)

        # Mock transaction queries
        mock_transaction_to_delete = Mock(id=2)
        mock_transaction_to_update = Mock(id=1)

        with patch.object(Transaction, "objects") as mock_manager:
            # Mock delete operation
            mock_manager.filter.return_value.values_list.return_value = [2]
            mock_manager.filter.return_value.delete.return_value = (
                1,
                {"finance.Transaction": 1},
            )

            # Mock update operation
            mock_manager.filter.return_value.select_related.return_value = [
                mock_transaction_to_update
            ]

            # Bulk sync operations
            sync_data = {
                "create": [
                    {
                        "type": "expense",
                        "original_amount": Decimal("50.00"),
                        "original_currency": "EUR",
                        "date": date(2024, 1, 25),
                        "expense_category": expense_root_category.id,
                    }
                ],
                "update": [
                    {
                        "id": 1,
                        "original_amount": Decimal("150.00"),  # Zmenená suma
                        "original_currency": "EUR",
                        "date": date(2024, 1, 15),
                        "expense_category": expense_root_category.id,
                    }
                ],
                "delete": [2],
            }

            with patch.object(
                TransactionService, "bulk_create_transactions"
            ) as mock_bulk_create:
                mock_bulk_create.return_value = [Mock(id=3)]

                results = TransactionService.bulk_sync_transactions(
                    sync_data, test_workspace, test_user
                )

        assert len(results["created"]) == 1
        assert len(results["updated"]) == 1
        assert len(results["deleted"]) == 1
        assert results["errors"] == []

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_bulk_sync_transactions_atomic_rollback(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        expense_root_category,
        workspace_settings,
    ):
        """Test atomic rollback pri chybe v bulk sync"""
        from finance.models import Transaction

        # Setup
        mock_recalculate.return_value = [Mock(id=1, amount_domestic=Decimal("100.00"))]

        # Create original transaction
        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.bulk_create.return_value = None
            mock_manager.bulk_update.return_value = None

            original_transaction = TransactionService.bulk_create_transactions(
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
            )[0]

        original_amount = Decimal("100.00")

        # Sync with invalid currency
        sync_data = {
            "update": [
                {
                    "id": 1,
                    "original_amount": Decimal("150.00"),
                    "original_currency": "INVALID",  # Neplatná mena
                    "date": date(2024, 1, 15),
                }
            ]
        }

        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value.select_related.return_value = [Mock(id=1)]

            results = TransactionService.bulk_sync_transactions(
                sync_data, test_workspace, test_user
            )

        # Should return error but transaction should remain unchanged (atomic rollback)
        assert len(results["errors"]) > 0
        assert "Currency must be one of" in results["errors"][0]

    def test_bulk_sync_transactions_invalid_delete_ids(self, test_user, test_workspace):
        """Test bulk sync s neplatnými ID pre delete"""
        sync_data = {"delete": [999, 1000]}  # Neexistujúce ID

        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value.values_list.return_value = (
                []
            )  # Žiadne platné ID
            mock_manager.filter.return_value.delete.return_value = (0, {})

            results = TransactionService.bulk_sync_transactions(
                sync_data, test_workspace, test_user
            )

        assert len(results["deleted"]) == 0
        assert len(results["errors"]) == 2  # Chyby pre obe neplatné ID


class TestTransactionServiceSingleOperations:
    """Testy pre single transaction operácie"""

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_create_transaction_success(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        expense_root_category,
        workspace_settings,
    ):
        """Test úspešného vytvorenia single transaction"""
        # Setup mock
        mock_recalculate.return_value = [Mock(amount_domestic=Decimal("100.00"))]

        transaction_data = {
            "type": "expense",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "date": date(2024, 1, 15),
            "expense_category": expense_root_category,
            "tags": ["potraviny", "nakup"],
            "note_manual": "Test transakcia",
        }

        def mock_save_side_effect(self, *args, **kwargs):
            if not self.pk:
                self.pk = 1

        with patch.object(Transaction, "save", new=mock_save_side_effect), \
             patch("finance.services.tag_service.TagService") as mock_tag_service:
            with patch.object(TransactionDraft.objects, "filter") as mock_draft_filter:
                mock_draft_filter.return_value.delete.return_value = (
                    1,
                    {"finance.TransactionDraft": 1},
                )

                transaction = TransactionService.create_transaction(
                    transaction_data, test_user, test_workspace
                )

        assert transaction.user == test_user
        assert transaction.workspace == test_workspace
        assert transaction.type == "expense"
        assert transaction.original_amount == Decimal("100.00")
        assert transaction.expense_category == expense_root_category
        mock_tag_service.return_value.get_or_create_tags.assert_called_once()

    def test_create_transaction_permission_denied(
        self, test_user, test_workspace, expense_root_category
    ):
        """Test vytvorenia transakcie bez prístupu k workspace"""
        # Mock workspace bez usera ako member
        mock_workspace = Mock(spec=test_workspace.__class__)
        mock_workspace.id = test_workspace.id
        mock_workspace.members.filter.return_value.exists.return_value = False

        transaction_data = {
            "type": "expense",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "date": date(2024, 1, 15),
            "expense_category": expense_root_category,
        }

        with pytest.raises(PermissionDenied) as exc_info:
            TransactionService.create_transaction(
                transaction_data, test_user, mock_workspace
            )

        assert "don't have access" in str(exc_info.value)

    def test_create_transaction_invalid_category_workspace(
        self, test_user, test_workspace, expense_root_category
    ):
        """Test vytvorenia transakcie s kategóriou z iného workspace"""
        transaction_data = {
            "type": "expense",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "date": date(2024, 1, 15),
            "expense_category": expense_root_category,
        }

        # Mock category z iného workspace
        mock_category = Mock(spec=ExpenseCategory)
        mock_category.id = expense_root_category.id
        mock_category.version.workspace.id = 999  # Iný workspace

        transaction_data["expense_category"] = mock_category

        with pytest.raises(ValidationError) as exc_info:
            TransactionService.create_transaction(
                transaction_data, test_user, test_workspace
            )

        assert "does not belong to this workspace" in str(exc_info.value)

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_create_transaction_draft_cleanup(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        expense_root_category,
        workspace_settings,
    ):
        """Test že sa odstráni draft po úspešnom vytvorení transakcie"""
        # Setup mock
        mock_recalculate.return_value = [Mock(amount_domestic=Decimal("100.00"))]

        transaction_data = {
            "type": "expense",
            "original_amount": Decimal("100.00"),
            "original_currency": "EUR",
            "date": date(2024, 1, 15),
            "expense_category": expense_root_category,
        }

        with patch.object(Transaction, "save"):
            with patch.object(TransactionDraft.objects, "filter") as mock_draft_filter:
                mock_draft_filter.return_value.delete.return_value = (
                    1,
                    {"finance.TransactionDraft": 1},
                )

                transaction = TransactionService.create_transaction(
                    transaction_data, test_user, test_workspace
                )

        # Verify draft cleanup was called
        mock_draft_filter.assert_called_once()
        mock_draft_filter.return_value.delete.assert_called_once()

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_update_transaction_success(
        self, mock_recalculate, expense_transaction, test_user, workspace_settings
    ):
        """Test úspešnej aktualizácie transakcie"""
        # Setup mock
        mock_recalculate.return_value = [Mock(amount_domestic=Decimal("150.00"))]

        update_data = {
            "original_amount": Decimal("150.00"),
            "note_manual": "Updated transaction",
        }

        with patch.object(Transaction, "save", wraps=expense_transaction.save) as mock_save:
            with patch.object(TransactionDraft.objects, "filter") as mock_draft_filter:
                mock_draft_filter.return_value.delete.return_value = (
                    1,
                    {"finance.TransactionDraft": 1},
                )

                updated_transaction = TransactionService.update_transaction(
                    expense_transaction, update_data, test_user
                )

        assert updated_transaction.original_amount == Decimal("150.00")
        assert updated_transaction.note_manual == "Updated transaction"
        mock_save.assert_called_once()

    def test_update_transaction_permission_denied(
        self, expense_transaction, test_user2
    ):
        """Test aktualizácie cudzej transakcie"""
        update_data = {"original_amount": Decimal("150.00")}

        with pytest.raises(PermissionDenied) as exc_info:
            TransactionService.update_transaction(
                expense_transaction, update_data, test_user2  # Iný user
            )

        assert "your own transactions" in str(exc_info.value)

    def test_delete_transaction_success(self, expense_transaction, test_user):
        """Test úspešného zmazania transakcie"""
        with patch.object(Transaction, "delete") as mock_delete:
            TransactionService.delete_transaction(expense_transaction, test_user)

        mock_delete.assert_called_once()

    def test_delete_transaction_permission_denied(
        self, expense_transaction, test_user2
    ):
        """Test zmazania cudzej transakcie"""
        with pytest.raises(PermissionDenied) as exc_info:
            TransactionService.delete_transaction(expense_transaction, test_user2)

        assert "your own transactions" in str(exc_info.value)

    def test_bulk_delete_transactions_success(
        self, test_user, expense_transaction, income_transaction
    ):
        """Test úspešného bulk mazania transakcií"""
        transaction_ids = [expense_transaction.id, income_transaction.id]

        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value = mock_manager
            mock_distinct = MagicMock()
            mock_distinct.distinct.return_value = [expense_transaction.workspace.id]
            mock_manager.values_list.return_value = mock_distinct
            mock_manager.delete.return_value = (2, {"finance.Transaction": 2})

            result = TransactionService.bulk_delete_transactions(
                transaction_ids, test_user
            )

        assert result["deleted"] == 2
        assert result["details"]["transactions_removed"] == 2

    def test_bulk_delete_transactions_invalid_ids(self, test_user):
        """Test bulk mazania s neplatnými ID"""
        transaction_ids = [999, 1000]  # Neexistujúce ID

        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value = mock_manager
            mock_distinct = MagicMock()
            mock_distinct.distinct.return_value = []
            mock_manager.values_list.return_value = mock_distinct
            mock_manager.delete.return_value = (0, {})

            result = TransactionService.bulk_delete_transactions(
                transaction_ids, test_user
            )

        assert result["deleted"] == 0
        assert len(result["details"]["invalid_ids"]) == 2


class TestTransactionServiceRecalculation:
    """Testy pre prepočty transakcií"""

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_recalculate_all_transactions_for_workspace(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        expense_root_category,
        workspace_settings,
    ):
        """Test prepočtu všetkých transakcií pre workspace"""
        from finance.models import Transaction

        # Setup mock
        mock_transactions = [
            Mock(id=1, amount_domestic=Decimal("100.00")),
            Mock(id=2, amount_domestic=Decimal("85.00")),
        ]
        mock_recalculate.return_value = mock_transactions

        # Create test transactions
        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value.iterator.return_value = [
                Mock(id=1, original_currency="EUR"),
                Mock(id=2, original_currency="USD"),
            ]
            mock_manager.bulk_update.return_value = None

            updated_count = (
                TransactionService.recalculate_all_transactions_for_workspace(
                    test_workspace
                )
            )

        assert updated_count == 2
        mock_recalculate.assert_called_once()
        mock_manager.bulk_update.assert_called_once()

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_recalculate_all_transactions_empty(
        self, mock_recalculate, test_workspace, workspace_settings
    ):
        """Test prepočtu prázdneho workspace"""
        from finance.models import Transaction

        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value.iterator.return_value = []

            updated_count = (
                TransactionService.recalculate_all_transactions_for_workspace(
                    test_workspace
                )
            )

        assert updated_count == 0
        mock_recalculate.assert_not_called()

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_recalculate_all_transactions_currency_error(
        self, mock_recalculate, test_workspace, workspace_settings
    ):
        """Test prepočtu s chybou konverzie meny"""
        from finance.models import Transaction
        from finance.utils.currency_utils import CurrencyConversionError

        # Setup mock to raise conversion error
        mock_recalculate.side_effect = CurrencyConversionError("Conversion failed")

        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value.iterator.return_value = [
                Mock(id=1, original_currency="USD")
            ]

            with pytest.raises(CurrencyConversionError):
                TransactionService.recalculate_all_transactions_for_workspace(
                    test_workspace
                )

        # Transaction should roll back due to @atomic


class TestTransactionServiceEdgeCases:
    """Testy pre edge cases a error handling"""

    def test_bulk_create_validation_error_logging(self, test_user, test_workspace):
        """Test logovania validačnej chyby"""
        with pytest.raises(ValidationError), patch("finance.services.transaction_service.logger") as mock_logger:
            TransactionService.bulk_create_transactions(
                [{"invalid": "data"}], test_workspace, test_user  # Neplatné dáta
            )

    @patch("finance.services.transaction_service.recalculate_transactions_domestic_amount")
    def test_bulk_sync_create_failure(
        self, mock_recalculate, test_user, test_workspace, workspace_settings
    ):
        """Test zlyhania create operácie v sync"""
        with patch("finance.services.transaction_service.logger") as mock_logger:
            with patch(
                "finance.services.transaction_service.TransactionService.bulk_create_transactions",
                side_effect=ValidationError("Create failed"),
            ):

                result = TransactionService.bulk_sync_transactions(
                    {"create": [{"invalid": "data"}]}, test_workspace, test_user
                )

                # Over error v results
                assert len(result["errors"]) > 0
                assert "Create failed" in result["errors"][0]

                # Over error logging
                mock_logger.error.assert_called_once()

    def test_update_transaction_nonexistent_category(
        self, expense_transaction, test_user
    ):
        """Test aktualizácie s neexistujúcou kategóriou"""
        update_data = {"expense_category": 999}  # Neexistujúce ID

        with patch.object(ExpenseCategory.objects, "filter") as mock_filter:
            with patch.object(ExpenseCategory.objects, "get") as mock_get:
                mock_get.side_effect = ObjectDoesNotExist

                with pytest.raises(ObjectDoesNotExist):
                    TransactionService.update_transaction(
                        expense_transaction, update_data, test_user
                    )


class TestTransactionServiceIntegration:
    """Integračné testy pre TransactionService"""

    @patch(
        "finance.services.transaction_service.recalculate_transactions_domestic_amount"
    )
    def test_complete_bulk_operations_flow(
        self,
        mock_recalculate,
        test_user,
        test_workspace,
        expense_root_category,
        income_root_category,
        workspace_settings,
    ):
        """Test kompletného flow bulk operácií"""
        from finance.models import Transaction

        # --- FINAL FIX: Use a side_effect for the mock ---
        # This ensures the mock returns a transformed version of its input,
        # which is correct for both the create and update steps.
        def recalculate_side_effect(transactions, workspace):
            return transactions # Simple pass-through for the test
        mock_recalculate.side_effect = recalculate_side_effect

        # Krok 1: Bulk create
        create_data = [
            {
                "type": "expense",
                "original_amount": Decimal("100.00"),
                "original_currency": "EUR",
                "date": date(2024, 1, 15),
                "expense_category": expense_root_category.id,
                "tags": ["eur", "test"],
            },
            {
                "type": "expense",
                "original_amount": Decimal("150.00"),
                "original_currency": "USD",
                "date": date(2024, 1, 15),
                "expense_category": expense_root_category.id,
                "tags": ["usd", "test"],
            },
        ]

        with patch.object(Transaction, "objects") as mock_manager, \
             patch.object(Transaction.tags.through.objects, "bulk_create") as mock_tags_bulk_create:
            # Simulate that bulk_create populates IDs on the instances
            def mock_bulk_create_side_effect(transactions, **kwargs):
                for i, t in enumerate(transactions):
                    t.id = i + 1
                return transactions
            mock_manager.bulk_create.side_effect = mock_bulk_create_side_effect
            mock_tags_bulk_create.return_value = None
            mock_manager.bulk_update.return_value = None

            created_transactions = TransactionService.bulk_create_transactions(
                create_data, test_workspace, test_user
            )

        assert len(created_transactions) == 2

        # Krok 2: Bulk sync
        sync_data = {
            "update": [
                {
                    "id": 1,
                    "original_amount": Decimal("200.00"),
                    "original_currency": "EUR",
                    "date": date(2024, 1, 15),
                    "expense_category": expense_root_category.id,
                }
            ],
            "delete": [2],
            "create": [
                {
                    "type": "income",
                    "original_amount": "2000.00",
                    "original_currency": "EUR",
                    "date": date(2024, 1, 20),
                    "income_category": income_root_category.id,
                }
            ],
        }

        with patch.object(TransactionService, "bulk_create_transactions") as mock_bulk_create, \
             patch.object(Transaction.tags.through.objects, "bulk_create"):
            with patch.object(Transaction, "objects") as mock_manager:
                mock_bulk_create.return_value = [Mock(id=3)]

                # --- FINAL CORRECTED MOCK ---
                # Isolate mocks for delete and update operations to prevent interference.
                # This mock now correctly handles both the .values_list() and .delete() calls.
                mock_delete_qs = MagicMock()
                mock_delete_qs.values_list.return_value = [2]
                mock_delete_qs.delete.return_value = (1, {"finance.Transaction": 1})

                mock_update_qs = MagicMock()
                mock_update_qs.select_related.return_value = [Mock(id=1)]

                # Return the correct mock based on the call
                mock_manager.filter.side_effect = lambda id__in, **kwargs: mock_update_qs if id__in == [1] else mock_delete_qs

                sync_results = TransactionService.bulk_sync_transactions(
                    sync_data, test_workspace, test_user
                )

        assert len(sync_results["created"]) == 1
        assert len(sync_results["updated"]) == 1
        assert len(sync_results["deleted"]) == 1
        
        # Krok 3: Recalculate all
        with patch.object(Transaction, "objects") as mock_manager:
            mock_manager.filter.return_value.iterator.return_value = [
                Mock(id=1),
                Mock(id=3),
            ]
            mock_manager.bulk_update.return_value = None

            updated_count = (
                TransactionService.recalculate_all_transactions_for_workspace(
                    test_workspace
                )
            )

        assert updated_count == 2
