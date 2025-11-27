# finance/tests/unit/test_service_draft.py
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from rest_framework.exceptions import PermissionDenied

from finance.models import TransactionDraft, Workspace
from finance.services.draft_service import DraftService


class TestDraftServiceSaveDraft:
    """Testy pre save_draft metódu"""

    def test_save_draft_success_new_draft(self, test_user, test_workspace):
        """Test úspešného uloženia nového draftu"""
        service = DraftService()
        transactions_data = [
            {
                "type": "expense",
                "original_amount": Decimal("100.00"),
                "original_currency": "EUR",
                "date": "2024-01-15",
                "note_manual": "Test transaction",
            }
        ]

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            with patch.object(TransactionDraft.objects, "create") as mock_create:
                # Mock delete vráti 0 (žiadny predchádzajúci draft)
                mock_filter.return_value.delete.return_value = (0, {})

                # Mock vytvorenia nového draftu
                mock_draft = Mock(
                    id=1,
                    user=test_user,
                    workspace=test_workspace,
                    draft_type="expense",
                    transactions_data=transactions_data,
                )
                mock_create.return_value = mock_draft

                draft = service.save_draft(
                    test_user, test_workspace.id, "expense", transactions_data
                )

        assert draft.id == 1
        assert draft.draft_type == "expense"
        mock_filter.assert_called_once()
        mock_create.assert_called_once()

    def test_save_draft_success_replace_existing(
        self, test_user, test_workspace, transaction_draft
    ):
        """Test úspešnej výmeny existujúceho draftu"""
        service = DraftService()
        new_transactions_data = [
            {
                "type": "expense",
                "original_amount": Decimal("200.00"),
                "original_currency": "EUR",
                "date": "2024-01-20",
            }
        ]

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            with patch.object(TransactionDraft.objects, "create") as mock_create:
                # Mock delete vráti 1 (odstránený predchádzajúci draft)
                mock_filter.return_value.delete.return_value = (
                    1,
                    {"finance.TransactionDraft": 1},
                )

                mock_draft = Mock(
                    id=2,
                    user=test_user,
                    workspace=test_workspace,
                    draft_type="expense",
                    transactions_data=new_transactions_data,
                )
                mock_create.return_value = mock_draft

                draft = service.save_draft(
                    test_user, test_workspace.id, "expense", new_transactions_data
                )

        assert draft.id == 2
        mock_filter.assert_called_once()

    def test_save_draft_permission_denied(self, test_user, test_user2, test_workspace):
        """Test uloženia draftu bez prístupu k workspace"""
        service = DraftService()
        transactions_data = [{"type": "expense", "original_amount": 100}]

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_workspace = Mock()
            mock_workspace.members.filter.return_value.exists.return_value = False
            mock_get.return_value = mock_workspace

            with pytest.raises(PermissionDenied) as exc_info:
                service.save_draft(
                    test_user2, test_workspace.id, "expense", transactions_data
                )

        assert "don't have access" in str(exc_info.value)

    def test_save_draft_validation_error_invalid_type(self, test_user, test_workspace):
        """Test uloženia draftu s neplatným typom"""
        service = DraftService()
        transactions_data = [{"type": "invalid_type", "original_amount": 100}]

        with pytest.raises(ValidationError) as exc_info:
            service.save_draft(
                test_user, test_workspace.id, "expense", transactions_data
            )

        assert "has invalid type" in str(exc_info.value)

    def test_save_draft_validation_error_type_mismatch(self, test_user, test_workspace):
        """Test uloženia draftu s nezhodujúcim sa typom transakcie"""
        service = DraftService()
        transactions_data = [
            {
                "type": "income",  # Mismatch s draft_type='expense'
                "original_amount": 100,
            }
        ]

        with pytest.raises(ValidationError) as exc_info:
            service.save_draft(
                test_user, test_workspace.id, "expense", transactions_data
            )

        assert "doesn't match draft type" in str(exc_info.value)

    def test_save_draft_validation_error_invalid_amount(
        self, test_user, test_workspace
    ):
        """Test uloženia draftu s neplatnou sumou"""
        service = DraftService()
        transactions_data = [
            {"type": "expense", "original_amount": -100}  # Záporná suma
        ]

        with pytest.raises(ValidationError) as exc_info:
            service.save_draft(
                test_user, test_workspace.id, "expense", transactions_data
            )

        assert "Invalid amount" in str(exc_info.value)

    def test_save_draft_database_error(self, test_user, test_workspace):
        """Test uloženia draftu s databázovou chybou pri vytváraní."""
        service = DraftService()
        transactions_data = [
            {"type": "expense", "original_amount": 100, "original_currency": "EUR"}
        ]

        # Patch _get_workspace_with_access to avoid hitting the DB for workspace
        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ):
            # Patch the create method to simulate a DB error during creation
            with patch.object(
                TransactionDraft.objects, "create", side_effect=DatabaseError("Connection failed")
            ):
                with pytest.raises(DatabaseError):
                    service.save_draft(
                        test_user, test_workspace.id, "expense", transactions_data
                    )


class TestDraftServiceGetWorkspaceDraft:
    """Testy pre get_workspace_draft metódu"""

    def test_get_workspace_draft_success(
        self, test_user, test_workspace, transaction_draft
    ):
        """Test úspešného získania draftu"""
        service = DraftService()

        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ):
            with patch.object(
                TransactionDraft.objects, "select_related"
            ) as mock_select_related:
                mock_get = mock_select_related.return_value.get
                mock_get.return_value = transaction_draft

                draft = service.get_workspace_draft(
                    test_user, test_workspace.id, "expense"
                )

                assert draft == transaction_draft
                mock_get.assert_called_once_with(
                    user=test_user, workspace_id=test_workspace.id, draft_type="expense"
                )

    def test_get_workspace_draft_not_found(self, test_user, test_workspace):
        """Test získania neexistujúceho draftu"""
        service = DraftService()

        with patch.object(TransactionDraft.objects, "get") as mock_get:
            from django.core.exceptions import ObjectDoesNotExist

            mock_get.side_effect = TransactionDraft.DoesNotExist()

            draft = service.get_workspace_draft(test_user, test_workspace.id, "expense")
            assert draft is None

    def test_get_workspace_draft_permission_denied(self, test_user, test_workspace):
        """Test získania draftu bez prístupu k workspace"""
        service = DraftService()

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_workspace = Mock()
            mock_workspace.members.filter.return_value.exists.return_value = False
            mock_get.return_value = mock_workspace

            with pytest.raises(PermissionDenied):
                service.get_workspace_draft(test_user, test_workspace.id, "expense")

    def test_get_workspace_draft_general_exception(self, test_user, test_workspace):
        """Test všeobecnej chyby pri získavaní draftu"""
        service = DraftService()
        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ):
            with patch.object(TransactionDraft.objects, "select_related") as mock_select:
                mock_select.side_effect = Exception("Something went wrong")
                with pytest.raises(Exception, match="Something went wrong"):
                    service.get_workspace_draft(test_user, test_workspace.id, "expense")


class TestDraftServiceGetOrCreateDraft:
    """Testy pre get_or_create_draft metódu"""

    def test_get_or_create_draft_existing(
        self, test_user, test_workspace, transaction_draft
    ):
        """Test získania existujúceho draftu"""
        service = DraftService()

        with patch.object(
            TransactionDraft.objects, "get_or_create"
        ) as mock_get_or_create:
            mock_get_or_create.return_value = (transaction_draft, False)

            draft = service.get_or_create_draft(test_user, test_workspace.id, "expense")

        assert draft == transaction_draft
        mock_get_or_create.assert_called_once_with(
            user=test_user,
            workspace_id=test_workspace.id,
            draft_type="expense",
            defaults={"transactions_data": []},
        )

    def test_get_or_create_draft_new(self, test_user, test_workspace):
        """Test vytvorenia nového draftu"""
        service = DraftService()
        new_draft = Mock(
            id=2,
            user=test_user,
            workspace=test_workspace,
            draft_type="expense",
            transactions_data=[],
        )

        with patch.object(
            TransactionDraft.objects, "get_or_create"
        ) as mock_get_or_create:
            mock_get_or_create.return_value = (new_draft, True)

            draft = service.get_or_create_draft(test_user, test_workspace.id, "expense")

        assert draft == new_draft
        assert draft.id == 2

    def test_get_or_create_draft_permission_denied(self, test_user, test_workspace):
        """Test get_or_create bez prístupu k workspace"""
        service = DraftService()

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_workspace = Mock()
            mock_workspace.members.filter.return_value.exists.return_value = False
            mock_get.return_value = mock_workspace

            with pytest.raises(PermissionDenied):
                service.get_or_create_draft(test_user, test_workspace.id, "expense")

    def test_get_or_create_draft_general_exception(self, test_user, test_workspace):
        """Test všeobecnej chyby pri get_or_create_draft"""
        service = DraftService()
        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ):
            with patch.object(
                TransactionDraft.objects, "get_or_create", side_effect=Exception("Unexpected error")
            ):
                with pytest.raises(Exception, match="Unexpected error"):
                    service.get_or_create_draft(test_user, test_workspace.id, "expense")


class TestDraftServiceDiscardDraft:
    """Testy pre discard_draft metódu"""

    def test_discard_draft_success(self, test_user, test_workspace, transaction_draft):
        """Test úspešného zrušenia draftu"""
        service = DraftService()

        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ), patch.object(
            TransactionDraft.objects, "get", return_value=transaction_draft
        ), patch.object(
            transaction_draft, "get_transactions_count", return_value=1
        ), patch.object(
            transaction_draft, "delete"
        ) as mock_delete:
            result = service.discard_draft(test_user, test_workspace.id, "expense")

            assert result is True
            mock_delete.assert_called_once()

    def test_discard_draft_not_found(self, test_user, test_workspace):
        """Test zrušenia neexistujúceho draftu"""
        service = DraftService()

        with patch.object(TransactionDraft.objects, "get") as mock_get:
            mock_get.side_effect = TransactionDraft.DoesNotExist()

            result = service.discard_draft(test_user, test_workspace.id, "expense")

        assert result is False

    def test_discard_draft_permission_denied(self, test_user, test_workspace):
        """Test zrušenia draftu bez prístupu k workspace"""
        service = DraftService()

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_workspace = Mock()
            mock_workspace.members.filter.return_value.exists.return_value = False
            mock_get.return_value = mock_workspace

            with pytest.raises(PermissionDenied):
                service.discard_draft(test_user, test_workspace.id, "expense")

    def test_discard_draft_general_exception(self, test_user, test_workspace):
        """Test všeobecnej chyby pri mazaní draftu"""
        service = DraftService()
        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ):
            with patch.object(
                TransactionDraft.objects, "get", side_effect=Exception("Unexpected error")
            ):
                with pytest.raises(Exception, match="Unexpected error"):
                    service.discard_draft(test_user, test_workspace.id, "expense")


class TestDraftServiceCleanupDrafts:
    """Testy pre cleanup_drafts_for_transaction metódu"""

    def test_cleanup_drafts_success(self, test_user, test_workspace, transaction_draft):
        """Test úspešného vyčistenia draftov"""
        service = DraftService()

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_filter.return_value.delete.return_value = (
                1,
                {"finance.TransactionDraft": 1},
            )

            deleted_count = service.cleanup_drafts_for_transaction(
                test_user, test_workspace.id, "expense"
            )

        assert deleted_count == 1
        mock_filter.assert_called_once_with(
            user=test_user, workspace=test_workspace, draft_type="expense"
        )

    def test_cleanup_drafts_none_found(self, test_user, test_workspace):
        """Test vyčistenia keď žiadne drafty neexistujú"""
        service = DraftService()

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_filter.return_value.delete.return_value = (0, {})

            deleted_count = service.cleanup_drafts_for_transaction(
                test_user, test_workspace.id, "expense"
            )

        assert deleted_count == 0

    def test_cleanup_drafts_permission_denied(self, test_user, test_workspace):
        """Test vyčistenia draftov bez prístupu k workspace"""
        service = DraftService()

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_workspace = Mock()
            mock_workspace.members.filter.return_value.exists.return_value = False
            mock_get.return_value = mock_workspace

            with pytest.raises(PermissionDenied):
                service.cleanup_drafts_for_transaction(
                    test_user, test_workspace.id, "expense"
                )

    def test_cleanup_drafts_general_exception(self, test_user, test_workspace):
        """Test všeobecnej chyby pri čistení draftov"""
        service = DraftService()
        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ):
            with patch.object(
                TransactionDraft.objects, "filter", side_effect=Exception("Unexpected error")
            ):
                with pytest.raises(Exception, match="Unexpected error"):
                    service.cleanup_drafts_for_transaction(
                        test_user, test_workspace.id, "expense"
                    )


class TestDraftServiceGetUserDraftsSummary:
    """Testy pre get_user_drafts_summary metódu"""

    def test_get_user_drafts_summary_success(
        self, test_user, test_workspace, transaction_draft
    ):
        """Test úspešného získania sumárie draftov"""
        service = DraftService()

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            # Create a mock that can be iterated and has a count() method
            mock_queryset = MagicMock()
            mock_draft = Mock(
                id=1,
                user=test_user,
                workspace=test_workspace,
                draft_type="expense",
                last_modified="2024-01-15",
            )
            mock_draft.workspace.id = test_workspace.id
            mock_draft.workspace.name = "Test Workspace"
            
            # Make the mock iterable
            mock_queryset.__iter__.return_value = [mock_draft]
            mock_queryset.count.return_value = 1

            mock_filter.return_value.select_related.return_value.order_by.return_value = mock_queryset

            summary = service.get_user_drafts_summary(test_user)

        assert summary["total_drafts"] == 1
        assert summary["by_type"]["expense"] == 1
        assert test_workspace.id in summary["workspaces"]
        assert (
            summary["workspaces"][test_workspace.id]["workspace_name"]
            == "Test Workspace"
        )

    def test_get_user_drafts_summary_empty(self, test_user):
        """Test získania sumárie pre používateľa bez draftov"""
        service = DraftService()

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_queryset = MagicMock()
            mock_queryset.__iter__.return_value = []
            mock_queryset.count.return_value = 0
            mock_filter.return_value.select_related.return_value.order_by.return_value = mock_queryset

            summary = service.get_user_drafts_summary(test_user)

        assert summary["total_drafts"] == 0
        assert summary["by_type"]["income"] == 0
        assert summary["by_type"]["expense"] == 0
        assert summary["workspaces"] == {}

    def test_get_user_drafts_summary_multiple_workspaces(
        self, test_user
    ):
        """Test sumárie s viacerými workspace a typmi"""
        service = DraftService()

        # Mock workspaces
        mock_workspace1 = Mock(id=1, name="Workspace 1")
        mock_workspace2 = Mock(id=2, name="Workspace 2")

        # Mock rôzne drafty
        mock_draft1 = Mock(
            id=1,
            user=test_user,
            workspace=mock_workspace1,
            draft_type="expense",
            last_modified="2024-01-15",
        )
        mock_draft2 = Mock(
            id=2,
            user=test_user,
            workspace=mock_workspace1,
            draft_type="income",
            last_modified="2024-01-16",
        )
        mock_draft3 = Mock(
            id=3,
            user=test_user,
            workspace=mock_workspace2,
            draft_type="expense",
            last_modified="2024-01-17",
        )

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_queryset = MagicMock()
            mock_queryset.__iter__.return_value = [mock_draft3, mock_draft2, mock_draft1] # Order by last_modified desc
            mock_queryset.count.return_value = 3
            mock_filter.return_value.select_related.return_value.order_by.return_value = mock_queryset

            summary = service.get_user_drafts_summary(test_user)

        assert summary["total_drafts"] == 3
        assert summary["by_type"]["expense"] == 2
        assert summary["by_type"]["income"] == 1
        assert summary["workspaces"][1]["draft_count"] == 2
        assert summary["workspaces"][2]["draft_count"] == 1
        assert "expense" in summary["workspaces"][1]["types"]
        assert "income" in summary["workspaces"][1]["types"]
        assert "expense" in summary["workspaces"][2]["types"]

    def test_get_user_drafts_summary_exception_handling(self, test_user):
        """Test handlingu výnimiek pri získavaní sumárie"""
        service = DraftService()

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_filter.side_effect = Exception("Database error")

            with pytest.raises(Exception, match="Database error"):
                service.get_user_drafts_summary(test_user)


class TestDraftServiceValidation:
    """Testy pre validačné metódy"""

    def test_validate_draft_data_success(self, test_user, test_workspace):
        """Test úspešnej validácie dát draftu"""
        service = DraftService()
        transactions_data = [
            {
                "type": "expense",
                "original_amount": 100.50,
                "original_currency": "EUR",
                "date": "2024-01-15",
            }
        ]

        # Malo by prejsť bez výnimky
        service._validate_draft_data(transactions_data, "expense")

    def test_validate_draft_data_invalid_draft_type(self):
        """Test validácie s neplatným typom draftu"""
        service = DraftService()
        transactions_data = [{"type": "expense", "original_amount": 100}]

        with pytest.raises(ValidationError) as exc_info:
            service._validate_draft_data(transactions_data, "invalid_type")

        assert "Invalid draft type" in str(exc_info.value)

    def test_validate_draft_data_not_list(self):
        """Test validácie s dátami ktoré nie sú list"""
        service = DraftService()

        with pytest.raises(ValidationError) as exc_info:
            service._validate_draft_data("not_a_list", "expense")

        assert "must be a list" in str(exc_info.value)

    def test_validate_draft_data_invalid_transaction_object(self):
        """Test validácie s neplatným objektom transakcie"""
        service = DraftService()
        transactions_data = ["not_a_dict"]  # Nie je dict

        with pytest.raises(ValidationError) as exc_info:
            service._validate_draft_data(transactions_data, "expense")

        assert "must be an object" in str(exc_info.value)

    def test_validate_draft_data_missing_type(self):
        """Test validácie transakcie bez typu"""
        service = DraftService()
        transactions_data = [{"original_amount": 100}]  # Chýba type

        with pytest.raises(ValidationError) as exc_info:
            service._validate_draft_data(transactions_data, "expense")

        assert "must have a type" in str(exc_info.value)

    def test_validate_draft_data_invalid_transaction_type(self):
        """Test validácie s neplatným typom transakcie"""
        service = DraftService()
        transactions_data = [{"type": "invalid_tx_type", "original_amount": 100}]

        with pytest.raises(ValidationError) as exc_info:
            service._validate_draft_data(transactions_data, "expense")

        assert "invalid type" in str(exc_info.value)

    def test_validate_draft_data_invalid_amount_format(self):
        """Test validácie s neplatným formátom sumy"""
        service = DraftService()
        transactions_data = [{"type": "expense", "original_amount": "not_a_number"}]

        with pytest.raises(ValidationError) as exc_info:
            service._validate_draft_data(transactions_data, "expense")

        assert "Invalid amount format" in str(exc_info.value)


class TestDraftServiceIntegration:
    """Integračné testy pre DraftService"""

    def test_complete_draft_workflow(self, test_user, test_workspace):
        """Test kompletného workflow s draftmi"""
        service = DraftService()

        # 1. Uloženie draftu
        transactions_data = [
            {
                "type": "expense",
                "original_amount": Decimal("150.00"),
                "original_currency": "EUR",
                "date": "2024-01-15",
                "note_manual": "Integration test",
            }
        ]

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_filter.return_value.delete.return_value = (0, {})
            with patch.object(TransactionDraft.objects, "create") as mock_create:
                mock_draft = Mock(
                    id=1,
                    user=test_user,
                    workspace=test_workspace,
                    draft_type="expense",
                    transactions_data=transactions_data,
                )
                mock_create.return_value = mock_draft

                saved_draft = service.save_draft(
                    test_user, test_workspace.id, "expense", transactions_data
                )

        assert saved_draft.id == 1

        # 2. Získanie draftu
        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ), patch.object(
            TransactionDraft.objects, "select_related"
        ) as mock_select_related:
            mock_select_related.return_value.get.return_value = mock_draft
            retrieved_draft = service.get_workspace_draft(
                test_user, test_workspace.id, "expense"
            )

        assert retrieved_draft.id == 1

        # 3. Zrušenie draftu
        with patch.object(
            service, "_get_workspace_with_access", return_value=test_workspace
        ), patch.object(
            TransactionDraft.objects, "get", return_value=mock_draft
        ), patch.object(
            mock_draft, "delete"
        ) as mock_delete:
            discard_result = service.discard_draft(
                test_user, test_workspace.id, "expense"
            )

            assert discard_result is True
            mock_delete.assert_called_once()

    def test_draft_lifecycle_multiple_types(self, test_user, test_workspace):
        """Test lifecycle draftov s viacerými typmi"""
        service = DraftService()

        # Expense draft
        expense_data = [{"type": "expense", "original_amount": 100}]
        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_filter.return_value.delete.return_value = (0, {})
            with patch.object(TransactionDraft.objects, "create") as mock_create:
                mock_expense_draft = Mock(id=1, draft_type="expense")
                mock_create.return_value = mock_expense_draft

                expense_draft = service.save_draft(
                    test_user, test_workspace.id, "expense", expense_data
                )

        assert expense_draft.draft_type == "expense"

        # Income draft
        income_data = [{"type": "income", "original_amount": 500}]
        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_filter.return_value.delete.return_value = (0, {})
            with patch.object(TransactionDraft.objects, "create") as mock_create:
                mock_income_draft = Mock(id=2, draft_type="income")
                mock_create.return_value = mock_income_draft

                income_draft = service.save_draft(
                    test_user, test_workspace.id, "income", income_data
                )

        assert income_draft.draft_type == "income"

        # Sumária
        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_queryset = MagicMock()
            mock_queryset.__iter__.return_value = [mock_expense_draft, mock_income_draft]
            mock_queryset.count.return_value = 2
            mock_filter.return_value.select_related.return_value.order_by.return_value = mock_queryset


            summary = service.get_user_drafts_summary(test_user)

        assert summary["total_drafts"] == 2
        assert summary["by_type"]["expense"] == 1
        assert summary["by_type"]["income"] == 1


class TestDraftServiceEdgeCases:
    """Testy pre edge cases"""

    def test_save_draft_empty_transactions(self, test_user, test_workspace):
        """Test uloženia draftu s prázdnym zoznamom transakcií"""
        service = DraftService()
        empty_transactions = []

        with patch.object(TransactionDraft.objects, "filter") as mock_filter:
            mock_filter.return_value.delete.return_value = (0, {})
            with patch.object(TransactionDraft.objects, "create") as mock_create:
                mock_draft = Mock(id=1, transactions_data=[])
                mock_create.return_value = mock_draft

                draft = service.save_draft(
                    test_user, test_workspace.id, "expense", empty_transactions
                )

        assert draft.id == 1

    def test_get_workspace_with_access_success(self, test_user, test_workspace):
        """Test získania workspace s prístupom"""
        service = DraftService()

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_workspace = Mock()
            mock_workspace.members.filter.return_value.exists.return_value = True
            mock_get.return_value = mock_workspace

            workspace = service._get_workspace_with_access(test_user, test_workspace.id)

        assert workspace == mock_workspace

    def test_get_workspace_with_access_not_found(self, test_user):
        """Test získania neexistujúceho workspace"""
        service = DraftService()

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_get.side_effect = Workspace.DoesNotExist()

            with pytest.raises(PermissionDenied):
                service._get_workspace_with_access(test_user, 999)

    def test_get_workspace_with_access_no_permission(self, test_user, test_workspace):
        """Test získania workspace bez oprávnenia"""
        service = DraftService()

        with patch.object(Workspace.objects, "get") as mock_get:
            mock_workspace = Mock()
            mock_workspace.members.filter.return_value.exists.return_value = False
            mock_get.return_value = mock_workspace

            with pytest.raises(PermissionDenied):
                service._get_workspace_with_access(test_user, test_workspace.id)
