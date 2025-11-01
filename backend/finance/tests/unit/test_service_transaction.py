# finance/tests/unit/test_service_transaction.py
import pytest
from decimal import Decimal
from unittest.mock import Mock, patch
from datetime import date
from django.core.exceptions import ValidationError
from finance.services.transaction_service import TransactionService


class TestTransactionService:
    """Testy pre TransactionService"""
    
    def test_bulk_create_transactions_success(self, test_user, test_workspace, expense_root_category, workspace_settings):
        """Test úspešného bulk vytvorenia transakcií"""
        transactions_data = [
            {
                'type': 'expense',
                'original_amount': Decimal('100.00'),
                'original_currency': 'EUR',
                'date': date(2024, 1, 15),
                'expense_category': expense_root_category.id,
                'tags': ['potraviny', 'nakup'],
                'note_manual': 'Test transakcia 1'
            },
            {
                'type': 'income',
                'original_amount': Decimal('2000.00'),
                'original_currency': 'EUR', 
                'date': date(2024, 1, 20),
                'income_category': None,  # Môže byť None
                'tags': ['plat'],
                'note_manual': 'Test transakcia 2'
            }
        ]
        
        transactions = TransactionService.bulk_create_transactions(
            transactions_data, test_workspace, test_user
        )
        
        assert len(transactions) == 2
        assert transactions[0].user == test_user
        assert transactions[0].workspace == test_workspace
        assert transactions[0].type == 'expense'
        assert transactions[0].original_amount == Decimal('100.00')
        assert transactions[0].expense_category == expense_root_category
        assert 'potraviny' in transactions[0].tags
    
    def test_bulk_create_transactions_validation_error(self, test_user, test_workspace):
        """Test bulk vytvorenia s validačnou chybou"""
        transactions_data = [
            {
                'type': 'expense',
                'original_amount': Decimal('-100.00'),  # Záporná suma
                'original_currency': 'EUR',
                'date': date(2024, 1, 15)
            }
        ]
        
        with pytest.raises(ValidationError) as exc_info:
            TransactionService.bulk_create_transactions(
                transactions_data, test_workspace, test_user
            )
        
        assert 'Amount must be positive' in str(exc_info.value)
    
    def test_bulk_create_transactions_invalid_currency(self, test_user, test_workspace, expense_root_category):
        """Test bulk vytvorenia s neplatnou menou"""
        transactions_data = [
            {
                'type': 'expense',
                'original_amount': Decimal('100.00'),
                'original_currency': 'INVALID',  # Neplatná mena
                'date': date(2024, 1, 15),
                'expense_category': expense_root_category.id
            }
        ]
        
        with pytest.raises(ValidationError) as exc_info:
            TransactionService.bulk_create_transactions(
                transactions_data, test_workspace, test_user
            )
        
        assert 'Currency must be one of' in str(exc_info.value)
    
    def test_bulk_create_transactions_category_consistency(self, test_user, test_workspace, expense_root_category, income_root_category):
        """Test konzistencie kategórií"""
        transactions_data = [
            {
                'type': 'expense',
                'original_amount': Decimal('100.00'),
                'original_currency': 'EUR',
                'date': date(2024, 1, 15),
                'expense_category': expense_root_category.id,
                'income_category': income_root_category.id  # Obe kategórie - chyba
            }
        ]
        
        with pytest.raises(ValidationError) as exc_info:
            TransactionService.bulk_create_transactions(
                transactions_data, test_workspace, test_user
            )
        
        assert 'cannot have both' in str(exc_info.value)
    
    def test_bulk_sync_transactions_complete_flow(self, test_user, test_workspace, expense_root_category, workspace_settings):
        """Test kompletného bulk sync flow"""
        from finance.models import Transaction
        
        # Najprv vytvoríme nejaké transakcie
        existing_transactions = TransactionService.bulk_create_transactions(
            [
                {
                    'type': 'expense',
                    'original_amount': Decimal('100.00'),
                    'original_currency': 'EUR',
                    'date': date(2024, 1, 15),
                    'expense_category': expense_root_category.id
                },
                {
                    'type': 'income',
                    'original_amount': Decimal('2000.00'),
                    'original_currency': 'EUR',
                    'date': date(2024, 1, 20)
                }
            ],
            test_workspace, test_user
        )
        
        transaction_to_update = existing_transactions[0]
        transaction_to_delete = existing_transactions[1]
        
        # Bulk sync operácie
        sync_data = {
            'create': [
                {
                    'type': 'expense',
                    'original_amount': Decimal('50.00'),
                    'original_currency': 'EUR',
                    'date': date(2024, 1, 25),
                    'expense_category': expense_root_category.id
                }
            ],
            'update': [
                {
                    'id': transaction_to_update.id,
                    'original_amount': Decimal('150.00'),  # Zmenená suma
                    'original_currency': 'EUR',
                    'date': date(2024, 1, 15),
                    'expense_category': expense_root_category.id
                }
            ],
            'delete': [transaction_to_delete.id]
        }
        
        results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )
        
        assert len(results['created']) == 1
        assert len(results['updated']) == 1
        assert len(results['deleted']) == 1
        assert results['errors'] == []
        
        # Over že zmeny sú skutočné
        updated_transaction = Transaction.objects.get(id=transaction_to_update.id)
        assert updated_transaction.original_amount == Decimal('150.00')
        
        # Over že transakcia bola vymazaná
        assert not Transaction.objects.filter(id=transaction_to_delete.id).exists()
        
        # Over že nová transakcia bola vytvorená
        new_transactions = Transaction.objects.filter(
            workspace=test_workspace,
            original_amount=Decimal('50.00')
        )
        assert new_transactions.exists()
    
    def test_bulk_sync_transactions_atomic_rollback(self, test_user, test_workspace, expense_root_category, workspace_settings):
        """Test atomic rollback pri chybe v bulk sync"""
        from finance.models import Transaction
        
        # Vytvoríme pôvodnú transakciu
        original_transaction = TransactionService.bulk_create_transactions(
            [
                {
                    'type': 'expense',
                    'original_amount': Decimal('100.00'),
                    'original_currency': 'EUR',
                    'date': date(2024, 1, 15),
                    'expense_category': expense_root_category.id
                }
            ],
            test_workspace, test_user
        )[0]
        
        original_amount = original_transaction.original_amount
        
        # Sync s chybou - neplatná mena
        sync_data = {
            'update': [
                {
                    'id': original_transaction.id,
                    'original_amount': Decimal('150.00'),
                    'original_currency': 'INVALID',  # Neplatná mena
                    'date': date(2024, 1, 15)
                }
            ]
        }
        
        results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )
        
        # Malo by vrátiť chybu ale transakcia by mala ostať nezmenená
        assert len(results['errors']) > 0
        assert 'Currency must be one of' in results['errors'][0]
        
        # Over že transakcia nebola zmenená (atomic rollback)
        original_transaction.refresh_from_db()
        assert original_transaction.original_amount == original_amount
    
    def test_recalculate_all_transactions_for_workspace(self, test_user, test_workspace, expense_root_category, exchange_rate_usd, workspace_settings):
        """Test prepočtu všetkých transakcií pre workspace"""
        from finance.models import Transaction
        
        # Vytvoríme transakcie s rôznymi menami
        TransactionService.bulk_create_transactions(
            [
                {
                    'type': 'expense',
                    'original_amount': Decimal('100.00'),
                    'original_currency': 'EUR',
                    'date': exchange_rate_usd.date,
                    'expense_category': expense_root_category.id
                },
                {
                    'type': 'expense',
                    'original_amount': Decimal('100.00'),
                    'original_currency': 'USD',
                    'date': exchange_rate_usd.date,
                    'expense_category': expense_root_category.id
                }
            ],
            test_workspace, test_user
        )
        
        # Prepočítame všetky transakcie
        updated_count = TransactionService.recalculate_all_transactions_for_workspace(test_workspace)
        
        assert updated_count == 2  # Obe transakcie by sa mali prepočítať
        
        # Over že domestic amounts sú nastavené
        transactions = Transaction.objects.filter(workspace=test_workspace)
        for tx in transactions:
            assert tx.amount_domestic is not None
            assert tx.amount_domestic > Decimal('0')
    
    def test_recalculate_empty_workspace(self, test_workspace, workspace_settings):
        """Test prepočtu prázdneho workspace"""
        updated_count = TransactionService.recalculate_all_transactions_for_workspace(test_workspace)
        
        assert updated_count == 0


class TestTransactionServiceValidation:
    """Testy validačných metód TransactionService"""
    
    def test_validate_transaction_data_success(self, test_workspace):
        """Test úspešnej validácie transakčných dát"""
        valid_data = {
            'type': 'expense',
            'original_amount': Decimal('100.00'),
            'original_currency': 'EUR',
            'date': date(2024, 1, 15)
        }
        
        # Malo by prejsť bez výnimky
        TransactionService._validate_transaction_data(valid_data, test_workspace)
    
    def test_validate_transaction_data_missing_required(self, test_workspace):
        """Test validácie s chýbajúcimi povinnými poliami"""
        invalid_data = {
            'type': 'expense',
            # Chýba original_amount
            'original_currency': 'EUR',
            'date': date(2024, 1, 15)
        }
        
        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)
        
        assert 'Missing required field' in str(exc_info.value)
    
    def test_validate_transaction_data_invalid_type(self, test_workspace):
        """Test validácie s neplatným typom"""
        invalid_data = {
            'type': 'invalid_type',
            'original_amount': Decimal('100.00'),
            'original_currency': 'EUR',
            'date': date(2024, 1, 15)
        }
        
        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)
        
        assert "must be 'income' or 'expense'" in str(exc_info.value)
    
    def test_validate_transaction_data_negative_amount(self, test_workspace):
        """Test validácie so zápornou sumou"""
        invalid_data = {
            'type': 'expense',
            'original_amount': Decimal('-100.00'),
            'original_currency': 'EUR',
            'date': date(2024, 1, 15)
        }
        
        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)
        
        assert 'Amount must be positive' in str(exc_info.value)
    
    def test_validate_transaction_data_invalid_amount_type(self, test_workspace):
        """Test validácie s neplatným typom sumy"""
        invalid_data = {
            'type': 'expense',
            'original_amount': 'not_a_number',  # Neplatný typ
            'original_currency': 'EUR',
            'date': date(2024, 1, 15)
        }
        
        with pytest.raises(ValidationError) as exc_info:
            TransactionService._validate_transaction_data(invalid_data, test_workspace)
        
        assert 'Amount must be a valid number' in str(exc_info.value)


class TestTransactionServiceIntegration:
    """Integračné testy pre TransactionService"""
    
    def test_complete_bulk_operations_flow(self, test_user, test_workspace, expense_root_category, income_root_category, exchange_rate_usd, exchange_rate_gbp, workspace_settings):
        """Test kompletného flow bulk operácií"""
        from finance.models import Transaction
        
        # Krok 1: Bulk create s rôznymi menami
        create_data = [
            {
                'type': 'expense',
                'original_amount': Decimal('100.00'),
                'original_currency': 'EUR',
                'date': exchange_rate_usd.date,
                'expense_category': expense_root_category.id,
                'tags': ['eur', 'test']
            },
            {
                'type': 'expense', 
                'original_amount': Decimal('150.00'),
                'original_currency': 'USD',
                'date': exchange_rate_usd.date,
                'expense_category': expense_root_category.id,
                'tags': ['usd', 'test']
            },
            {
                'type': 'income',
                'original_amount': Decimal('2000.00'),
                'original_currency': 'GBP',
                'date': exchange_rate_gbp.date,
                'income_category': income_root_category.id,
                'tags': ['gbp', 'test']
            }
        ]
        
        created_transactions = TransactionService.bulk_create_transactions(
            create_data, test_workspace, test_user
        )
        
        assert len(created_transactions) == 3
        
        # Krok 2: Bulk sync s update a delete
        transaction_to_update = created_transactions[0]
        transaction_to_delete = created_transactions[1]
        
        sync_data = {
            'update': [
                {
                    'id': transaction_to_update.id,
                    'original_amount': Decimal('200.00'),  # Zdvojnásobená suma
                    'original_currency': 'EUR',
                    'date': exchange_rate_usd.date,
                    'expense_category': expense_root_category.id
                }
            ],
            'delete': [transaction_to_delete.id],
            'create': [
                {
                    'type': 'expense',
                    'original_amount': Decimal('75.00'),
                    'original_currency': 'USD',
                    'date': exchange_rate_usd.date,
                    'expense_category': expense_root_category.id
                }
            ]
        }
        
        sync_results = TransactionService.bulk_sync_transactions(
            sync_data, test_workspace, test_user
        )
        
        assert len(sync_results['created']) == 1
        assert len(sync_results['updated']) == 1
        assert len(sync_results['deleted']) == 1
        assert sync_results['errors'] == []
        
        # Krok 3: Recalculate všetkých transakcií
        updated_count = TransactionService.recalculate_all_transactions_for_workspace(test_workspace)
        
        # Malo by byť 3 transakcie (pôvodné 3 + 1 nová - 1 vymazaná = 3)
        assert updated_count == 3
        
        # Over finálny stav
        final_transactions = Transaction.objects.filter(workspace=test_workspace)
        assert final_transactions.count() == 3
        
        for tx in final_transactions:
            assert tx.amount_domestic is not None
            assert tx.amount_domestic > Decimal('0')
            assert tx.user == test_user
            assert tx.workspace == test_workspace

class TestTransactionServiceMissingCoverage:
    """Minimalistické testy pre nepokryté riadky v transaction_service.py"""

    @pytest.mark.django_db
    def test_bulk_create_validation_error_logging(self):
        """Test riadky 112-113: Logovanie validačnej chyby"""
        with patch('finance.services.transaction_service.logger') as mock_logger:
            with pytest.raises(ValidationError):
                TransactionService.bulk_create_transactions(
                    [{'invalid': 'data'}],  # Neplatné dáta
                    Mock(), Mock()
                )
            
            # Over že sa volal error logger
            mock_logger.error.assert_called_once()

    @pytest.mark.django_db
    def test_bulk_sync_create_failure(self):
        """Test riadky 311-323: Zlyhanie create operácie v sync"""
        with patch('finance.services.transaction_service.logger') as mock_logger:
            with patch('finance.services.transaction_service.TransactionService.bulk_create_transactions',
                      side_effect=ValidationError("Create failed")):
                
                result = TransactionService.bulk_sync_transactions(
                    {
                        'create': [{'invalid': 'data'}]
                    },
                    Mock(), Mock()
                )
                
                # Over error v results
                assert len(result['errors']) > 0
                assert 'Create failed' in result['errors'][0]
                
                # Over error logging
                mock_logger.error.assert_called_once()

