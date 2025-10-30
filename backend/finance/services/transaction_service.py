"""
Service for transaction operations with proper error handling and logging.

This module provides the TransactionService class for handling bulk transaction
operations with atomicity guarantees and comprehensive error handling.
"""

import logging
from django.db import transaction as db_transaction
from django.core.exceptions import ObjectDoesNotExist, ValidationError

from ..models import Transaction, ExpenseCategory, IncomeCategory
from ..utils.currency_utils import recalculate_transactions_domestic_amount, CurrencyConversionError

# Get structured logger for this module
logger = logging.getLogger(__name__)


class TransactionService:
    """
    Service for handling transaction operations with transaction safety.
    
    Provides atomic bulk operations for creating, updating, and deleting
    transactions with proper currency conversion and data validation.
    """
    
    @staticmethod
    @db_transaction.atomic
    def bulk_create_transactions(transactions_data, workspace, user):
        """
        Atomically create multiple transactions with currency conversion.
        
        Creates transactions in bulk with proper category resolution and
        automatic domestic amount calculation based on workspace currency.
        
        Args:
            transactions_data: List of transaction dictionaries
            workspace: Workspace instance
            user: User instance
            
        Returns:
            list: Created transaction instances with updated domestic amounts
            
        Raises:
            ValidationError: If data validation fails
            CurrencyConversionError: If currency conversion fails
            Exception: If any operation fails, rolls back entire transaction
            
        Example:
            >>> transactions = TransactionService.bulk_create_transactions(
            ...     [{'type': 'expense', 'original_amount': 100, ...}],
            ...     workspace, user
            ... )
        """
        logger.info(
            "Bulk creating transactions",
            extra={
                "user_id": user.id,
                "workspace_id": workspace.id,
                "transaction_count": len(transactions_data),
                "action": "bulk_create_start",
                "component": "TransactionService",
            },
        )
        
        transactions = []
        validation_errors = []
        
        # Pre-validate all transactions before creation
        for i, data in enumerate(transactions_data):
            try:
                TransactionService._validate_transaction_data(data, workspace)
            except ValidationError as e:
                validation_errors.append(f"Transaction {i}: {str(e)}")
        
        if validation_errors:
            logger.error(
                "Transaction validation failed",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace.id,
                    "error_count": len(validation_errors),
                    "errors": validation_errors,
                    "action": "bulk_create_validation_failed",
                    "component": "TransactionService",
                    "severity": "high",
                },
            )
            raise ValidationError("; ".join(validation_errors))
        
        # Process and create transactions
        for data in transactions_data:
            expense_category = None
            income_category = None
            
            # Resolve expense category
            if data.get('expense_category'):
                try:
                    expense_category = ExpenseCategory.objects.get(
                        id=data['expense_category'], 
                        version__workspace=workspace
                    )
                    logger.debug(
                        "Expense category resolved",
                        extra={
                            "category_id": data['expense_category'],
                            "category_name": expense_category.name,
                            "action": "category_resolved",
                            "component": "TransactionService",
                        },
                    )
                except ExpenseCategory.DoesNotExist:
                    logger.warning(
                        "Expense category not found during transaction creation",
                        extra={
                            "category_id": data['expense_category'],
                            "workspace_id": workspace.id,
                            "action": "category_not_found",
                            "component": "TransactionService",
                            "severity": "medium",
                        },
                    )
                    
            # Resolve income category  
            if data.get('income_category'):
                try:
                    income_category = IncomeCategory.objects.get(
                        id=data['income_category'],
                        version__workspace=workspace  
                    )
                    logger.debug(
                        "Income category resolved",
                        extra={
                            "category_id": data['income_category'],
                            "category_name": income_category.name,
                            "action": "category_resolved",
                            "component": "TransactionService",
                        },
                    )
                except IncomeCategory.DoesNotExist:
                    logger.warning(
                        "Income category not found during transaction creation",
                        extra={
                            "category_id": data['income_category'],
                            "workspace_id": workspace.id,
                            "action": "category_not_found", 
                            "component": "TransactionService",
                            "severity": "medium",
                        },
                    )
            
            transaction = Transaction(
                user=user,
                workspace=workspace,
                type=data['type'],
                original_amount=data['original_amount'],
                original_currency=data['original_currency'],
                date=data['date'],
                expense_category=expense_category,
                income_category=income_category,
                tags=data.get('tags', []),
                note_manual=data.get('note_manual', ''),
                note_auto=data.get('note_auto', ''),
                amount_domestic=data.get('original_amount')  # Temporary value
            )
            transactions.append(transaction)
        
        # Create transactions with temporary domestic amount
        Transaction.objects.bulk_create(transactions)
        
        # Recalculate and update domestic amounts with proper currency conversion
        try:
            transactions = recalculate_transactions_domestic_amount(transactions, workspace)
            Transaction.objects.bulk_update(transactions, ['amount_domestic'])
        except CurrencyConversionError as e:
            logger.error(
                "Currency conversion failed during bulk create",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace.id,
                    "error_message": str(e),
                    "action": "currency_conversion_failed",
                    "component": "TransactionService",
                    "severity": "high",
                },
            )
            # Transaction will roll back due to @db_transaction.atomic
            raise
        
        logger.info(
            "Bulk transaction creation completed successfully",
            extra={
                "user_id": user.id,
                "workspace_id": workspace.id,
                "created_count": len(transactions),
                "action": "bulk_create_success",
                "component": "TransactionService",
            },
        )
        
        return transactions
    
    @staticmethod
    @db_transaction.atomic
    def bulk_sync_transactions(transactions_data, workspace, user):
        """
        Universal atomic bulk sync: CREATE, UPDATE, DELETE in single transaction.
        
        Performs atomic bulk create, update, and delete operations on transactions
        within a single database transaction to ensure data consistency.
        
        Args:
            transactions_data: Dictionary with 'create', 'update', 'delete' keys
            workspace: Workspace instance
            user: User instance
            
        Returns:
            dict: Results of sync operation with created, updated, deleted counts
            
        Raises:
            ValidationError: If data validation fails
            CurrencyConversionError: If currency conversion fails
            Exception: If any operation fails, rolls back entire transaction
            
        Example:
            >>> results = TransactionService.bulk_sync_transactions(
            ...     {
            ...         'create': [...],
            ...         'update': [...], 
            ...         'delete': [...]
            ...     },
            ...     workspace, user
            ... )
        """
        logger.info(
            "Starting bulk transaction sync",
            extra={
                "user_id": user.id,
                "workspace_id": workspace.id,
                "create_count": len(transactions_data.get('create', [])),
                "update_count": len(transactions_data.get('update', [])),
                "delete_count": len(transactions_data.get('delete', [])),
                "action": "bulk_sync_start",
                "component": "TransactionService",
            },
        )
        
        results = {
            'created': [],
            'updated': [],
            'deleted': [],
            'errors': []
        }
        
        # 1. DELETE operations
        if transactions_data.get('delete'):
            logger.debug(
                "Processing transaction deletions",
                extra={
                    "delete_count": len(transactions_data['delete']),
                    "action": "bulk_delete_start",
                    "component": "TransactionService",
                },
            )
            
            # Verify transactions exist and belong to user/workspace
            existing_transactions = Transaction.objects.filter(
                id__in=transactions_data['delete'],
                workspace=workspace,
                user=user
            )
            
            existing_ids = list(existing_transactions.values_list('id', flat=True))
            invalid_ids = set(transactions_data['delete']) - set(existing_ids)
            
            if invalid_ids:
                logger.warning(
                    "Invalid transaction IDs for deletion",
                    extra={
                        "invalid_ids": list(invalid_ids),
                        "valid_ids": existing_ids,
                        "action": "bulk_delete_validation_warning",
                        "component": "TransactionService",
                        "severity": "medium",
                    },
                )
                results['errors'].extend([f"Invalid delete ID: {id}" for id in invalid_ids])
            
            # Perform deletion on valid transactions only
            deleted_count, deletion_details = existing_transactions.delete()
            results['deleted'] = existing_ids
            
            logger.debug(
                "Delete operations completed",
                extra={
                    "deleted_count": deleted_count,
                    "deleted_ids": existing_ids,
                    "action": "bulk_delete_completed",
                    "component": "TransactionService",
                },
            )
        
        # 2. CREATE operations
        if transactions_data.get('create'):
            try:
                new_transactions = TransactionService.bulk_create_transactions(
                    transactions_data['create'], workspace, user
                )
                results['created'] = [t.id for t in new_transactions]
            except (ValidationError, CurrencyConversionError) as e:
                logger.error(
                    "Bulk create failed during sync",
                    extra={
                        "user_id": user.id,
                        "workspace_id": workspace.id,
                        "error_message": str(e),
                        "action": "bulk_create_failed_during_sync",
                        "component": "TransactionService",
                        "severity": "high",
                    },
                )
                results['errors'].append(f"Create failed: {str(e)}")
        
        # 3. UPDATE operations
        if transactions_data.get('update'):
            logger.debug(
                "Processing transaction updates",
                extra={
                    "update_count": len(transactions_data['update']),
                    "action": "bulk_update_start",
                    "component": "TransactionService",
                },
            )
            
            updates = []
            update_errors = []
            
            for data in transactions_data['update']:
                try:
                    transaction = Transaction.objects.get(
                        id=data['id'],
                        workspace=workspace,
                        user=user
                    )
                    
                    # Validate update data
                    TransactionService._validate_transaction_data(data, workspace, is_update=True)
                    
                    # Update fields
                    transaction.type = data.get('type', transaction.type)
                    transaction.original_amount = data.get('original_amount', transaction.original_amount)
                    transaction.original_currency = data.get('original_currency', transaction.original_currency)
                    transaction.date = data.get('date', transaction.date)
                    
                    # Update categories
                    if 'expense_category' in data:
                        if data['expense_category']:
                            transaction.expense_category = ExpenseCategory.objects.get(
                                id=data['expense_category'],
                                version__workspace=workspace
                            )
                        else:
                            transaction.expense_category = None
                    
                    if 'income_category' in data:
                        if data['income_category']:
                            transaction.income_category = IncomeCategory.objects.get(
                                id=data['income_category'],
                                version__workspace=workspace
                            )
                        else:
                            transaction.income_category = None
                    
                    updates.append(transaction)
                    
                except (Transaction.DoesNotExist, ExpenseCategory.DoesNotExist, IncomeCategory.DoesNotExist) as e:
                    logger.warning(
                        "Transaction or category not found during update",
                        extra={
                            "transaction_id": data.get('id'),
                            "error_type": type(e).__name__,
                            "action": "update_skip_not_found",
                            "component": "TransactionService",
                            "severity": "medium",
                        },
                    )
                    update_errors.append(f"Transaction {data.get('id')} not found")
                    continue
                except ValidationError as e:
                    update_errors.append(f"Transaction {data.get('id')}: {str(e)}")
                    continue
            
            if updates:
                try:
                    # Recalculate domestic amounts for updated transactions
                    updates = recalculate_transactions_domestic_amount(updates, workspace)
                    Transaction.objects.bulk_update(updates, [
                        'type', 'original_amount', 'original_currency', 'date',
                        'expense_category', 'income_category', 'amount_domestic'
                    ])
                    results['updated'] = [t.id for t in updates]
                except CurrencyConversionError as e:
                    logger.error(
                        "Currency conversion failed during update",
                        extra={
                            "user_id": user.id,
                            "workspace_id": workspace.id,
                            "error_message": str(e),
                            "action": "currency_conversion_failed_during_update",
                            "component": "TransactionService",
                            "severity": "high",
                        },
                    )
                    update_errors.append(f"Currency conversion failed: {str(e)}")
            
            if update_errors:
                results['errors'].extend(update_errors)
            
            logger.debug(
                "Update operations completed",
                extra={
                    "updated_count": len(results['updated']),
                    "update_errors": len(update_errors),
                    "action": "bulk_update_completed",
                    "component": "TransactionService",
                },
            )
        
        logger.info(
            "Bulk transaction sync completed",
            extra={
                "user_id": user.id,
                "workspace_id": workspace.id,
                "results": {k: v for k, v in results.items() if k != 'errors' or v},
                "error_count": len(results['errors']),
                "action": "bulk_sync_completed",
                "component": "TransactionService",
            },
        )
        
        return results
    
    @staticmethod
    @db_transaction.atomic  
    def recalculate_all_transactions_for_workspace(workspace):
        """
        Recalculate domestic amounts for all transactions in workspace.
        
        Used when workspace currency changes or exchange rates are updated.
        Ensures all transaction amounts are consistent with current currency settings.
        
        Args:
            workspace: Workspace instance
            
        Returns:
            int: Number of successfully updated transactions
            
        Raises:
            CurrencyConversionError: If currency conversion fails for any transaction
            Exception: If recalculation fails, rolls back entire transaction
            
        Example:
            >>> updated_count = TransactionService.recalculate_all_transactions_for_workspace(workspace)
        """
        logger.info(
            "Recalculating all transactions for workspace",
            extra={
                "workspace_id": workspace.id,
                "domestic_currency": workspace.settings.domestic_currency,
                "action": "recalculation_start",
                "component": "TransactionService",
            },
        )
        
        transactions = Transaction.objects.filter(workspace=workspace)
        transactions_list = list(transactions)
        
        if not transactions_list:
            logger.debug(
                "No transactions to recalculate",
                extra={
                    "workspace_id": workspace.id,
                    "action": "recalculation_skip_empty",
                    "component": "TransactionService",
                },
            )
            return 0
        
        try:
            updated_transactions = recalculate_transactions_domestic_amount(
                transactions_list, 
                workspace
            )
            
            Transaction.objects.bulk_update(
                updated_transactions,
                ['amount_domestic']
            )
            
            updated_count = len(updated_transactions)
            
            logger.info(
                "Transaction recalculation completed successfully",
                extra={
                    "workspace_id": workspace.id,
                    "transactions_updated": updated_count,
                    "domestic_currency": workspace.settings.domestic_currency,
                    "action": "recalculation_success",
                    "component": "TransactionService",
                },
            )
            
            return updated_count
            
        except CurrencyConversionError as e:
            logger.error(
                "Currency conversion failed during workspace recalculation",
                extra={
                    "workspace_id": workspace.id,
                    "error_message": str(e),
                    "action": "recalculation_currency_conversion_failed",
                    "component": "TransactionService",
                    "severity": "critical",
                },
            )
            # Transaction will roll back due to @db_transaction.atomic
            raise
    
    @staticmethod
    def _validate_transaction_data(data, workspace, is_update=False):
        """
        Validate transaction data before creation or update.
        
        Args:
            data: Transaction data dictionary
            workspace: Workspace instance for context
            is_update: Whether this is for an update operation
            
        Raises:
            ValidationError: If data validation fails
        """
        # Required fields validation
        if not is_update:
            required_fields = ['type', 'original_amount', 'original_currency', 'date']
            for field in required_fields:
                if field not in data or data[field] is None:
                    raise ValidationError(f"Missing required field: {field}")
        
        # Type validation
        if 'type' in data and data['type'] not in ['income', 'expense']:
            raise ValidationError("Type must be 'income' or 'expense'")
        
        # Amount validation
        if 'original_amount' in data:
            try:
                amount = float(data['original_amount'])
                if amount <= 0:
                    raise ValidationError("Amount must be positive")
            except (ValueError, TypeError):
                raise ValidationError("Amount must be a valid number")
        
        # Currency validation
        valid_currencies = ['EUR', 'USD', 'GBP', 'CHF', 'PLN', 'CZK']
        if 'original_currency' in data and data['original_currency'] not in valid_currencies:
            raise ValidationError(f"Currency must be one of: {', '.join(valid_currencies)}")
        
        # Category consistency validation
        if data.get('expense_category') and data.get('income_category'):
            raise ValidationError("Transaction cannot have both expense and income categories")
        
        if data.get('type') == 'expense' and data.get('income_category'):
            raise ValidationError("Expense transaction cannot have income category")
        
        if data.get('type') == 'income' and data.get('expense_category'):
            raise ValidationError("Income transaction cannot have expense category")