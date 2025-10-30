"""
Service for atomic currency change operations with transaction safety.

This module provides the CurrencyService class for handling workspace currency
changes with full atomicity guarantees and comprehensive error handling.
"""

import logging
from django.db import transaction
from django.core.exceptions import ValidationError

from .transaction_service import TransactionService

# Get structured logger for this module
logger = logging.getLogger(__name__)


class CurrencyService:
    """
    Service for handling workspace currency changes with full transaction safety.
    
    Provides atomic currency change operations that ensure either both the
    currency update and all transaction recalculations succeed, or both
    are rolled back to maintain data consistency.
    """
    
    @staticmethod
    @transaction.atomic
    def change_workspace_currency(workspace_settings, new_currency):
        """
        Atomically change workspace currency and recalculate all transactions.
        
        This method ensures that either both operations succeed or both are
        rolled back, maintaining financial data consistency across the entire
        workspace.
        
        Args:
            workspace_settings: WorkspaceSettings instance to update
            new_currency: New currency code (e.g., 'USD', 'EUR')
            
        Returns:
            dict: Operation results including:
                - success: Boolean indicating overall success
                - changed: Boolean indicating if currency was actually changed
                - transactions_updated: Number of transactions recalculated
                - old_currency: Previous currency code
                - new_currency: New currency code
                - message: Human-readable result message
                
        Raises:
            ValidationError: If currency is invalid or operation fails
            Exception: Any other error during processing that triggers rollback
            
        Example:
            >>> result = CurrencyService.change_workspace_currency(settings, 'USD')
            >>> print(result['transactions_updated'])  # 150
        """
        old_currency = workspace_settings.domestic_currency
        
        # Validate currency change - skip if no actual change
        if old_currency == new_currency:
            logger.info(
                "Currency change skipped - same currency",
                extra={
                    "workspace_settings_id": workspace_settings.id,
                    "workspace_id": workspace_settings.workspace.id,
                    "currency": old_currency,
                    "action": "currency_change_skipped",
                    "component": "CurrencyService",
                },
            )
            return {
                "success": True,
                "changed": False,
                "message": "Currency unchanged",
                "transactions_updated": 0,
                "old_currency": old_currency,
                "new_currency": new_currency
            }
        
        # Validate new currency against available choices
        valid_currencies = dict(workspace_settings.CURRENCY_CHOICES)
        if new_currency not in valid_currencies:
            logger.error(
                "Invalid currency requested",
                extra={
                    "workspace_settings_id": workspace_settings.id,
                    "workspace_id": workspace_settings.workspace.id,
                    "requested_currency": new_currency,
                    "valid_currencies": list(valid_currencies.keys()),
                    "old_currency": old_currency,
                    "action": "currency_validation_failed",
                    "component": "CurrencyService",
                    "severity": "high",
                },
            )
            raise ValidationError(
                f"Invalid currency: {new_currency}. "
                f"Must be one of: {', '.join(valid_currencies.keys())}"
            )
        
        logger.info(
            "Starting atomic currency change process",
            extra={
                "workspace_settings_id": workspace_settings.id,
                "workspace_id": workspace_settings.workspace.id,
                "old_currency": old_currency,
                "new_currency": new_currency,
                "currency_name": valid_currencies[new_currency],
                "action": "atomic_currency_change_started",
                "component": "CurrencyService",
            },
        )
        
        try:
            # Step 1: Update currency in database
            workspace_settings.domestic_currency = new_currency
            workspace_settings.save(update_fields=['domestic_currency'])
            
            logger.debug(
                "Workspace currency updated in database",
                extra={
                    "workspace_settings_id": workspace_settings.id,
                    "workspace_id": workspace_settings.workspace.id,
                    "action": "currency_update_completed",
                    "component": "CurrencyService",
                },
            )
            
            # Step 2: Recalculate all transactions - THIS MUST SUCCEED
            # If this fails, the entire transaction will roll back
            updated_count = TransactionService.recalculate_all_transactions_for_workspace(
                workspace_settings.workspace
            )
            
            logger.info(
                "Atomic currency change completed successfully",
                extra={
                    "workspace_settings_id": workspace_settings.id,
                    "workspace_id": workspace_settings.workspace.id,
                    "old_currency": old_currency,
                    "new_currency": new_currency,
                    "transactions_updated": updated_count,
                    "action": "atomic_currency_change_completed",
                    "component": "CurrencyService",
                },
            )
            
            return {
                "success": True,
                "changed": True,
                "transactions_updated": updated_count,
                "old_currency": old_currency,
                "new_currency": new_currency,
                "message": f"Currency changed from {old_currency} to {new_currency}, "
                          f"updated {updated_count} transactions"
            }
            
        except Exception as e:
            logger.error(
                "Atomic currency change failed - transaction will roll back",
                extra={
                    "workspace_settings_id": workspace_settings.id,
                    "workspace_id": workspace_settings.workspace.id,
                    "old_currency": old_currency,
                    "new_currency": new_currency,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "atomic_currency_change_failed",
                    "component": "CurrencyService",
                    "severity": "critical",
                },
                exc_info=True,
            )
            
            # Re-raise to ensure transaction rollback
            # The @transaction.atomic decorator will catch this and roll back
            raise ValidationError(
                f"Currency change failed: {str(e)}. "
                "All changes have been rolled back to maintain data consistency."
            ) from e

    @staticmethod
    def validate_currency_change(workspace_settings, new_currency):
        """
        Validate currency change without performing the actual operation.
        
        Useful for pre-validation in frontend or API endpoints to provide
        immediate feedback to users.
        
        Args:
            workspace_settings: WorkspaceSettings instance to validate against
            new_currency: Proposed new currency code
            
        Returns:
            dict: Validation results with success status and message
            
        Example:
            >>> validation = CurrencyService.validate_currency_change(settings, 'USD')
            >>> if validation['success']:
            ...     # Proceed with actual change
        """
        old_currency = workspace_settings.domestic_currency
        
        if old_currency == new_currency:
            return {
                "success": True,
                "valid": False,
                "message": "Currency unchanged",
                "old_currency": old_currency,
                "new_currency": new_currency
            }
        
        # Validate new currency
        valid_currencies = dict(workspace_settings.CURRENCY_CHOICES)
        if new_currency not in valid_currencies:
            return {
                "success": False,
                "valid": False,
                "message": f"Invalid currency: {new_currency}",
                "old_currency": old_currency,
                "new_currency": new_currency,
                "valid_currencies": list(valid_currencies.keys())
            }
        
        return {
            "success": True,
            "valid": True,
            "message": "Currency change is valid",
            "old_currency": old_currency,
            "new_currency": new_currency,
            "currency_name": valid_currencies[new_currency]
        }