"""
Currency conversion utilities for financial management system.

This module provides functions for currency conversion, exchange rate handling,
and transaction amount recalculations with proper error handling and logging.
"""

import logging
from decimal import Decimal, ROUND_HALF_UP
from collections import defaultdict
from datetime import date
from typing import List, Dict, Optional

from .models import ExchangeRate, Transaction, Workspace

# Get structured logger for this module
logger = logging.getLogger(__name__)


class CurrencyConversionError(Exception):
    """Custom exception for currency conversion failures."""
    
    def __init__(self, message: str, currency: str = None, tx_date: date = None, transaction_id: int = None):
        self.message = message
        self.currency = currency
        self.tx_date = tx_date
        self.transaction_id = transaction_id
        super().__init__(self.message)


def get_exchange_rates_for_range(currencies: List[str], date_from: date, date_to: date) -> Dict[str, Dict[date, Decimal]]:
    """
    Retrieve exchange rates for specified currencies and date range.
    
    Fetches historical exchange rates from the database for the given currencies
    and date range, excluding EUR as it's the base currency.
    
    Args:
        currencies: List of currency codes to fetch rates for
        date_from: Start date of the range (inclusive)
        date_to: End date of the range (inclusive)
        
    Returns:
        Dictionary mapping currency codes to dictionaries of date-rate pairs
        
    Raises:
        CurrencyConversionError: If no rates found for required currencies
    """
    logger.debug(
        "Fetching exchange rates for range",
        extra={
            "currencies": currencies,
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "action": "exchange_rates_fetch_start",
            "component": "get_exchange_rates_for_range",
        },
    )
    
    rates = defaultdict(dict)
    
    # Remove duplicates and EUR if present in currencies
    currencies = list(set(currencies))
    
    # Load rates for all currencies EXCEPT EUR
    non_eur_currencies = [c for c in currencies if c != 'EUR']
    
    if non_eur_currencies:
        qs = ExchangeRate.objects.filter(
            currency__in=non_eur_currencies,
            date__gte=date_from,
            date__lte=date_to
        ).order_by('currency', 'date')

        for rate_record in qs:
            currency_key = rate_record.currency.upper()
            rates[currency_key][rate_record.date] = Decimal(rate_record.rate_to_eur)
    
    # Validate that we have rates for all required currencies (except EUR)
    missing_currencies = [curr for curr in non_eur_currencies if curr not in rates or not rates[curr]]
    if missing_currencies:
        logger.error(
            "Missing exchange rates for required currencies",
            extra={
                "missing_currencies": missing_currencies,
                "date_range": f"{date_from.isoformat()} to {date_to.isoformat()}",
                "available_currencies": list(rates.keys()),
                "action": "exchange_rates_missing",
                "component": "get_exchange_rates_for_range",
                "severity": "high",
            },
        )
        raise CurrencyConversionError(
            f"No exchange rates found for currencies: {', '.join(missing_currencies)} "
            f"in date range {date_from} to {date_to}"
        )
    
    logger.debug(
        "Exchange rates fetched successfully",
        extra={
            "currencies_requested": currencies,
            "currencies_fetched": list(rates.keys()),
            "total_rate_records": sum(len(dates) for dates in rates.values()),
            "date_range": f"{date_from.isoformat()} to {date_to.isoformat()}",
            "action": "exchange_rates_fetch_success",
            "component": "get_exchange_rates_for_range",
        },
    )
    
    return rates


def find_closest_rate(rates: Dict[str, Dict[date, Decimal]], currency: str, tx_date: date) -> Decimal:
    """
    Find the closest available exchange rate for a currency on or before transaction date.
    
    Searches for the most recent exchange rate that is available on or before
    the transaction date to ensure historical accuracy.
    
    Args:
        rates: Dictionary of currency rates from get_exchange_rates_for_range
        currency: Currency code to find rate for
        tx_date: Transaction date to find closest rate for
        
    Returns:
        Decimal exchange rate
        
    Raises:
        CurrencyConversionError: If no suitable rate found
    """
    if currency not in rates:
        logger.error(
            "Currency not found in rates dictionary",
            extra={
                "currency": currency,
                "available_currencies": list(rates.keys()),
                "action": "currency_not_found_in_rates",
                "component": "find_closest_rate",
                "severity": "high",
            },
        )
        raise CurrencyConversionError(
            f"No exchange rates available for currency: {currency}",
            currency=currency
        )
    
    currency_rates = rates[currency]
    if not currency_rates:
        logger.error(
            "No rates available for currency",
            extra={
                "currency": currency,
                "action": "no_rates_for_currency",
                "component": "find_closest_rate",
                "severity": "high",
            },
        )
        raise CurrencyConversionError(
            f"No exchange rate records found for currency: {currency}",
            currency=currency
        )
    
    # Find all dates on or before transaction date
    possible_dates = [rate_date for rate_date in currency_rates.keys() if rate_date <= tx_date]
    if not possible_dates:
        logger.error(
            "No suitable rates found for currency before transaction date",
            extra={
                "currency": currency,
                "transaction_date": tx_date.isoformat(),
                "available_dates": list(currency_rates.keys()),
                "action": "no_rates_before_date",
                "component": "find_closest_rate",
                "severity": "high",
            },
        )
        raise CurrencyConversionError(
            f"No exchange rate found for {currency} on or before {tx_date}",
            currency=currency,
            tx_date=tx_date
        )
    
    # Get the closest date (maximum date that is <= tx_date)
    closest_date = max(possible_dates)
    closest_rate = currency_rates[closest_date]
    
    logger.debug(
        "Closest rate found successfully",
        extra={
            "currency": currency,
            "transaction_date": tx_date.isoformat(),
            "closest_date": closest_date.isoformat(),
            "closest_rate": float(closest_rate),
            "days_difference": (tx_date - closest_date).days,
            "action": "closest_rate_found",
            "component": "find_closest_rate",
        },
    )
    
    return closest_rate


def convert_amount_to_domestic(
    original_amount: Decimal, 
    original_currency: str, 
    domestic_currency: str, 
    tx_date: date, 
    rates: Dict[str, Dict[date, Decimal]],
    transaction_id: int = None
) -> Decimal:
    """
    Convert transaction amount from original currency to domestic currency.
    
    Handles three conversion scenarios:
    1. Same currency: Direct return
    2. Domestic is EUR: Convert via EUR rate
    3. Different currencies: Convert via EUR intermediary
    
    Args:
        original_amount: Amount in original currency
        original_currency: Source currency code
        domestic_currency: Target currency code
        tx_date: Transaction date for rate lookup
        rates: Dictionary of exchange rates
        transaction_id: Optional transaction ID for error context
        
    Returns:
        Converted amount in domestic currency
        
    Raises:
        CurrencyConversionError: If conversion fails for any reason
        ValueError: If input parameters are invalid
    """
    # Input validation
    if not isinstance(original_amount, (Decimal, int, float)):
        raise ValueError("original_amount must be a numeric type")
    
    if not original_currency or not domestic_currency:
        raise ValueError("Currency codes cannot be empty")
    
    logger.debug(
        "Currency conversion started",
        extra={
            "transaction_id": transaction_id,
            "original_amount": float(original_amount),
            "original_currency": original_currency,
            "domestic_currency": domestic_currency,
            "transaction_date": tx_date.isoformat(),
            "action": "currency_conversion_start",
            "component": "convert_amount_to_domestic",
        },
    )
    
    # Same currency - no conversion needed
    if original_currency == domestic_currency:
        logger.debug(
            "Same currency - no conversion needed",
            extra={
                "currency": original_currency,
                "action": "same_currency_skip",
                "component": "convert_amount_to_domestic",
            },
        )
        return Decimal(original_amount)
    
    original_amount_decimal = Decimal(original_amount)
    
    try:
        # Case 1: Domestic currency is EUR
        if domestic_currency == 'EUR':
            rate = find_closest_rate(rates, original_currency, tx_date)
            converted_amount = (original_amount_decimal * rate).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP)
            
            logger.debug(
                "Conversion to EUR completed",
                extra={
                    "transaction_id": transaction_id,
                    "original_amount": float(original_amount_decimal),
                    "rate": float(rate),
                    "converted_amount": float(converted_amount),
                    "action": "conversion_to_eur_success",
                    "component": "convert_amount_to_domestic",
                },
            )
            return converted_amount
        
        # Case 2: Original currency is EUR
        elif original_currency == 'EUR':
            rate_domestic = find_closest_rate(rates, domestic_currency, tx_date)
            converted_amount = (original_amount_decimal / rate_domestic).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP)
            
            logger.debug(
                "Conversion from EUR completed",
                extra={
                    "transaction_id": transaction_id,
                    "original_amount": float(original_amount_decimal),
                    "rate": float(rate_domestic),
                    "converted_amount": float(converted_amount),
                    "action": "conversion_from_eur_success",
                    "component": "convert_amount_to_domestic",
                },
            )
            return converted_amount
        
        # Case 3: Different currencies - convert via EUR
        else:
            rate_orig = find_closest_rate(rates, original_currency, tx_date)
            rate_domestic = find_closest_rate(rates, domestic_currency, tx_date)
            
            # Convert: original → EUR → domestic
            converted_amount = (original_amount_decimal * (rate_domestic / rate_orig)).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP)
            
            logger.debug(
                "Cross-currency conversion completed",
                extra={
                    "transaction_id": transaction_id,
                    "original_amount": float(original_amount_decimal),
                    "rate_original": float(rate_orig),
                    "rate_domestic": float(rate_domestic),
                    "converted_amount": float(converted_amount),
                    "action": "cross_currency_conversion_success",
                    "component": "convert_amount_to_domestic",
                },
            )
            return converted_amount
            
    except CurrencyConversionError as e:
        # Re-raise with transaction context
        logger.error(
            "Currency conversion failed",
            extra={
                "transaction_id": transaction_id,
                "original_currency": original_currency,
                "domestic_currency": domestic_currency,
                "transaction_date": tx_date.isoformat(),
                "error_message": str(e),
                "action": "currency_conversion_failed",
                "component": "convert_amount_to_domestic",
                "severity": "high",
            },
        )
        raise CurrencyConversionError(
            f"Failed to convert {original_amount} {original_currency} to {domestic_currency}: {e.message}",
            currency=original_currency,
            tx_date=tx_date,
            transaction_id=transaction_id
        ) from e


def recalculate_transactions_domestic_amount(transactions: List[Transaction], workspace: Workspace) -> List[Transaction]:
    """
    Recalculate domestic amounts for transactions based on workspace currency.
    
    Processes a list of transactions and updates their domestic_amount fields
    based on current exchange rates and workspace domestic currency settings.
    Transactions already in domestic currency are skipped.
    
    Args:
        transactions: List of Transaction instances to recalculate
        workspace: Workspace instance containing currency settings
        
    Returns:
        List of Transaction instances with updated domestic_amount fields
        
    Raises:
        CurrencyConversionError: If any transaction conversion fails
        
    Example:
        >>> updated_transactions = recalculate_transactions_domestic_amount(transactions, workspace)
    """
    if not transactions:
        logger.debug(
            "No transactions to recalculate",
            extra={
                "workspace_id": workspace.id,
                "action": "recalculation_skip_empty",
                "component": "recalculate_transactions_domestic_amount",
            },
        )
        return transactions
    
    domestic_currency = workspace.settings.domestic_currency
    
    logger.info(
        "Transaction domestic amount recalculation started",
        extra={
            "workspace_id": workspace.id,
            "domestic_currency": domestic_currency,
            "total_transactions": len(transactions),
            "action": "recalculation_start",
            "component": "recalculate_transactions_domestic_amount",
        },
    )
    
    # Filter transactions that need recalculation
    transactions_to_recalculate = [t for t in transactions if t.original_currency != domestic_currency]
    
    if not transactions_to_recalculate:
        logger.debug(
            "No transactions need recalculation - all already in domestic currency",
            extra={
                "workspace_id": workspace.id,
                "domestic_currency": domestic_currency,
                "action": "recalculation_skip_same_currency",
                "component": "recalculate_transactions_domestic_amount",
            },
        )
        return transactions
    
    # Determine date range and currency list
    all_dates = [t.date for t in transactions_to_recalculate if t.date]
    if not all_dates:
        logger.error(
            "No valid dates in transactions - cannot recalculate",
            extra={
                "workspace_id": workspace.id,
                "transaction_count": len(transactions_to_recalculate),
                "action": "recalculation_failed_no_dates",
                "component": "recalculate_transactions_domestic_amount",
                "severity": "high",
            },
        )
        raise CurrencyConversionError(
            "Cannot recalculate transactions: no valid dates found in transactions"
        )
        
    date_from, date_to = min(all_dates), max(all_dates)
    currencies = list({t.original_currency for t in transactions_to_recalculate})
    currencies.append(domestic_currency)
    
    logger.debug(
        "Recalculation parameters determined",
        extra={
            "workspace_id": workspace.id,
            "transactions_to_recalculate": len(transactions_to_recalculate),
            "date_range": f"{date_from.isoformat()} to {date_to.isoformat()}",
            "currencies_involved": currencies,
            "action": "recalculation_parameters_determined",
            "component": "recalculate_transactions_domestic_amount",
        },
    )
    
    try:
        # Load exchange rates - this will fail if rates are missing
        rates = get_exchange_rates_for_range(currencies, date_from, date_to)
        
        # Recalculate amounts - any failure will raise CurrencyConversionError
        for transaction in transactions_to_recalculate:
            domestic_amount = convert_amount_to_domestic(
                transaction.original_amount,
                transaction.original_currency,
                domestic_currency,
                transaction.date,
                rates,
                transaction_id=transaction.id
            )
            transaction.amount_domestic = domestic_amount
            
            logger.debug(
                "Transaction domestic amount updated successfully",
                extra={
                    "transaction_id": transaction.id,
                    "original_amount": float(transaction.original_amount),
                    "original_currency": transaction.original_currency,
                    "domestic_amount": float(domestic_amount),
                    "domestic_currency": domestic_currency,
                    "action": "transaction_domestic_amount_updated",
                    "component": "recalculate_transactions_domestic_amount",
                },
            )
        
        logger.info(
            "Transaction domestic amount recalculation completed successfully",
            extra={
                "workspace_id": workspace.id,
                "total_processed": len(transactions_to_recalculate),
                "success_rate": "100%",
                "action": "recalculation_completed_success",
                "component": "recalculate_transactions_domestic_amount",
            },
        )
        
        return transactions
        
    except CurrencyConversionError as e:
        logger.error(
            "Transaction domestic amount recalculation failed",
            extra={
                "workspace_id": workspace.id,
                "failed_transaction_id": e.transaction_id,
                "error_message": e.message,
                "affected_currency": e.currency,
                "transaction_date": e.tx_date.isoformat() if e.tx_date else None,
                "action": "recalculation_failed",
                "component": "recalculate_transactions_domestic_amount",
                "severity": "critical",
            },
        )
        # Re-raise to ensure atomic rollback in calling code
        raise