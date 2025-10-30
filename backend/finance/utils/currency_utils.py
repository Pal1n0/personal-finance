# utils/currency_utils.py
from decimal import Decimal, ROUND_HALF_UP
from collections import defaultdict
from datetime import date
from django.db import transaction
from .models import ExchangeRate

def get_exchange_rates_for_range(currencies, date_from, date_to):
    rates = defaultdict(dict)
    
    # Odstráň duplikáty a EUR ak je v currencies
    currencies = list(set(currencies))
    
    # Načítaj kurzy pre všetky meny OKREM EUR
    non_eur_currencies = [c for c in currencies if c != 'EUR']
    
    if non_eur_currencies:
        qs = ExchangeRate.objects.filter(
            currency__in=non_eur_currencies,
            date__gte=date_from,
            date__lte=date_to
        ).order_by('currency', 'date')

        for r in qs:
            rates[r.currency.upper()][r.date] = Decimal(r.rate_to_eur)
    
    return rates

def find_closest_rate(rates, currency, tx_date):
    """Nájde kurz platný pre daný dátum (<= tx_date)."""
    if currency not in rates:
        return None
    
    currency_rates = rates[currency]
    if not currency_rates:
        return None
    
    possible_dates = [d for d in currency_rates.keys() if d <= tx_date]
    if not possible_dates:
        return None
    
    closest_date = max(possible_dates)
    return currency_rates[closest_date]

def convert_amount_to_domestic(original_amount, original_currency, domestic_currency, tx_date, rates):
    if original_currency == domestic_currency:
        return Decimal(original_amount)
    
    original_amount = Decimal(original_amount)
    
    # Ak je domáca EUR
    if domestic_currency == 'EUR':
        rate = find_closest_rate(rates, original_currency, tx_date)
        if rate:
            return (original_amount * rate).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP)
        return None
    
    # Ak je pôvodná EUR
    elif original_currency == 'EUR':
        rate_domestic = find_closest_rate(rates, domestic_currency, tx_date)
        if rate_domestic:
            return (original_amount / rate_domestic).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP)
        return None
    
    # Iné meny: orig → EUR → domestic
    else:
        rate_orig = find_closest_rate(rates, original_currency, tx_date)
        rate_domestic = find_closest_rate(rates, domestic_currency, tx_date)
        if rate_orig and rate_domestic:
            return (original_amount * (rate_domestic / rate_orig)).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP)
        return None

def recalculate_transactions_domestic_amount(transactions, workspace):
    """
    Prepočíta `amount_domestic` pre transakcie podľa workspace meny.
    """
    if not transactions:
        return transactions
    
    domestic_currency = workspace.settings.domestic_currency
    transactions_to_recalculate = [t for t in transactions if t.original_currency != domestic_currency]
    
    if not transactions_to_recalculate:
        return transactions
    
    # Zistíme rozsah dátumov a zoznam mien
    all_dates = [t.date for t in transactions_to_recalculate if t.date]
    if not all_dates:
        return transactions
        
    date_from, date_to = min(all_dates), max(all_dates)
    currencies = list({t.original_currency for t in transactions_to_recalculate})
    currencies.append(domestic_currency)
    
    # Načítame kurzy
    rates = get_exchange_rates_for_range(currencies, date_from, date_to)
    
    # Prepočítame sumy
    for tx in transactions_to_recalculate:
        domestic_amount = convert_amount_to_domestic(
            tx.original_amount,
            tx.original_currency,
            domestic_currency,
            tx.date,
            rates
        )
        if domestic_amount is not None:
            tx.amount_domestic = domestic_amount
        else:
            # Fallback - použij pôvodnú sumu
            tx.amount_domestic = tx.original_amount
    
    return transactions