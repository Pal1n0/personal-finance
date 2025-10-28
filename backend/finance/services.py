# app/services.py (alebo app/utils.py)
from django.db import transaction
from .models import Transaction
from .utils.currency_utils import recalculate_transactions_domestic_amount

def recalculate_all_transactions_for_user(user, new_domestic_currency):
    """
    Prepočíta všetky transakcie používateľa pri zmene domácej meny.
    """
    # Najprv zmeníme domestic_currency v settings (ak ešte nie je zmenené)
    # Toto sa už deje pred volaním tejto funkcie
    
    transactions = Transaction.objects.filter(user=user)
    
    updated_transactions = recalculate_transactions_domestic_amount(
        list(transactions), 
        user
    )
    
    with transaction.atomic():
        Transaction.objects.bulk_update(
            updated_transactions,
            ['amount_domestic']
        )
    
    return len(updated_transactions)