# services/transaction_service.py
from django.db import transaction as db_transaction
from ..models import Transaction, ExpenseCategory, IncomeCategory
from ..utils.currency_utils import recalculate_transactions_domestic_amount

class TransactionService:
    
    @staticmethod
    @db_transaction.atomic
    def bulk_create_transactions(transactions_data, workspace, user):
        transactions = []
        for data in transactions_data:
            # ✅ Oprava - expense_category a income_category musia byť instance, nie ID
            expense_category = None
            income_category = None
            
            if data.get('expense_category'):
                try:
                    expense_category = ExpenseCategory.objects.get(
                        id=data['expense_category'], 
                        version__workspace=workspace
                    )
                except ExpenseCategory.DoesNotExist:
                    pass
                    
            if data.get('income_category'):
                try:
                    income_category = IncomeCategory.objects.get(
                        id=data['income_category'],
                        version__workspace=workspace  
                    )
                except IncomeCategory.DoesNotExist:
                    pass
            
            transaction = Transaction(
                user=user,
                workspace=workspace,
                type=data['type'],
                original_amount=data['original_amount'],
                original_currency=data['original_currency'],
                date=data['date'],
                expense_category=expense_category,  # ✅ Instance, nie ID
                income_category=income_category,    # ✅ Instance, nie ID
                tags=data.get('tags', []),
                note_manual=data.get('note_manual', ''),
                note_auto=data.get('note_auto', ''),
                amount_domestic=data.get('original_amount')  # Dočasne
            )
            transactions.append(transaction)
        
        # Ulož s dočasným amount_domestic
        Transaction.objects.bulk_create(transactions)
        
        # Prepočítaj a updatuj amount_domestic
        transactions = recalculate_transactions_domestic_amount(transactions, workspace)
        Transaction.objects.bulk_update(transactions, ['amount_domestic'])
        
        return transactions
    
    @staticmethod
    @db_transaction.atomic
    def bulk_sync_transactions(transactions_data, workspace, user):
        """
        Univerzálny bulk sync: CREATE, UPDATE, DELETE naraz
        transactions_data = {
            'create': [ {...} ],
            'update': [ {...} ], 
            'delete': [id1, id2, ...]
        }
        """
        results = {
            'created': [],
            'updated': [],
            'deleted': []
        }
        
        # 1. DELETE
        if transactions_data.get('delete'):
            deleted_count, _ = Transaction.objects.filter(
                id__in=transactions_data['delete'],
                workspace=workspace,
                user=user
            ).delete()
            results['deleted'] = transactions_data['delete']
        
        # 2. CREATE
        if transactions_data.get('create'):
            new_transactions = []
            for data in transactions_data['create']:
                expense_category = None
                income_category = None
                
                if data.get('expense_category'):
                    try:
                        expense_category = ExpenseCategory.objects.get(
                            id=data['expense_category'], 
                            version__workspace=workspace
                        )
                    except ExpenseCategory.DoesNotExist:
                        pass
                        
                if data.get('income_category'):
                    try:
                        income_category = IncomeCategory.objects.get(
                            id=data['income_category'],
                            version__workspace=workspace  
                        )
                    except IncomeCategory.DoesNotExist:
                        pass
                
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
                    amount_domestic=data.get('original_amount')  # Dočasne
                )
                new_transactions.append(transaction)
            
            Transaction.objects.bulk_create(new_transactions)
            
            # Prepočítaj amount_domestic pre nové transakcie
            new_transactions = recalculate_transactions_domestic_amount(new_transactions, workspace)
            Transaction.objects.bulk_update(new_transactions, ['amount_domestic'])
            
            results['created'] = [t.id for t in new_transactions]
        
        # 3. UPDATE
        if transactions_data.get('update'):
            updates = []
            for data in transactions_data['update']:
                try:
                    transaction = Transaction.objects.get(
                        id=data['id'],
                        workspace=workspace,
                        user=user
                    )
                    
                    # Update polia
                    transaction.type = data.get('type', transaction.type)
                    transaction.original_amount = data.get('original_amount', transaction.original_amount)
                    transaction.original_currency = data.get('original_currency', transaction.original_currency)
                    transaction.date = data.get('date', transaction.date)
                    
                    # Update category
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
                    
                except (Transaction.DoesNotExist, ExpenseCategory.DoesNotExist, IncomeCategory.DoesNotExist):
                    continue
            
            # Prepočítaj amount_domestic pre updatované transakcie
            updates = recalculate_transactions_domestic_amount(updates, workspace)
            Transaction.objects.bulk_update(updates, [
                'type', 'original_amount', 'original_currency', 'date',
                'expense_category', 'income_category', 'amount_domestic'
            ])
            
            results['updated'] = [t.id for t in updates]
        
        return results
    
    @staticmethod
    @db_transaction.atomic  
    def recalculate_all_transactions_for_workspace(workspace):
        """Prepočíta všetky transakcie workspace pri zmene meny"""
        transactions = Transaction.objects.filter(workspace=workspace)
        transactions_list = list(transactions)
        
        updated_transactions = recalculate_transactions_domestic_amount(
            transactions_list, 
            workspace
        )
        
        Transaction.objects.bulk_update(
            updated_transactions,
            ['amount_domestic']
        )
        
        return len(updated_transactions)