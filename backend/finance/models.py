from django.db import models
from django.conf import settings
from .utils.currency_utils import recalculate_transactions_domestic_amount
from django.core.exceptions import ValidationError

# -------------------------------
# User settings
# -------------------------------

class UserSettings(models.Model):
    LANGUAGE_CHOICES = [
        ('en', 'English'),
        ('cs', 'Czech'),
        ('sk', 'Slovak'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='settings')
    language = models.CharField(max_length=2, choices=LANGUAGE_CHOICES, default='en')

    def __str__(self):
        return f"{self.user.username} settings"

# -------------------------------
# Workspaces + Category
# -------------------------------

class Workspace(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='owned_workspaces')
    members = models.ManyToManyField(settings.AUTH_USER_MODEL, through='WorkspaceMembership', related_name='workspaces')
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.name} (Owner: {self.owner.username})"

class WorkspaceMembership(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('editor', 'Editor'), 
        ('viewer', 'Viewer'),
    ]
    
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='viewer')
    joined_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} in {self.workspace.name} as {self.role}"
    
class WorkspaceSettings(models.Model):
    CURRENCY_CHOICES = [
        ('EUR', 'Euro'),
        ('USD', 'US Dollar'),
        ('GBP', 'British Pound'),
        ('CHF', 'Swiss Franc'),
        ('PLN', 'Polish Zloty'),
        # pridaj ďalšie európske meny podľa potreby
    ]

    FISCAL_YEAR_START_CHOICES = [
        (1, 'January'),
        (2, 'February'),
        (3, 'March'),
        (4, 'April'),
        (5, 'May'),
        (6, 'June'),
        (7, 'July'),
        (8, 'August'),
        (9, 'September'),
        (10, 'October'),
        (11, 'November'),
        (12, 'December'),
    ]

    DISPLAY_MODE_CHOICES = [
        ('month', 'Month only'),
        ('day', 'Full date'),
    ]

    workspace = models.OneToOneField(Workspace, on_delete=models.CASCADE, related_name='settings')
    domestic_currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='EUR')
    fiscal_year_start = models.PositiveSmallIntegerField(choices=FISCAL_YEAR_START_CHOICES, default=1)
    display_mode = models.CharField(max_length=5, choices=DISPLAY_MODE_CHOICES, default='month')
    accounting_mode = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.workspace.name} settings"
    

class ExpenseCategoryVersion(models.Model):
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)  # ← Pridané
    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # ← Zmenené z user
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.workspace.name} - Expense"

class ExpenseCategory(models.Model):

    LEVEL_CHOICES=[(1, 'Level 1 - Root'), (2, 'Level 2'), (3, 'Level 3'), (4, 'Level 4'), (5, 'Level 5 - Leaf')]

    version = models.ForeignKey(ExpenseCategoryVersion, on_delete=models.CASCADE, related_name='categories')
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    children = models.ManyToManyField(
        'self',
        symmetrical=False,  # ❌ nie symetrické
        related_name='parents',  # Automaticky vytvorí reverse vzťah
        blank=True
    )
    level = models.PositiveIntegerField(choices=LEVEL_CHOICES)
    is_active = models.BooleanField(default=True)
    
    @property
    def is_leaf(self):
        return not self.children.exists()

    @property 
    def is_root(self):
        return not self.parents.exists()
    
    def add_child(self, child):
        """Bezpečné pridanie child s validáciou"""
        if child.parents.exists():
            raise ValidationError(f"Kategória {child.name} už má parenta")
        self.children.add(child)
    
    def clean(self):
        """Validácia pri uložení"""
        for child in self.children.all():
            if child.parents.exclude(pk=self.pk).exists():
                raise ValidationError(f"Child {child.name} už má iného parenta")

class IncomeCategoryVersion(models.Model):
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)  # ← Pridané
    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # ← Zmenené
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.workspace.name} - Income"

class IncomeCategory(models.Model):

    LEVEL_CHOICES=[(1, 'Level 1 - Root'), (2, 'Level 2'), (3, 'Level 3'), (4, 'Level 4'), (5, 'Level 5 - Leaf')]

    version = models.ForeignKey(IncomeCategoryVersion, on_delete=models.CASCADE, related_name='categories')
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    children = models.ManyToManyField(
        'self',
        symmetrical=False,  # ❌ nie symetrické
        related_name='parents',  # Automaticky vytvorí reverse vzťah
        blank=True
    )
    level = models.PositiveIntegerField(choices=LEVEL_CHOICES)
    is_active = models.BooleanField(default=True)

    @property
    def is_leaf(self):
        return not self.children.exists()

    @property 
    def is_root(self):
        return not self.parents.exists()
    
    def add_child(self, child):
        """Bezpečné pridanie child s validáciou"""
        if child.parents.exists():
            raise ValidationError(f"Kategória {child.name} už má parenta")
        self.children.add(child)
    
    def clean(self):
        """Validácia pri uložení"""
        for child in self.children.all():
            if child.parents.exclude(pk=self.pk).exists():
                raise ValidationError(f"Child {child.name} už má iného parenta")

class BaseCategoryProperty(models.Model):
    property_type = models.CharField(max_length=10)
    
    class Meta:
        abstract = True
    
    def __str__(self):
        return f"{self.property_type}"

class ExpenseCategoryProperty(BaseCategoryProperty):
    PROPERTY_CHOICES = [
        ('cost', 'Only cost'),
        ('expense', 'Only expense'),
    ]
    category = models.OneToOneField(ExpenseCategory, on_delete=models.CASCADE, related_name='property')
    property_type = models.CharField(max_length=10, choices=PROPERTY_CHOICES)

    def __str__(self):
        return f"{self.category.name} - {self.property_type}"


class IncomeCategoryProperty(BaseCategoryProperty):
    PROPERTY_CHOICES = [
        ('revenue', 'Only revenue'),
        ('income', 'Only income'),
    ]
    category = models.OneToOneField(IncomeCategory, on_delete=models.CASCADE, related_name='property')
    property_type = models.CharField(max_length=10, choices=PROPERTY_CHOICES)

    def __str__(self):
        return f"{self.category.name} - {self.property_type}"

# -------------------------------
# Exchange rate
# -------------------------------
class ExchangeRate(models.Model):
    currency = models.CharField(max_length=3)  # napr. USD, GBP
    rate_to_eur = models.DecimalField(max_digits=20, decimal_places=6)
    date = models.DateField()

    class Meta:
        unique_together = ('currency', 'date')
        ordering = ['-date']

    def __str__(self):
        return f"{self.currency} - {self.rate_to_eur} ({self.date})"
    
    def clean(self):
        if self.rate_to_eur <= 0:
            raise ValidationError("Exchange rate must be positive")

# -------------------------------
# Transaction
# -------------------------------
class Transaction(models.Model):
    class Meta:
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['user', 'month']),
            models.Index(fields=['user', 'type']),
        ]

    TRANSACTION_TYPES = [
        ('income', 'Income'),
        ('expense', 'Expense'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    expense_category = models.ForeignKey(
        ExpenseCategory, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='expense_transactions'
    )
    income_category = models.ForeignKey(
        IncomeCategory, on_delete=models.SET_NULL, null=True, blank=True, 
        related_name='income_transactions'
    )
    original_amount = models.DecimalField(max_digits=20, decimal_places=4)
    original_currency = models.CharField(max_length=3)
    amount_domestic = models.DecimalField(max_digits=20, decimal_places=4)  # uložené už v domácej mene
    date = models.DateField()
    month = models.DateField()
    tags = models.JSONField(default=list, blank=True)
    note_manual = models.TextField(blank=True)
    note_auto = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if self.date:
            self.month = self.date.replace(day=1)
        
        needs_recalculation = False
        
        if self.pk:
            try:
                old = Transaction.objects.get(pk=self.pk)
                needs_recalculation = (
                    old.original_amount != self.original_amount or
                    old.original_currency != self.original_currency or
                    old.date != self.date
                )
            except Transaction.DoesNotExist:
                needs_recalculation = True
        else:
            needs_recalculation = True
        
        if needs_recalculation:
            try:
                transactions = recalculate_transactions_domestic_amount([self], self.workspace)
                if transactions and transactions[0].amount_domestic is not None:
                    self.amount_domestic = transactions[0].amount_domestic
                else:
                    # Fallback - použij pôvodnú sumu
                    self.amount_domestic = self.original_amount
            except Exception:
                # Ak prepočet zlyhá, použij pôvodnú sumu
                self.amount_domestic = self.original_amount
        
        super().save(*args, **kwargs)

    @property
    def category(self):
        return self.expense_category or self.income_category
    
    def clean(self):
        if self.expense_category and self.income_category:
            raise ValidationError("Transaction can have only one category type")
        if not self.expense_category and not self.income_category:
            raise ValidationError("Transaction must have one category")
        
        # Voliteľné: kontrola konzistencie type a category
        if self.type == 'expense' and self.income_category:
            raise ValidationError("Expense transaction cannot have income category")
        if self.type == 'income' and self.expense_category:
            raise ValidationError("Income transaction cannot have expense category")

    def __str__(self):
        return f"{self.user} | {self.type} | {self.amount_domestic} {self.workspace.settings.domestic_currency}"
