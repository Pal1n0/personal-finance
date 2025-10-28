from django.db import models
from django.conf import settings
from decimal import Decimal
from django.core.exceptions import ValidationError
from .utils.currency_utils import recalculate_transactions_domestic_amount

# -------------------------------
# User settings
# -------------------------------
class UserSettings(models.Model):
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

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='settings')
    domestic_currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='EUR')
    fiscal_year_start = models.PositiveSmallIntegerField(choices=FISCAL_YEAR_START_CHOICES, default=1)
    display_mode = models.CharField(max_length=5, choices=DISPLAY_MODE_CHOICES, default='month')
    accounting_mode = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} settings"
    
# -------------------------------
# Category
# -------------------------------
class CategoryVersion(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    version = models.PositiveIntegerField()
    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)  # práve aktívna verzia

    class Meta:
        unique_together = ('user', 'version')

    def __str__(self):
        return f"{self.user.username} - v{self.version}"

class Category(models.Model):
    version = models.ForeignKey(CategoryVersion, on_delete=models.CASCADE, related_name='categories')
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    parent = models.ForeignKey('self', null=True, blank=True,
                               on_delete=models.CASCADE, related_name='children')
    level = models.PositiveIntegerField(default=1)  # od spodného levelu = 1
    is_active = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        # Ak má parenta, vypočíta level z jeho levelu
        if self.parent:
            self.level = self.parent.level - 1
            if self.level < 1:
                self.level = 1
        elif self.children.exists():
            self.level = max(child.level for child in self.children.all()) + 1
        else:
            self.level = 1

        super().save(*args, **kwargs)
    
    def recalc_levels(category):
        """
        Prepočíta level kategórie rekurzívne od leaf nahor.
        Vstup: najvyššie kategórie bez parenta.
        Leaf = level 1
        Parent = max(child.level) + 1
        Funkcia vracia max level stromu.
        """
        max_level = 1  # prednastavené, leaf bude level 1

        if category.children.exists():
            for child in category.children.all():
                child_max = recalc_levels(child)
                if child_max + 1 > max_level:
                    max_level = child_max + 1
            category.level = max_level
        else:
            category.level = 1  # leaf

        category.save(update_fields=['level'])
        return max_level

    def validate_tree_with_root(category, max_level):
        """
        Validácia stromu kategórií:
        - Leaf = level 1
        - Parent > 1
        - Vetva má aspoň jeden leaf
        - Každá kategória, ktorá nie je root, má presne jeden root s level = max_level

        pouzitie:
        roots = Category.objects.filter(parent__isnull=True) # idelne len u jedneho usera
        for root in roots:
            max_level = recalc_levels(root)
            validate_tree_with_root(root, max_level)
        """
        # Leaf kontrola
        if not category.children.exists():
            if category.level != 1:
                raise ValidationError(f"Leaf {category.name} nemá level 1")
            return True

        # Parent level kontrola
        if category.level <= 1:
            raise ValidationError(f"Parent {category.name} má level <= 1")

        # Kontrola, či vetva má leaf
        if not any(child.level == 1 for child in category.children.all()):
            raise ValidationError(f"Vetva {category.name} nemá leaf level = 1")

        # Root kontrola
        if category.parent is None:
            if category.level != max_level:
                raise ValidationError(
                    f"Root {category.name} má level {category.level}, "
                    f"ale očakávaný max level je {max_level}"
                )
        else:
            # Každá ne-root kategória musí mať presne jeden root s level = max_level
            root_count = Category.objects.filter(parent__isnull=True, level=max_level).count()
            if root_count != 1:
                raise ValidationError(
                    f"Kategória {category.name} nemá presne jeden root s level = {max_level}"
                )

        # Rekurzívne validujeme deti
        for child in category.children.all():
            validate_tree_with_root(child, max_level)

        return True

    def is_leaf(self):
        return not self.children.exists()


class CategoryProperty(models.Model):
    PROPERTY_CHOICES = [
        ('cost', 'Only cost'),
        ('expense', 'Only expense'),
        ('revenue', 'Only revenue'),
        ('income', 'Only income'),
    ]
    category = models.OneToOneField(Category, on_delete=models.CASCADE, related_name='property')
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

# -------------------------------
# Transaction
# -------------------------------
class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('income', 'Income'),
        ('expense', 'Expense'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
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
        
        # ⚠️ PROBLEM: Toto nebude fungovať správne pre jednotlivé save
        needs_recalculation = (
            not self.pk or  # Nový záznam
            'original_amount' in kwargs.get('update_fields', []) or
            'original_currency' in kwargs.get('update_fields', []) or
            'date' in kwargs.get('update_fields', [])
        )
        
        # ⚠️ Lepšie je porovnať s pôvodnými hodnotami
        if self.pk:
            old = Transaction.objects.get(pk=self.pk)
            needs_recalculation = (
                old.original_amount != self.original_amount or
                old.original_currency != self.original_currency or
                old.date != self.date
            )
        else:
            needs_recalculation = True
        
        if needs_recalculation:
            transactions = recalculate_transactions_domestic_amount([self], self.user)
            if transactions:
                self.amount_domestic = transactions[0].amount_domestic
        
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user} | {self.type} | {self.amount_domestic} {self.user.settings.domestic_currency}"
