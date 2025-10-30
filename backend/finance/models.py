"""
Database models for financial management system.

This module defines all database models for the financial management application,
including workspaces, transactions, categories, exchange rates, and user settings.
"""

import logging
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from .utils.currency_utils import recalculate_transactions_domestic_amount


# Get structured logger for this module
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# USER SETTINGS
# -------------------------------------------------------------------
# User-specific preferences and personalization options


class UserSettings(models.Model):
    """
    User-specific settings and preferences.
    
    Stores individual user preferences like language settings
    and other personalization options.
    """
    
    LANGUAGE_CHOICES = [
        ('en', 'English'),
        ('cs', 'Czech'),
        ('sk', 'Slovak'),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='settings'
    )
    language = models.CharField(
        max_length=2, 
        choices=LANGUAGE_CHOICES, 
        default='en'
    )

    def __str__(self):
        """
        String representation of UserSettings.
        """
        return f"{self.user.username} settings"

    def clean(self):
        """
        Validate user settings data.
        """
        super().clean()
        
        logger.debug(
            "UserSettings validation completed",
            extra={
                "user_id": self.user.id,
                "language": self.language,
                "action": "user_settings_validation",
                "component": "UserSettings",
            },
        )

# -------------------------------------------------------------------
# WORKSPACE & MEMBERSHIP  
# -------------------------------------------------------------------
# Collaborative workspace models with role-based permissions


class Workspace(models.Model):
    """
    Workspace model for collaborative financial management.
    
    Represents a shared workspace where multiple users can collaborate
    on financial data with different permission levels.
    """
    
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='owned_workspaces'
    )
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL, 
        through='WorkspaceMembership', 
        related_name='workspaces'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        """
        String representation of Workspace.
        """
        return f"{self.name} (Owner: {self.owner.username})"

    def clean(self):
        """
        Validate workspace data.
        """
        if not self.name or len(self.name.strip()) < 2:
            raise ValidationError("Workspace name must be at least 2 characters long.")
        
        logger.debug(
            "Workspace validation completed",
            extra={
                "workspace_id": self.id if self.id else "new",
                "workspace_name": self.name,
                "action": "workspace_validation",
                "component": "Workspace",
            },
        )


class WorkspaceMembership(models.Model):
    """
    Workspace membership model with role-based permissions.
    
    Defines the relationship between users and workspaces with specific roles
    that determine access levels and permissions.
    """
    
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('editor', 'Editor'), 
        ('viewer', 'Viewer'),
    ]
    
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='viewer')
    joined_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['workspace', 'user']
        verbose_name_plural = "Workspace memberships"
    
    def __str__(self):
        """
        String representation of WorkspaceMembership.
        """
        return f"{self.user.username} in {self.workspace.name} as {self.role}"

    def clean(self):
        """
        Validate workspace membership data.
        """
        # Prevent duplicate memberships
        if WorkspaceMembership.objects.filter(
            workspace=self.workspace, 
            user=self.user
        ).exclude(pk=self.pk).exists():
            raise ValidationError("User is already a member of this workspace.")
        
        logger.debug(
            "WorkspaceMembership validation completed",
            extra={
                "workspace_id": self.workspace.id,
                "user_id": self.user.id,
                "role": self.role,
                "action": "workspace_membership_validation",
                "component": "WorkspaceMembership",
            },
        )

# -------------------------------------------------------------------
# WORKSPACE SETTINGS
# -------------------------------------------------------------------
# Workspace-specific configuration and preferences


class WorkspaceSettings(models.Model):
    """
    Workspace-specific configuration and settings.
    
    Stores workspace-level preferences including currency settings,
    fiscal year configuration, and display options.
    """
    
    CURRENCY_CHOICES = [
        ('EUR', 'Euro'),
        ('USD', 'US Dollar'),
        ('GBP', 'British Pound'),
        ('CHF', 'Swiss Franc'),
        ('PLN', 'Polish Zloty'),
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

    workspace = models.OneToOneField(
        Workspace, 
        on_delete=models.CASCADE, 
        related_name='settings'
    )
    domestic_currency = models.CharField(
        max_length=3, 
        choices=CURRENCY_CHOICES, 
        default='EUR'
    )
    fiscal_year_start = models.PositiveSmallIntegerField(
        choices=FISCAL_YEAR_START_CHOICES, 
        default=1
    )
    display_mode = models.CharField(
        max_length=5, 
        choices=DISPLAY_MODE_CHOICES, 
        default='month'
    )
    accounting_mode = models.BooleanField(default=False)

    def __str__(self):
        """
        String representation of WorkspaceSettings.
        """
        return f"{self.workspace.name} settings"
    
    def clean(self):
        """
        Validate workspace settings data.
        """
        if self.fiscal_year_start not in [choice[0] for choice in self.FISCAL_YEAR_START_CHOICES]:
            raise ValidationError("Invalid fiscal year start month.")
        
        logger.debug(
            "WorkspaceSettings validation completed",
            extra={
                "workspace_id": self.workspace.id,
                "domestic_currency": self.domestic_currency,
                "fiscal_year_start": self.fiscal_year_start,
                "action": "workspace_settings_validation",
                "component": "WorkspaceSettings",
            },
        )

# -------------------------------------------------------------------
# EXPENSE CATEGORIES
# -------------------------------------------------------------------
# Hierarchical expense category system with version control


class ExpenseCategoryVersion(models.Model):
    """
    Version control for expense category hierarchies.
    
    Enables multiple versions of expense category structures for audit trails
    and historical tracking within workspaces.
    """
    
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "Expense category versions"
        ordering = ['-created_at']

    def __str__(self):
        """
        String representation of ExpenseCategoryVersion.
        """
        return f"{self.workspace.name} - Expense"

    def clean(self):
        """
        Validate expense category version data.
        """
        if not self.name or len(self.name.strip()) < 2:
            raise ValidationError("Version name must be at least 2 characters long.")
        
        logger.debug(
            "ExpenseCategoryVersion validation completed",
            extra={
                "version_id": self.id if self.id else "new",
                "workspace_id": self.workspace.id,
                "action": "expense_category_version_validation",
                "component": "ExpenseCategoryVersion",
            },
        )


class ExpenseCategory(models.Model):
    """
    Hierarchical expense category structure.
    
    Represents a tree-like structure for organizing expense categories
    with multiple levels and parent-child relationships.
    """
    
    LEVEL_CHOICES = [
        (1, 'Level 1 - Root'), 
        (2, 'Level 2'), 
        (3, 'Level 3'), 
        (4, 'Level 4'), 
        (5, 'Level 5 - Leaf')
    ]

    version = models.ForeignKey(
        ExpenseCategoryVersion, 
        on_delete=models.CASCADE, 
        related_name='categories'
    )
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    children = models.ManyToManyField(
        'self',
        symmetrical=False,
        related_name='parents',
        blank=True
    )
    level = models.PositiveIntegerField(choices=LEVEL_CHOICES)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name_plural = "Expense categories"
        ordering = ['level', 'name']

    @property
    def is_leaf(self):
        """
        Check if category is a leaf node (has no children).
        
        Returns:
            bool: True if category has no children
        """
        return not self.children.exists()

    @property 
    def is_root(self):
        """
        Check if category is a root node (has no parents).
        
        Returns:
            bool: True if category has no parents
        """
        return not self.parents.exists()
    
    def add_child(self, child):
        """
        Safely add child category with validation.
        
        Args:
            child: ExpenseCategory instance to add as child
            
        Raises:
            ValidationError: If child already has a parent
        """
        if child.parents.exists():
            logger.warning(
                "Attempt to add child with existing parent",
                extra={
                    "parent_id": self.id,
                    "child_id": child.id,
                    "child_name": child.name,
                    "action": "child_addition_failed",
                    "component": "ExpenseCategory",
                    "severity": "medium",
                },
            )
            raise ValidationError(f"Category {child.name} already has a parent")
        
        self.children.add(child)
        
        logger.debug(
            "Child category added successfully",
            extra={
                "parent_id": self.id,
                "child_id": child.id,
                "action": "child_addition_success",
                "component": "ExpenseCategory",
            },
        )
    
    def clean(self):
        """
        Validate category data and relationships.
        """
        # Validate level constraints
        if self.level < 1 or self.level > 5:
            raise ValidationError("Category level must be between 1 and 5")
        
        # Validate name
        if not self.name or len(self.name.strip()) < 2:
            raise ValidationError("Category name must be at least 2 characters long")
        
        # Validate child relationships
        for child in self.children.all():
            if child.parents.exclude(pk=self.pk).exists():
                logger.warning(
                    "Category validation failed - child has other parents",
                    extra={
                        "category_id": self.id,
                        "child_id": child.id,
                        "action": "category_validation_failed",
                        "component": "ExpenseCategory",
                        "severity": "medium",
                    },
                )
                raise ValidationError(f"Child {child.name} already has another parent")
        
        logger.debug(
            "ExpenseCategory validation completed",
            extra={
                "category_id": self.id if self.id else "new",
                "category_name": self.name,
                "level": self.level,
                "child_count": self.children.count(),
                "action": "expense_category_validation",
                "component": "ExpenseCategory",
            },
        )

    def __str__(self):
        """
        String representation of ExpenseCategory.
        """
        return f"{self.name} (Level {self.level})"

# -------------------------------------------------------------------
# INCOME CATEGORIES
# -------------------------------------------------------------------
# Hierarchical income category system with version control


class IncomeCategoryVersion(models.Model):
    """
    Version control for income category hierarchies.
    
    Enables multiple versions of income category structures for audit trails
    and historical tracking within workspaces.
    """
    
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "Income category versions"
        ordering = ['-created_at']

    def __str__(self):
        """
        String representation of IncomeCategoryVersion.
        """
        return f"{self.workspace.name} - Income"

    def clean(self):
        """
        Validate income category version data.
        """
        if not self.name or len(self.name.strip()) < 2:
            raise ValidationError("Version name must be at least 2 characters long.")
        
        logger.debug(
            "IncomeCategoryVersion validation completed",
            extra={
                "version_id": self.id if self.id else "new",
                "workspace_id": self.workspace.id,
                "action": "income_category_version_validation",
                "component": "IncomeCategoryVersion",
            },
        )


class IncomeCategory(models.Model):
    """
    Hierarchical income category structure.
    
    Represents a tree-like structure for organizing income categories
    with multiple levels and parent-child relationships.
    """
    
    LEVEL_CHOICES = [
        (1, 'Level 1 - Root'), 
        (2, 'Level 2'), 
        (3, 'Level 3'), 
        (4, 'Level 4'), 
        (5, 'Level 5 - Leaf')
    ]

    version = models.ForeignKey(
        IncomeCategoryVersion, 
        on_delete=models.CASCADE, 
        related_name='categories'
    )
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=1000, blank=True, null=True)  
    children = models.ManyToManyField(
        'self',
        symmetrical=False,
        related_name='parents',
        blank=True
    )
    level = models.PositiveIntegerField(choices=LEVEL_CHOICES)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name_plural = "Income categories"
        ordering = ['level', 'name']

    @property
    def is_leaf(self):
        """
        Check if category is a leaf node (has no children).
        
        Returns:
            bool: True if category has no children
        """
        return not self.children.exists()

    @property 
    def is_root(self):
        """
        Check if category is a root node (has no parents).
        
        Returns:
            bool: True if category has no parents
        """
        return not self.parents.exists()
    
    def add_child(self, child):
        """
        Safely add child category with validation.
        
        Args:
            child: IncomeCategory instance to add as child
            
        Raises:
            ValidationError: If child already has a parent
        """
        if child.parents.exists():
            logger.warning(
                "Attempt to add child with existing parent",
                extra={
                    "parent_id": self.id,
                    "child_id": child.id,
                    "child_name": child.name,
                    "action": "child_addition_failed",
                    "component": "IncomeCategory",
                    "severity": "medium",
                },
            )
            raise ValidationError(f"Category {child.name} already has a parent")
        
        self.children.add(child)
        
        logger.debug(
            "Child category added successfully",
            extra={
                "parent_id": self.id,
                "child_id": child.id,
                "action": "child_addition_success",
                "component": "IncomeCategory",
            },
        )
    
    def clean(self):
        """
        Validate category data and relationships.
        """
        # Validate level constraints
        if self.level < 1 or self.level > 5:
            raise ValidationError("Category level must be between 1 and 5")
        
        # Validate name
        if not self.name or len(self.name.strip()) < 2:
            raise ValidationError("Category name must be at least 2 characters long")
        
        # Validate child relationships
        for child in self.children.all():
            if child.parents.exclude(pk=self.pk).exists():
                logger.warning(
                    "Category validation failed - child has other parents",
                    extra={
                        "category_id": self.id,
                        "child_id": child.id,
                        "action": "category_validation_failed",
                        "component": "IncomeCategory",
                        "severity": "medium",
                    },
                )
                raise ValidationError(f"Child {child.name} already has another parent")
        
        logger.debug(
            "IncomeCategory validation completed",
            extra={
                "category_id": self.id if self.id else "new",
                "category_name": self.name,
                "level": self.level,
                "child_count": self.children.count(),
                "action": "income_category_validation",
                "component": "IncomeCategory",
            },
        )

    def __str__(self):
        """
        String representation of IncomeCategory.
        """
        return f"{self.name} (Level {self.level})"

# -------------------------------------------------------------------
# CATEGORY PROPERTIES
# -------------------------------------------------------------------
# Additional properties and constraints for categories


class BaseCategoryProperty(models.Model):
    """
    Abstract base model for category properties.
    
    Provides common fields and methods for both expense and income
    category property models.
    """
    
    property_type = models.CharField(max_length=10)
    
    class Meta:
        abstract = True
    
    def __str__(self):
        """
        String representation of BaseCategoryProperty.
        """
        return f"{self.property_type}"


class ExpenseCategoryProperty(BaseCategoryProperty):
    """
    Property definitions for expense categories.
    
    Defines specific properties and constraints for expense categories
    like cost/expense classification.
    """
    
    PROPERTY_CHOICES = [
        ('cost', 'Only cost'),
        ('expense', 'Only expense'),
    ]
    
    category = models.OneToOneField(
        ExpenseCategory, 
        on_delete=models.CASCADE, 
        related_name='property'
    )
    property_type = models.CharField(max_length=10, choices=PROPERTY_CHOICES)

    class Meta:
        verbose_name_plural = "Expense category properties"

    def __str__(self):
        """
        String representation of ExpenseCategoryProperty.
        """
        return f"{self.category.name} - {self.property_type}"

    def clean(self):
        """
        Validate expense category property data.
        """
        logger.debug(
            "ExpenseCategoryProperty validation completed",
            extra={
                "category_id": self.category.id,
                "property_type": self.property_type,
                "action": "expense_category_property_validation",
                "component": "ExpenseCategoryProperty",
            },
        )


class IncomeCategoryProperty(BaseCategoryProperty):
    """
    Property definitions for income categories.
    
    Defines specific properties and constraints for income categories
    like revenue/income classification.
    """
    
    PROPERTY_CHOICES = [
        ('revenue', 'Only revenue'),
        ('income', 'Only income'),
    ]
    
    category = models.OneToOneField(
        IncomeCategory, 
        on_delete=models.CASCADE, 
        related_name='property'
    )
    property_type = models.CharField(max_length=10, choices=PROPERTY_CHOICES)

    class Meta:
        verbose_name_plural = "Income category properties"

    def __str__(self):
        """
        String representation of IncomeCategoryProperty.
        """
        return f"{self.category.name} - {self.property_type}"

    def clean(self):
        """
        Validate income category property data.
        """
        logger.debug(
            "IncomeCategoryProperty validation completed",
            extra={
                "category_id": self.category.id,
                "property_type": self.property_type,
                "action": "income_category_property_validation",
                "component": "IncomeCategoryProperty",
            },
        )

# -------------------------------------------------------------------
# EXCHANGE RATES
# -------------------------------------------------------------------
# Currency exchange rate storage and management


class ExchangeRate(models.Model):
    """
    Currency exchange rate storage.
    
    Stores historical exchange rates for currency conversion
    with date-based uniqueness constraints.
    """
    
    currency = models.CharField(max_length=3)  # e.g., USD, GBP
    rate_to_eur = models.DecimalField(max_digits=20, decimal_places=6)
    date = models.DateField()

    class Meta:
        unique_together = ('currency', 'date')
        ordering = ['-date']
        verbose_name_plural = "Exchange rates"

    def __str__(self):
        """
        String representation of ExchangeRate.
        """
        return f"{self.currency} - {self.rate_to_eur} ({self.date})"
    
    def clean(self):
        """
        Validate exchange rate data.
        """
        if self.rate_to_eur <= 0:
            logger.warning(
                "Invalid exchange rate - must be positive",
                extra={
                    "currency": self.currency,
                    "rate": float(self.rate_to_eur),
                    "date": self.date.isoformat(),
                    "action": "exchange_rate_validation_failed",
                    "component": "ExchangeRate",
                    "severity": "medium",
                },
            )
            raise ValidationError("Exchange rate must be positive")
        
        # Validate currency format
        if not self.currency or len(self.currency) != 3:
            raise ValidationError("Currency code must be 3 characters long")
        
        logger.debug(
            "ExchangeRate validation completed",
            extra={
                "currency": self.currency,
                "rate": float(self.rate_to_eur),
                "date": self.date.isoformat(),
                "action": "exchange_rate_validation",
                "component": "ExchangeRate",
            },
        )

# -------------------------------------------------------------------
# TRANSACTIONS
# -------------------------------------------------------------------
# Core financial transaction records with currency conversion


class Transaction(models.Model):
    """
    Financial transaction record.
    
    Represents individual financial transactions with currency conversion,
    categorization, and workspace context.
    """
    
    TRANSACTION_TYPES = [
        ('income', 'Income'),
        ('expense', 'Expense'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    expense_category = models.ForeignKey(
        ExpenseCategory, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='expense_transactions'
    )
    income_category = models.ForeignKey(
        IncomeCategory, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='income_transactions'
    )
    original_amount = models.DecimalField(max_digits=20, decimal_places=4)
    original_currency = models.CharField(max_length=3)
    amount_domestic = models.DecimalField(max_digits=20, decimal_places=4)  # Stored in domestic currency
    date = models.DateField()
    month = models.DateField()
    tags = models.JSONField(default=list, blank=True)
    note_manual = models.TextField(blank=True)
    note_auto = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['user', 'month']),
            models.Index(fields=['user', 'type']),
            models.Index(fields=['workspace', 'date']),
        ]
        ordering = ['-date', '-created_at']

    def save(self, *args, **kwargs):
        """
        Save transaction with automatic month calculation and currency conversion.
        """
        # Calculate month from date
        if self.date:
            self.month = self.date.replace(day=1)
        
        # Determine if recalculation is needed
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
        
        # Recalculate domestic amount if needed
        if needs_recalculation:
            logger.debug(
                "Transaction recalculation triggered",
                extra={
                    "transaction_id": self.id if self.id else "new",
                    "needs_recalculation": needs_recalculation,
                    "action": "transaction_recalculation_triggered",
                    "component": "Transaction",
                },
            )
            
            try:
                transactions = recalculate_transactions_domestic_amount([self], self.workspace)
                if transactions and transactions[0].amount_domestic is not None:
                    self.amount_domestic = transactions[0].amount_domestic
                else:
                    self.amount_domestic = self.original_amount
                    
                logger.debug(
                    "Transaction domestic amount recalculated",
                    extra={
                        "transaction_id": self.id if self.id else "new",
                        "original_amount": float(self.original_amount),
                        "domestic_amount": float(self.amount_domestic),
                        "action": "transaction_recalculation_success",
                        "component": "Transaction",
                    },
                )
            except Exception as e:
                logger.error(
                    "Transaction recalculation failed",
                    extra={
                        "transaction_id": self.id if self.id else "new",
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "action": "transaction_recalculation_failed",
                        "component": "Transaction",
                        "severity": "high",
                    },
                    exc_info=True,
                )
                self.amount_domestic = self.original_amount
        
        super().save(*args, **kwargs)
        
    @property
    def category(self):
        """
        Get the associated category regardless of type.
        
        Returns:
            Category: ExpenseCategory or IncomeCategory instance
        """
        return self.expense_category or self.income_category
    
    def clean(self):
        """
        Validate transaction data and business rules.
        """
        # Validate category consistency
        if self.expense_category and self.income_category:
            logger.warning(
                "Transaction validation failed - both categories provided",
                extra={
                    "transaction_id": self.id if self.id else "new",
                    "expense_category_id": self.expense_category.id,
                    "income_category_id": self.income_category.id,
                    "action": "transaction_validation_failed",
                    "component": "Transaction",
                    "severity": "medium",
                },
            )
            raise ValidationError("Transaction can have only one category type")
            
        if not self.expense_category and not self.income_category:
            logger.warning(
                "Transaction validation failed - no category provided",
                extra={
                    "transaction_id": self.id if self.id else "new",
                    "action": "transaction_validation_failed",
                    "component": "Transaction",
                    "severity": "medium",
                },
            )
            raise ValidationError("Transaction must have one category")
        
        # Validate type-category consistency
        if self.type == 'expense' and self.income_category:
            logger.warning(
                "Transaction validation failed - expense with income category",
                extra={
                    "transaction_id": self.id if self.id else "new",
                    "transaction_type": self.type,
                    "income_category_id": self.income_category.id,
                    "action": "transaction_validation_failed",
                    "component": "Transaction",
                    "severity": "medium",
                },
            )
            raise ValidationError("Expense transaction cannot have income category")
            
        if self.type == 'income' and self.expense_category:
            logger.warning(
                "Transaction validation failed - income with expense category",
                extra={
                    "transaction_id": self.id if self.id else "new",
                    "transaction_type": self.type,
                    "expense_category_id": self.expense_category.id,
                    "action": "transaction_validation_failed",
                    "component": "Transaction",
                    "severity": "medium",
                },
            )
            raise ValidationError("Income transaction cannot have expense category")
        
        # Validate amount
        if self.original_amount <= 0:
            logger.warning(
                "Transaction validation failed - invalid amount",
                extra={
                    "transaction_id": self.id if self.id else "new",
                    "original_amount": float(self.original_amount),
                    "action": "transaction_validation_failed",
                    "component": "Transaction",
                    "severity": "medium",
                },
            )
            raise ValidationError("Transaction amount must be positive")
        
        logger.debug(
            "Transaction validation completed successfully",
            extra={
                "transaction_id": self.id if self.id else "new",
                "transaction_type": self.type,
                "original_amount": float(self.original_amount),
                "action": "transaction_validation_success",
                "component": "Transaction",
            },
        )

    def __str__(self):
        """
        String representation of Transaction.
        """
        domestic_currency = getattr(self.workspace.settings, 'domestic_currency', 'EUR')
        return f"{self.user} | {self.type} | {self.amount_domestic} {domestic_currency}"