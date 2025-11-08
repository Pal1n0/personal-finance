"""
Serializers for financial management system models.

This module provides Django REST Framework serializers for all models
with proper validation, error handling, and data transformation.
"""

import logging
from django.conf import settings
from rest_framework import serializers
from rest_framework.exceptions import ValidationError as DRFValidationError

from .mixins import TargetUserMixin, CategoryWorkspaceMixin, WorkspaceMembershipMixin

from .models import (
    Transaction, ExchangeRate, UserSettings, WorkspaceSettings, 
    Workspace, WorkspaceMembership, ExpenseCategoryVersion, 
    IncomeCategoryVersion, ExpenseCategory, IncomeCategory,
    TransactionDraft
)

# Get structured logger for this module
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# USER SETTINGS SERIALIZER
# -------------------------------------------------------------------
# User preferences with field-level security

class UserSettingsSerializer(serializers.ModelSerializer):
    """
    Serializer for user-specific settings.
    
    Handles serialization and validation of user preferences and settings
    with strict field-level security controls.
    """
    
    class Meta:
        model = UserSettings
        fields = ['id', 'user', 'language']
        read_only_fields = ['id', 'user']

    def validate_language(self, value):
        """
        Validate language code format.
        
        Args:
            value: Language code to validate
            
        Returns:
            str: Validated language code
            
        Raises:
            ValidationError: If language code is invalid
        """

        valid_languages = [lang[0] for lang in getattr(settings, 'LANGUAGES', [])]
        
        if value not in valid_languages:
            logger.warning(
                "Invalid language code provided",
                extra={
                    "provided_language": value,
                    "valid_languages": valid_languages,
                    "action": "language_validation_failed",
                    "component": "UserSettingsSerializer",
                    "severity": "low",
                },
            )
            raise serializers.ValidationError(f"Unsupported language. Choose from: {', '.join(valid_languages)}")
        
        return value

# -------------------------------------------------------------------
# WORKSPACE SERIALIZER
# -------------------------------------------------------------------
# Workspace data with membership context and role information

class WorkspaceSerializer(WorkspaceMembershipMixin, serializers.ModelSerializer):
    """
    Serializer for Workspace model with user membership information.
    
    Provides enhanced workspace data including user role context,
    member counts, ownership information, and user permissions for frontend consumption.
    """
    
    owner_username = serializers.CharField(source='owner.username', read_only=True)
    owner_email = serializers.CharField(source='owner.email', read_only=True)
    user_role = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()
    user_permissions = serializers.SerializerMethodField()
    
    class Meta:
        model = Workspace
        fields = [
            'id', 'name', 'description', 'owner', 'owner_username', 'owner_email',
            'user_role', 'member_count', 'is_owner', 'user_permissions',
            'created_at', 'is_active'
        ]
        read_only_fields = ['id', 'owner', 'owner_username', 'owner_email', 'created_at']
    
    def get_user_role(self, obj):
        """
        Get current user's role in this workspace.
        
        Args:
            obj: Workspace instance
            
        Returns:
            str or None: User's role in the workspace
        """
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            role = self._get_membership_for_workspace(obj, request)
        
            if role:
                logger.debug(
                    "User role retrieved from cache",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": obj.id,
                        "user_role": role,
                        "action": "user_role_retrieved_cached",
                        "component": "WorkspaceSerializer",
                    },
                )
                return role
            else:
                logger.warning(
                    "Workspace membership not found in cache",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": obj.id,
                        "action": "workspace_membership_cache_miss",
                        "component": "WorkspaceSerializer",
                        "severity": "low",
                    },
                )
                return None
        return None
        
    def get_member_count(self, obj):
        """
        Get total number of members in the workspace.
        
        Args:
            obj: Workspace instance
            
        Returns:
            int: Number of workspace members
        """
        # Use annotate count if available, otherwise calculate
        if hasattr(obj, 'member_count'):
            count = obj.member_count
        else:
            count = obj.members.count()
        
        logger.debug(
            "Member count calculated for workspace",
            extra={
                "workspace_id": obj.id,
                "member_count": count,
                "action": "member_count_calculated",
                "component": "WorkspaceSerializer",
            },
        )
        
        return count
    
    def get_is_owner(self, obj):
        """
        Check if current user is the owner of the workspace.
        
        Args:
            obj: Workspace instance
            
        Returns:
            bool: True if user is workspace owner
        """
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            is_owner = obj.owner_id == request.user.id
            
            logger.debug(
                "Ownership check completed",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "is_owner": is_owner,
                    "action": "ownership_check_completed",
                    "component": "WorkspaceSerializer",
                },
            )
            
            return is_owner
        return False
    
    def get_user_permissions(self, obj):
        """
        Get detailed user permissions for this workspace.
        
        Calculates comprehensive permissions based on user role and workspace state.
        
        Args:
            obj: Workspace instance
            
        Returns:
            dict: User permissions for this workspace
        """
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return self._get_anonymous_permissions()
        
        user_role = self._get_membership_for_workspace(obj, request)
    
        if user_role:
            permissions = self._calculate_user_permissions(obj, user_role, request.user)
            
            logger.debug(
                "User permissions calculated from cached membership",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "user_role": user_role,
                    "permissions_count": len(permissions),
                    "action": "user_permissions_calculated_cached",
                    "component": "WorkspaceSerializer",
                },
            )
            
            return permissions
        else:
            logger.warning(
                "Workspace membership not found for permissions calculation",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "action": "permissions_calculation_failed_cache",
                    "component": "WorkspaceSerializer",
                    "severity": "low",
                },
            )
            return self._get_anonymous_permissions()
    
    def _calculate_user_permissions(self, workspace, user_role, user):
        """
        Calculate user permissions based on role and workspace state.
        
        Args:
            workspace: Workspace instance
            user_role: User's role in workspace
            user: User instance
            
        Returns:
            dict: Calculated permissions
        """
        is_owner = workspace.owner_id == user.id
        is_admin_owner = user_role in ['admin', 'owner']
        workspace_active = workspace.is_active
        
        permissions = {
            # Basic permissions
            'can_view': workspace_active or is_admin_owner,
            'can_see_inactive': is_admin_owner,
            
            # Workspace management
            'can_edit': is_admin_owner and workspace_active,
            'can_activate': is_admin_owner and not workspace_active,
            'can_deactivate': is_admin_owner and workspace_active,
            'can_soft_delete': is_admin_owner and workspace_active,
            
            # Member management
            'can_manage_members': is_admin_owner and workspace_active,
            'can_invite': is_admin_owner and workspace_active,
            
            # Data management
            'can_create_transactions': user_role in ['editor', 'admin', 'owner'] and workspace_active,
            'can_view_transactions': workspace_active or is_admin_owner,
            
            # Ownership-specific permissions
            'can_hard_delete': is_owner,
            'can_transfer_ownership': is_owner and workspace_active,
        }
        
        return permissions
    
    def _get_anonymous_permissions(self):
        """
        Get permissions for anonymous/unauthenticated users.
        
        Returns:
            dict: Empty permissions for anonymous users
        """
        return {
            'can_view': False,
            'can_see_inactive': False,
            'can_edit': False,
            'can_activate': False,
            'can_deactivate': False,
            'can_soft_delete': False,
            'can_manage_members': False,
            'can_invite': False,
            'can_create_transactions': False,
            'can_view_transactions': False,
            'can_hard_delete': False,
            'can_transfer_ownership': False,
        }
    
    def validate_name(self, value):
        """
        Validate workspace name.
        
        Args:
            value: Workspace name to validate
            
        Returns:
            str: Validated and stripped workspace name
            
        Raises:
            ValidationError: If name is too short or too long
        """
        stripped_value = value.strip()
        
        if len(stripped_value) < 2:
            logger.warning(
                "Workspace name validation failed - too short",
                extra={
                    "provided_name": value,
                    "min_length": 2,
                    "action": "workspace_name_validation_failed",
                    "component": "WorkspaceSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError("Workspace name must be at least 2 characters long.")
        
        if len(stripped_value) > 100:
            logger.warning(
                "Workspace name validation failed - too long",
                extra={
                    "provided_name": value,
                    "max_length": 100,
                    "action": "workspace_name_validation_failed",
                    "component": "WorkspaceSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError("Workspace name must be at most 100 characters long.")
        
        logger.debug(
            "Workspace name validated successfully",
            extra={
                "original_name": value,
                "stripped_name": stripped_value,
                "action": "workspace_name_validation_success",
                "component": "WorkspaceSerializer",
            },
        )
        
        return stripped_value
    
    def create(self, validated_data):
        """
        Create workspace and automatically add owner as admin member.
        
        Args:
            validated_data: Validated workspace data
            
        Returns:
            Workspace: Created workspace instance
        """
        request = self.context.get('request')
        
        logger.info(
            "Workspace creation initiated in serializer",
            extra={
                "user_id": request.user.id if request else None,
                "workspace_name": validated_data.get('name'),
                "action": "workspace_serializer_creation_start",
                "component": "WorkspaceSerializer",
            },
        )
        
        if request and request.user.is_authenticated:
            validated_data['owner'] = request.user
        
        workspace = super().create(validated_data)
        
        # Automatically add owner as admin member
        WorkspaceMembership.objects.create(
            workspace=workspace,
            user=workspace.owner,
            role='admin'
        )
        
        logger.info(
            "Workspace created successfully in serializer",
            extra={
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "owner_id": workspace.owner.id,
                "action": "workspace_serializer_creation_success",
                "component": "WorkspaceSerializer",
            },
        )
        
        return workspace
 
# -------------------------------------------------------------------
# WORKSPACE MEMBERSHIP SERIALIZER
# -------------------------------------------------------------------
# Membership data with role-based permission validation

class WorkspaceMembershipSerializer(serializers.ModelSerializer):
    """
    Serializer for WorkspaceMembership model.
    
    Handles workspace membership data with user and workspace context
    and role-based permission validation.
    """
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    workspace_name = serializers.CharField(source='workspace.name', read_only=True)
    is_workspace_owner = serializers.SerializerMethodField()
    
    class Meta:
        model = WorkspaceMembership
        fields = [
            'id', 'workspace', 'workspace_name', 'user', 'user_username', 
            'user_email', 'role', 'is_workspace_owner', 'joined_at'
        ]
        read_only_fields = ['id', 'workspace', 'user', 'joined_at', 'is_workspace_owner']
    
    def get_is_workspace_owner(self, obj):
        """
        Check if the membership user is the workspace owner.
        
        Args:
            obj: WorkspaceMembership instance
            
        Returns:
            bool: True if user is workspace owner
        """
        return obj.user == obj.workspace.owner
    
    def validate_role(self, value):
        """
        Validate role assignment with permission checks.
        
        Args:
            value: Role to assign
            
        Returns:
            str: Validated role
            
        Raises:
            ValidationError: If permission checks fail
        """
        valid_roles = ['admin', 'editor', 'viewer']
        
        if value not in valid_roles:
            logger.warning(
                "Invalid role provided",
                extra={
                    "provided_role": value,
                    "valid_roles": valid_roles,
                    "action": "role_validation_failed",
                    "component": "WorkspaceMembershipSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(f"Invalid role. Choose from: {', '.join(valid_roles)}")
        
        request = self.context.get('request')
        instance = self.instance
        
        if instance and request:
            # Check if user can change roles (only workspace owners/admins)
            workspace = instance.workspace
            
            try:
                current_user_membership = WorkspaceMembership.objects.get(
                    workspace=workspace, 
                    user=request.user
                )
                
                # Only owners and admins can change roles
                if current_user_membership.role not in ['admin', 'owner']:
                    logger.warning(
                        "Role change permission denied",
                        extra={
                            "user_id": request.user.id,
                            "workspace_id": workspace.id,
                            "user_role": current_user_membership.role,
                            "required_roles": ['admin', 'owner'],
                            "action": "role_change_permission_denied",
                            "component": "WorkspaceMembershipSerializer",
                            "severity": "medium",
                        },
                    )
                    raise serializers.ValidationError("You don't have permission to change roles.")
                
                # Prevent changing owner's role
                if instance.user == workspace.owner:
                    logger.warning(
                        "Attempt to change owner role blocked",
                        extra={
                            "user_id": request.user.id,
                            "workspace_id": workspace.id,
                            "target_user_id": instance.user.id,
                            "action": "owner_role_change_blocked",
                            "component": "WorkspaceMembershipSerializer",
                            "severity": "high",
                        },
                    )
                    raise serializers.ValidationError("Cannot change owner's role.")
                    
            except WorkspaceMembership.DoesNotExist:
                logger.warning(
                    "Current user membership not found for role validation",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace.id,
                        "action": "current_membership_not_found",
                        "component": "WorkspaceMembershipSerializer",
                        "severity": "medium",
                    },
                )
                raise serializers.ValidationError("You are not a member of this workspace.")
        
        logger.debug(
            "Role validation completed successfully",
            extra={
                "role": value,
                "action": "role_validation_success",
                "component": "WorkspaceMembershipSerializer",
            },
        )
        
        return value
    
# -------------------------------------------------------------------
# WORKSPACE SETTINGS SERIALIZER
# -------------------------------------------------------------------
# Workspace configuration with currency and fiscal settings

class WorkspaceSettingsSerializer(serializers.ModelSerializer):
    """
    Serializer for workspace-specific settings.
    
    Handles workspace configuration including currency, fiscal year settings,
    and display preferences with proper validation.
    """
    
    class Meta:
        model = WorkspaceSettings
        fields = [
            'id', 'workspace', 'domestic_currency', 'fiscal_year_start', 
            'display_mode', 'accounting_mode'
        ]
        read_only_fields = ['id', 'workspace']
    
    def validate_domestic_currency(self, value):
        """
        Validate domestic currency code.
        
        Args:
            value: Currency code to validate
            
        Returns:
            str: Validated currency code
            
        Raises:
            ValidationError: If currency code is invalid
        """
        valid_currencies = ['EUR', 'USD', 'GBP', 'CHF', 'PLN']
        
        if value not in valid_currencies:
            logger.warning(
                "Invalid domestic currency provided",
                extra={
                    "provided_currency": value,
                    "valid_currencies": valid_currencies,
                    "action": "currency_validation_failed",
                    "component": "WorkspaceSettingsSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(f"Invalid currency. Choose from: {', '.join(valid_currencies)}")
        
        return value
    
    def validate_fiscal_year_start(self, value):
        """
        Validate fiscal year start month.
        
        Args:
            value: Month number (1-12)
            
        Returns:
            int: Validated month number
            
        Raises:
            ValidationError: If month is invalid
        """
        if not 1 <= value <= 12:
            logger.warning(
                "Invalid fiscal year start month",
                extra={
                    "provided_month": value,
                    "valid_range": "1-12",
                    "action": "fiscal_month_validation_failed",
                    "component": "WorkspaceSettingsSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError("Fiscal year start must be between 1 and 12.")
        
        return value

# -------------------------------------------------------------------
# CATEGORY VERSION SERIALIZERS
# -------------------------------------------------------------------

class ExpenseCategoryVersionSerializer(serializers.ModelSerializer):
    """
    Serializer for Expense Category Version model.
    
    Handles versioning of expense category hierarchies with audit trail.
    """
    
    class Meta:
        model = ExpenseCategoryVersion
        fields = ['id', 'workspace', 'name', 'description', 'created_by', 'created_at', 'is_active']
        read_only_fields = ['id', 'created_by', 'created_at']


class IncomeCategoryVersionSerializer(serializers.ModelSerializer):
    """
    Serializer for Income Category Version model.
    
    Handles versioning of income category hierarchies with audit trail.
    """
    
    class Meta:
        model = IncomeCategoryVersion
        fields = ['id', 'workspace', 'name', 'description', 'created_by', 'created_at', 'is_active']
        read_only_fields = ['id', 'created_by', 'created_at']

# -------------------------------------------------------------------
# CATEGORY SERIALIZERS
# -------------------------------------------------------------------
# Hierarchical category data with relationships

class ExpenseCategorySerializer(CategoryWorkspaceMixin, serializers.ModelSerializer):
    """
    Serializer for Expense Category model.
    
    Provides hierarchical category data with version context and child relationships.
    Includes workspace validation for security during admin impersonation.
    """
    
    version = ExpenseCategoryVersionSerializer(read_only=True)
    children = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    
    class Meta:
        model = ExpenseCategory
        fields = [
            'id', 'name', 'description', 'property', 'level', 'version', 'children', 'is_active'
        ]
        read_only_fields = ['version']  # Prevent direct version modification

    def validate_name(self, value):
        """
        Validate expense category name.
        
        Args:
            value: Category name to validate
            
        Returns:
            str: Validated category name
        """
        stripped_value = value.strip()
        
        if len(stripped_value) < 2:
            raise serializers.ValidationError("Category name must be at least 2 characters long.")
        
        return stripped_value

class IncomeCategorySerializer(CategoryWorkspaceMixin, serializers.ModelSerializer):
    """
    Serializer for Income Category model.
    
    Provides hierarchical category data with version context and child relationships.
    Includes workspace validation for security during admin impersonation.
    """
    
    version = IncomeCategoryVersionSerializer(read_only=True)
    children = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    
    class Meta:
        model = IncomeCategory
        fields = [
            'id', 'name', 'description', 'property', 'level', 'version', 'children', 'is_active'
        ]
        read_only_fields = ['version']  # Prevent direct version modification

    def validate_name(self, value):
        """
        Validate income category name.
        
        Args:
            value: Category name to validate
            
        Returns:
            str: Validated category name
        """
        stripped_value = value.strip()
        
        if len(stripped_value) < 2:
            raise serializers.ValidationError("Category name must be at least 2 characters long.")
        
        return stripped_value

# -------------------------------------------------------------------
# TRANSACTION SERIALIZER
# -------------------------------------------------------------------
# Financial transactions with category validation and currency conversion

class TransactionSerializer(TargetUserMixin, serializers.ModelSerializer):
    """
    Serializer for Transaction model.
    
    Handles financial transaction data with category validation,
    currency conversion, and business rule enforcement.
    """
    
    expense_category = serializers.PrimaryKeyRelatedField(
        queryset=ExpenseCategory.objects.none(),  # Safe - will be set in __init__
        required=False,
        allow_null=True
    )
    income_category = serializers.PrimaryKeyRelatedField(
        queryset=IncomeCategory.objects.none(),  # Safe - will be set in __init__
        required=False, 
        allow_null=True
    )
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'user', 'workspace', 'type', 'expense_category', 'income_category',
            'original_amount', 'original_currency', 'amount_domestic', 'date', 
            'month', 'tags', 'note_manual', 'note_auto', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'workspace', 'amount_domestic', 'month', 
            'created_at', 'updated_at'
        ]

    def __init__(self, *args, **kwargs):
        """
        Initialize serializer with security-enhanced querysets.
        
        Sets up workspace-scoped category querysets to prevent cross-workspace
        access during admin impersonation.
        """
        super().__init__(*args, **kwargs)
        
        # SECURE QUERYSETS: Limited to current workspace
        request = self.context.get('request')
        if request and hasattr(request, 'workspace'):
            workspace = request.workspace
            
            # Use cached category lists if available
            if hasattr(request, '_cached_expense_categories'):
                expense_categories = request._cached_expense_categories
            else:
                expense_categories = ExpenseCategory.objects.filter(
                    version__workspace=workspace,
                    is_active=True
                )
                request._cached_expense_categories = expense_categories
            
            if hasattr(request, '_cached_income_categories'):
                income_categories = request._cached_income_categories
            else:
                income_categories = IncomeCategory.objects.filter(
                    version__workspace=workspace,
                    is_active=True
                )
                request._cached_income_categories = income_categories
            
            self.fields['expense_category'].queryset = expense_categories
            self.fields['income_category'].queryset = income_categories
            
            logger.debug(
                "TransactionSerializer initialized with workspace-scoped categories",
                extra={
                    "workspace_id": workspace.id,
                    "expense_categories_count": self.fields['expense_category'].queryset.count(),
                    "income_categories_count": self.fields['income_category'].queryset.count(),
                    "action": "serializer_initialized_with_workspace_scoping",
                    "component": "TransactionSerializer",
                },
            )
        else:
            logger.warning(
                "TransactionSerializer initialized without workspace context",
                extra={
                    "action": "serializer_initialized_without_workspace",
                    "component": "TransactionSerializer",
                    "severity": "low",
                },
            )

    def validate(self, data):
        """
        Validate transaction data consistency and business rules.
        """
        logger.debug(
            "Transaction validation started",
            extra={
                "transaction_type": data.get('type'),
                "has_expense_category": 'expense_category' in data,
                "has_income_category": 'income_category' in data,
                "action": "transaction_validation_start",
                "component": "TransactionSerializer",
            },
        )
        
        expense_category = data.get('expense_category')
        income_category = data.get('income_category')
        transaction_type = data.get('type')
        
        # Validate category consistency
        if expense_category and income_category:
            logger.warning(
                "Transaction validation failed - both categories provided",
                extra={
                    "expense_category_id": expense_category.id,
                    "income_category_id": income_category.id,
                    "action": "transaction_validation_failed",
                    "component": "TransactionSerializer",
                    "severity": "medium",
                },
            )
            raise DRFValidationError("Transaction can have only one category type")
            
        if not expense_category and not income_category:
            logger.warning(
                "Transaction validation failed - no category provided",
                extra={
                    "action": "transaction_validation_failed",
                    "component": "TransactionSerializer",
                    "severity": "medium",
                },
            )
            raise DRFValidationError("Transaction must have one category")
            
        if transaction_type == 'expense' and income_category:
            logger.warning(
                "Transaction validation failed - expense with income category",
                extra={
                    "transaction_type": transaction_type,
                    "income_category_id": income_category.id,
                    "action": "transaction_validation_failed",
                    "component": "TransactionSerializer",
                    "severity": "medium",
                },
            )
            raise DRFValidationError("Expense transaction cannot have income category")
            
        if transaction_type == 'income' and expense_category:
            logger.warning(
                "Transaction validation failed - income with expense category",
                extra={
                    "transaction_type": transaction_type,
                    "expense_category_id": expense_category.id,
                    "action": "transaction_validation_failed",
                    "component": "TransactionSerializer",
                    "severity": "medium",
                },
            )
            raise DRFValidationError("Income transaction cannot have expense category")
        
        # Additional workspace security validation
        request = self.context.get('request')
        if request and hasattr(request, 'workspace'):
            workspace = request.workspace
            
            # Verify categories belong to correct workspace
            if expense_category and expense_category.version.workspace_id != workspace.id:
                logger.warning(
                    "Security violation attempted - expense category from different workspace",
                    extra={
                        "provided_category_id": expense_category.id,
                        "category_workspace_id": expense_category.version.workspace_id,
                        "target_workspace_id": workspace.id,
                        "action": "cross_workspace_category_access_attempt",
                        "component": "TransactionSerializer",
                        "severity": "high",
                    },
                )
                raise DRFValidationError("Expense category does not belong to this workspace")
                
            if income_category and income_category.version.workspace_id != workspace.id:
                logger.warning(
                    "Security violation attempted - income category from different workspace",
                    extra={
                        "provided_category_id": income_category.id,
                        "category_workspace_id": income_category.version.workspace_id,
                        "target_workspace_id": workspace.id,
                        "action": "cross_workspace_category_access_attempt",
                        "component": "TransactionSerializer",
                        "severity": "high",
                    },
                )
                raise DRFValidationError("Income category does not belong to this workspace")
        
        # Validate amount
        original_amount = data.get('original_amount')
        if original_amount is not None and original_amount <= 0:
            logger.warning(
                "Transaction validation failed - invalid amount",
                extra={
                    "original_amount": original_amount,
                    "action": "transaction_validation_failed",
                    "component": "TransactionSerializer",
                    "severity": "medium",
                },
            )
            raise DRFValidationError("Transaction amount must be positive")
        
        logger.debug(
            "Transaction validation completed successfully",
            extra={
                "action": "transaction_validation_success",
                "component": "TransactionSerializer",
            },
        )
        
        return data

    def validate_original_currency(self, value):
        """
        Validate original currency code.
        """
        valid_currencies = ['EUR', 'USD', 'GBP', 'CHF', 'PLN', 'CZK']
        
        if value not in valid_currencies:
            logger.warning(
                "Invalid transaction currency provided",
                extra={
                    "provided_currency": value,
                    "valid_currencies": valid_currencies,
                    "action": "currency_validation_failed",
                    "component": "TransactionSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(f"Invalid currency. Choose from: {', '.join(valid_currencies)}")
        
        return value

# -------------------------------------------------------------------
# TRANSACTION LIST SERIALIZER
# -------------------------------------------------------------------
# Only for get requests lightweight

class TransactionListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for transaction list view - read-only optimized for performance.
    
    Provides minimal data for transaction listings with optimized database queries.
    Used exclusively for list views to improve API response times and reduce payload size.
    
    Performance Features:
    - Minimal field selection to reduce data transfer
    - Read-only fields to prevent accidental writes
    - Optimized category name retrieval without expensive joins
    """
    
    workspace_name = serializers.CharField(source='workspace.name', read_only=True)
    category_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'type', 'expense_category', 'income_category', 'amount_domestic', 'original_amount', 'original_currency',
            'date', 'month', 'workspace', 'note_manual', 'note_auto', 'tags'
        ]
        read_only_fields = fields  # All fields are read-only for list view

    def get_category_name(self, obj):
        """
        Get category name without expensive database joins.
        
        Uses category IDs instead of full object relations to avoid N+1 queries
        and reduce database load. Frontend can fetch full category details if needed.
        
        Args:
            obj: Transaction instance
            
        Returns:
            str: Formatted category name or None
        """
        if obj.expense_category_id:
            logger.debug(
                "Retrieved expense category name from ID",
                extra={
                    "transaction_id": obj.id,
                    "expense_category_id": obj.expense_category_id,
                    "action": "category_name_retrieval",
                    "component": "TransactionListSerializer",
                },
            )
            return f"Expense Category #{obj.expense_category_id}"
        elif obj.income_category_id:
            logger.debug(
                "Retrieved income category name from ID", 
                extra={
                    "transaction_id": obj.id,
                    "income_category_id": obj.income_category_id,
                    "action": "category_name_retrieval",
                    "component": "TransactionListSerializer",
                },
            )
            return f"Income Category #{obj.income_category_id}"
        
        logger.debug(
            "No category found for transaction",
            extra={
                "transaction_id": obj.id,
                "action": "category_name_not_found",
                "component": "TransactionListSerializer",
            },
        )
        return None

# -------------------------------------------------------------------
# EXCHANGE RATE SERIALIZER
# -------------------------------------------------------------------
# Currency exchange rates with validation

class ExchangeRateSerializer(serializers.ModelSerializer):
    """
    Serializer for Exchange Rate model.
    
    Handles currency exchange rate data with validation and date consistency checks.
    """
    
    class Meta:
        model = ExchangeRate
        fields = ['id', 'currency', 'rate_to_eur', 'date']
    
    def validate_currency(self, value):
        """
        Validate currency code.
        
        Args:
            value: Currency code to validate
            
        Returns:
            str: Validated currency code
        """
        valid_currencies = ['EUR', 'USD', 'GBP', 'CHF', 'PLN', 'CZK']
        
        if value not in valid_currencies:
            logger.warning(
                "Invalid exchange rate currency provided",
                extra={
                    "provided_currency": value,
                    "valid_currencies": valid_currencies,
                    "action": "exchange_rate_currency_validation_failed",
                    "component": "ExchangeRateSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(f"Invalid currency. Choose from: {', '.join(valid_currencies)}")
        
        return value
    
    def validate_rate_to_eur(self, value):
        """
        Validate exchange rate value.
        
        Args:
            value: Exchange rate to validate
            
        Returns:
            Decimal: Validated exchange rate
            
        Raises:
            ValidationError: If rate is invalid
        """
        if value <= 0:
            logger.warning(
                "Invalid exchange rate value",
                extra={
                    "provided_rate": value,
                    "action": "exchange_rate_validation_failed",
                    "component": "ExchangeRateSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError("Exchange rate must be positive")
        
        return value

# -------------------------------------------------------------------
# TRANSACTION DRAFT SERIALIZER
# -------------------------------------------------------------------
# Serializer for transaction draft data

class TransactionDraftSerializer(TargetUserMixin, serializers.ModelSerializer):
    """
    Serializer for Transaction Draft model.
    """
    transactions_count = serializers.SerializerMethodField()
    
    class Meta:
        model = TransactionDraft
        fields = [
            'id', 'user', 'workspace', 'draft_type', 
            'transactions_data', 'transactions_count',
            'last_modified', 'created_at'
        ]
        read_only_fields = ['id', 'user', 'workspace', 'last_modified', 'created_at']

    def get_transactions_count(self, obj):
        """Get number of transactions in draft."""
        return obj.get_transactions_count()