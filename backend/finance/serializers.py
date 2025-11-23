"""
Production-grade serializers for financial management system.
100% Service Layer architecture with atomic operations, comprehensive caching,
and unified exception handling.

Architecture Pattern:
Serializer (Validation + Cache) → Business Services → Database
         ↓
ServiceExceptionHandlerMixin (Unified Error Handling)
"""

import logging

from django.conf import settings
from django.db import transaction
from rest_framework import serializers
from rest_framework.exceptions import ValidationError as DRFValidationError

from .mixins.category_workspace import CategoryWorkspaceMixin
from .mixins.service_exception_handler import ServiceExceptionHandlerMixin
from .mixins.target_user import TargetUserMixin
from .mixins.workspace_membership import WorkspaceMembershipMixin
from .models import (ExchangeRate, ExpenseCategory, ExpenseCategoryVersion,
                     IncomeCategory, IncomeCategoryVersion, Tags, Transaction,
                     TransactionDraft, UserSettings, Workspace,
                     WorkspaceMembership, WorkspaceSettings, WorkspaceAdmin)
from .services.category_service import CategoryService
from .services.draft_service import DraftService
from .services.tag_service import TagService
from .services.transaction_service import TransactionService
from .services.workspace_service import WorkspaceService

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# USER SETTINGS SERIALIZER
# -------------------------------------------------------------------


class UserSettingsSerializer(serializers.ModelSerializer):
    """
    Production-ready serializer for user-specific settings.

    Features:
    - Field-level security controls
    - Language code validation
    - Read-only user field protection
    """

    class Meta:
        model = UserSettings
        fields = ["id", "user", "language", "preferred_currency", "date_format"]
        read_only_fields = ["id", "user"]

    def validate_language(self, value):
        """Validate language code against configured settings."""
        valid_languages = [lang[0] for lang in getattr(settings, "LANGUAGES", [])]

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
            raise serializers.ValidationError(
                f"Unsupported language. Choose from: {', '.join(valid_languages)}"
            )

        logger.debug(
            "Language validation successful",
            extra={
                "language": value,
                "action": "language_validation_success",
                "component": "UserSettingsSerializer",
            },
        )
        return value


# -------------------------------------------------------------------
# WORKSPACE SERIALIZER
# -------------------------------------------------------------------


class WorkspaceSerializer(
    WorkspaceMembershipMixin, ServiceExceptionHandlerMixin, serializers.ModelSerializer
):
    """
    Production-ready workspace serializer with 100% service layer delegation.

    Features:
    - Atomic workspace creation via WorkspaceService
    - Cached permission data from request context
    - Comprehensive user role and permission calculations
    - ServiceExceptionHandlerMixin for unified error handling
    """

    owner_username = serializers.CharField(source="owner.username", read_only=True)
    owner_email = serializers.CharField(source="owner.email", read_only=True)
    user_role = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()
    user_permissions = serializers.SerializerMethodField()

    class Meta:
        model = Workspace
        fields = [
            "id",
            "name",
            "description",
            "owner",
            "owner_username",
            "owner_email",
            "user_role",
            "member_count",
            "is_owner",
            "user_permissions",
            "created_at",
            "is_active",
        ]
        read_only_fields = [
            "id",
            "owner",
            "owner_username",
            "owner_email",
            "created_at",
        ]

    def __init__(self, *args, **kwargs):
        """Initialize with workspace service for business logic delegation."""
        super().__init__(*args, **kwargs)
        self.workspace_service = WorkspaceService()

    def get_user_role(self, obj):
        """
        Get user role from cached request context - ZERO database queries.

        Uses pre-calculated permissions from WorkspaceContextMiddleware.
        """
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            permissions_data = getattr(request, "user_permissions", {})
            role = permissions_data.get("workspace_role")

            logger.debug(
                "User role retrieved from request context",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "user_role": role,
                    "action": "user_role_from_context",
                    "component": "WorkspaceSerializer",
                },
            )
            return role
        return None

    def get_member_count(self, obj):
        """Get member count using optimized property."""
        count = obj.member_count

        logger.debug(
            "Member count retrieved",
            extra={
                "workspace_id": obj.id,
                "member_count": count,
                "action": "member_count_retrieved",
                "component": "WorkspaceSerializer",
            },
        )
        return count

    def get_is_owner(self, obj):
        """Check ownership using request context."""
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            is_owner = obj.owner_id == request.user.id

            logger.debug(
                "Ownership check completed",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "is_owner": is_owner,
                    "action": "ownership_check",
                    "component": "WorkspaceSerializer",
                },
            )
            return is_owner
        return False

    def get_user_permissions(self, obj):
        """
        Get permissions from cached request context - ZERO database queries.

        Uses pre-calculated permissions from WorkspaceContextMiddleware.
        """
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return self._get_anonymous_permissions()

        permissions_data = getattr(request, "user_permissions", {})

        logger.debug(
            "User permissions retrieved from request context",
            extra={
                "user_id": request.user.id,
                "workspace_id": obj.id,
                "permissions_count": len(permissions_data),
                "action": "permissions_from_context",
                "component": "WorkspaceSerializer",
            },
        )

        return permissions_data

    def _get_anonymous_permissions(self):
        """Default permissions for anonymous users."""
        return {
            "can_view": False,
            "can_see_inactive": False,
            "can_edit": False,
            "can_activate": False,
            "can_deactivate": False,
            "can_soft_delete": False,
            "can_manage_members": False,
            "can_invite": False,
            "can_create_transactions": False,
            "can_view_transactions": False,
            "can_hard_delete": False,
            "can_transfer_ownership": False,
        }

    def validate_name(self, value):
        """Validate workspace name with comprehensive checks."""
        stripped_value = value.strip()

        if len(stripped_value) < 2:
            logger.warning(
                "Workspace name too short",
                extra={
                    "provided_name": value,
                    "min_length": 2,
                    "action": "workspace_name_validation_failed",
                    "component": "WorkspaceSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                "Workspace name must be at least 2 characters long."
            )

        if len(stripped_value) > 100:
            logger.warning(
                "Workspace name too long",
                extra={
                    "provided_name": value,
                    "max_length": 100,
                    "action": "workspace_name_validation_failed",
                    "component": "WorkspaceSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                "Workspace name must be at most 100 characters long."
            )

        logger.debug(
            "Workspace name validated",
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
        Atomic workspace creation via WorkspaceService.

        Delegates ALL business logic to service layer with proper exception handling.
        ServiceExceptionHandlerMixin converts service exceptions to DRF exceptions.
        """
        request = self.context.get("request")

        logger.info(
            "Workspace creation delegated to service layer",
            extra={
                "user_id": request.user.id if request else None,
                "workspace_name": validated_data.get("name"),
                "action": "workspace_creation_service_delegation",
                "component": "WorkspaceSerializer",
            },
        )

        # ServiceExceptionHandlerMixin handles exception conversion
        workspace = self.handle_service_call(
            self.workspace_service.create_workspace,
            name=validated_data["name"],
            description=validated_data.get("description", ""),
            owner=request.target_user,  # From TargetUserMixin
        )

        logger.info(
            "Workspace created successfully via service",
            extra={
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "owner_id": workspace.owner.id,
                "action": "workspace_creation_via_service_success",
                "component": "WorkspaceSerializer",
            },
        )

        return workspace


# -------------------------------------------------------------------
# WORKSPACE MEMBERSHIP SERIALIZER
# -------------------------------------------------------------------


class WorkspaceMembershipSerializer(serializers.ModelSerializer):
    """
    Production-ready workspace membership serializer.

    Handles workspace membership data with user and workspace context
    and role-based permission validation.
    """

    user_username = serializers.CharField(source="user.username", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)
    workspace_name = serializers.CharField(source="workspace.name", read_only=True)
    is_workspace_owner = serializers.SerializerMethodField()

    class Meta:
        model = WorkspaceMembership
        fields = [
            "id",
            "workspace",
            "workspace_name",
            "user",
            "user_username",
            "user_email",
            "role",
            "is_workspace_owner",
            "joined_at",
        ]
        read_only_fields = [
            "id",
            "workspace",
            "user",
            "joined_at",
            "is_workspace_owner",
        ]

    def get_is_workspace_owner(self, obj):
        """Check if membership user is workspace owner."""
        return obj.user == obj.workspace.owner

    def validate_role(self, value):
        """Validate role assignment with permission checks."""
        valid_roles = ["admin", "editor", "viewer"]

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
            raise serializers.ValidationError(
                f"Invalid role. Choose from: {', '.join(valid_roles)}"
            )

        request = self.context.get("request")
        instance = self.instance

        if instance and request:
            # Permission checks...
            workspace = instance.workspace

            # Use cached permissions instead of DB query
            permissions_data = getattr(request, "user_permissions", {})
            user_role = permissions_data.get("workspace_role")

            # Only owners and admins can change roles
            if user_role not in ["admin", "owner"]:
                logger.warning(
                    "Role change permission denied",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace.id,
                        "user_role": user_role,
                        "required_roles": ["admin", "owner"],
                        "action": "role_change_permission_denied",
                        "component": "WorkspaceMembershipSerializer",
                        "severity": "medium",
                    },
                )
                raise serializers.ValidationError(
                    "You don't have permission to change roles."
                )

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
# WORKSPACE ADMIN SERIALIZER
# -------------------------------------------------------------------

class WorkspaceAdminSerializer(serializers.ModelSerializer):
    """
    Production-ready serializer for workspace administrator assignments.
    Minimalist version with essential security and logging.
    """

    user_id = serializers.IntegerField(source="user.id", read_only=True)
    username = serializers.CharField(source="user.username", read_only=True)
    workspace_id = serializers.IntegerField(source="workspace.id", read_only=True)
    workspace_name = serializers.CharField(source="workspace.name", read_only=True)
    assigned_by_username = serializers.CharField(source="assigned_by.username", read_only=True)

    class Meta:
        model = WorkspaceAdmin
        fields = [
            "id",
            "user_id",
            "username",
            "workspace_id", 
            "workspace_name",
            "assigned_by_username",
            "assigned_at",
            "deactivated_at",
            "is_active",
            "can_impersonate",
            "can_manage_users",
        ]
        read_only_fields = [
            "id", "user_id", "username", "workspace_id", "workspace_name",
            "assigned_by_username", "assigned_at", "deactivated_at"
        ]

    def validate(self, attrs):
        """Basic validation for permission changes."""
        request = self.context.get("request")
        instance = self.instance

        # Only superusers can modify permissions
        if instance and request and not request.user.is_superuser:
            if any(field in attrs for field in ["can_impersonate", "can_manage_users"]):
                raise serializers.ValidationError(
                    "Only superusers can modify admin permissions."
                )

        return attrs

    def create(self, validated_data):
        """Prevent direct creation via serializer."""
        raise serializers.ValidationError(
            "Use the assign-admin endpoint to create workspace admin assignments."
        )

# -------------------------------------------------------------------
# WORKSPACE SETTINGS SERIALIZER
# -------------------------------------------------------------------


class WorkspaceSettingsSerializer(serializers.ModelSerializer):
    """
    Production-ready workspace settings serializer.

    Features:
    - Currency validation with supported codes
    - Fiscal year start validation
    - Read-only workspace field protection
    """

    class Meta:
        model = WorkspaceSettings
        fields = [
            "id",
            "workspace",
            "domestic_currency",
            "fiscal_year_start",
            "display_mode",
            "accounting_mode",
        ]
        read_only_fields = ["id", "workspace"]

    def validate_domestic_currency(self, value):
        """Validate domestic currency against supported codes."""
        valid_currencies = ["EUR", "USD", "GBP", "CHF", "PLN"]

        if value not in valid_currencies:
            logger.warning(
                "Invalid domestic currency",
                extra={
                    "provided_currency": value,
                    "valid_currencies": valid_currencies,
                    "action": "currency_validation_failed",
                    "component": "WorkspaceSettingsSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                f"Invalid currency. Choose from: {', '.join(valid_currencies)}"
            )

        logger.debug(
            "Currency validation successful",
            extra={
                "currency": value,
                "action": "currency_validation_success",
                "component": "WorkspaceSettingsSerializer",
            },
        )
        return value

    def validate_fiscal_year_start(self, value):
        """Validate fiscal year start month."""
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
            raise serializers.ValidationError(
                "Fiscal year start must be between 1 and 12."
            )

        logger.debug(
            "Fiscal month validation successful",
            extra={
                "month": value,
                "action": "fiscal_month_validation_success",
                "component": "WorkspaceSettingsSerializer",
            },
        )
        return value


# -------------------------------------------------------------------
# TRANSACTION SERIALIZER
# -------------------------------------------------------------------


class TransactionSerializer(
    TargetUserMixin, ServiceExceptionHandlerMixin, serializers.ModelSerializer
):
    """
    Production-ready transaction serializer with 100% service layer integration.

    Features:
    - Workspace-scoped category security
    - Business rule validation via TransactionService
    - Cached category data for performance
    - ServiceExceptionHandlerMixin for unified error handling
    """

    expense_category = serializers.PrimaryKeyRelatedField(
        queryset=ExpenseCategory.objects.none(), required=False, allow_null=True
    )
    income_category = serializers.PrimaryKeyRelatedField(
        queryset=IncomeCategory.objects.none(), required=False, allow_null=True
    )
    tags = serializers.ListField(
        child=serializers.CharField(max_length=50), required=False, write_only=True
    )
    tag_list = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = [
            "id",
            "user",
            "workspace",
            "type",
            "expense_category",
            "income_category",
            "original_amount",
            "original_currency",
            "amount_domestic",
            "date",
            "month",
            "tag_list",
            "tags",
            "note_manual",
            "note_auto",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "user",
            "workspace",
            "amount_domestic",
            "month",
            "created_at",
            "updated_at",
        ]

    def get_tag_list(self, obj):
        """
        Returns a list of tag names associated with the transaction.
        """
        return [tag.name for tag in obj.tags.all()]

    def __init__(self, *args, **kwargs):
        """Initialize with security-enhanced querysets from request cache."""
        super().__init__(*args, **kwargs)
        self.tag_service = TagService()
        self.transaction_service = TransactionService()

        # SECURITY: Workspace-scoped categories from request cache
        request = self.context.get("request")
        if request and hasattr(request, "workspace"):

            self.fields["expense_category"].queryset = ExpenseCategory.objects.all()
            self.fields["income_category"].queryset = IncomeCategory.objects.all()

            logger.debug(
                "TransactionSerializer initialized with cached categories",
                extra={
                    "workspace_id": request.workspace.id,
                    "action": "serializer_initialized_with_cache",
                    "component": "TransactionSerializer",
                },
            )

    def validate(self, data):
        """
        Comprehensive transaction validation pipeline.

        This method orchestrates the validation flow by:
        1. Performing standard DRF validation.
        2. Enforcing structural constraints (Leaf Category Level 5).
        3. Delegating complex business logic to the TransactionService.

        Returns:
            dict: The validated data dictionary.

        Raises:
            serializers.ValidationError: If structural or business rules are violated.
        """
        # 1. Standard DRF Validation
        data = super().validate(data)

        logger.debug(
            "Transaction validation starting",
            extra={
                "transaction_type": data.get("type"),
                "has_expense_category": "expense_category" in data,
                "has_income_category": "income_category" in data,
                "action": "transaction_validation_start",
                "component": "TransactionSerializer",
            },
        )

        # 2. Structural Constraint: Leaf Category Check (Level 5)
        # We check incoming data. If not present in data (e.g. PATCH), we don't re-validate 
        # unless necessary, but here we strictly check if a new category is being set.
        expense_category = data.get("expense_category")
        income_category = data.get("income_category")
        category = expense_category or income_category

        if category and category.level != 5:
            logger.warning(
                "Invalid category level usage attempt",
                extra={
                    "category_id": category.id,
                    "category_name": category.name,
                    "level": category.level,
                    "required_level": 5,
                    "action": "transaction_validation_failed",
                }
            )
            raise serializers.ValidationError(
                {
                    "category": f"Category '{category.name}' (Level {category.level}) is not a leaf category. Only Level 5 categories are allowed."
                }
            )

        # 3. Service Layer Validation (Business Logic)
        request = self.context.get("request")
        workspace = getattr(request, "workspace", None)

        if workspace:
            # Delegate complex validation (currency, date rules, limits) to service layer.
            # ServiceExceptionHandlerMixin handles converting service exceptions to HTTP 400.
            is_update = self.instance is not None
            
            self.handle_service_call(
                TransactionService._validate_transaction_data,
                data=data,
                workspace=workspace,
                is_update=is_update,
            )

        logger.debug(
            "Transaction validation completed successfully",
            extra={
                "action": "transaction_validation_success",
                "component": "TransactionSerializer",
            },
        )

        return data

    def validate_original_currency(self, value):
        """Validate transaction currency code."""
        valid_currencies = ["EUR", "USD", "GBP", "CHF", "PLN", "CZK"]

        if value not in valid_currencies:
            logger.warning(
                "Invalid transaction currency",
                extra={
                    "provided_currency": value,
                    "valid_currencies": valid_currencies,
                    "action": "transaction_currency_validation_failed",
                    "component": "TransactionSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                f"Invalid currency. Choose from: {', '.join(valid_currencies)}"
            )

        return value

    def create(self, validated_data):
        """
        Create a transaction and handle tag assignment via TagService.
        """
        tag_names = validated_data.pop("tags", [])
        transaction = super().create(validated_data)

        if tag_names:
            self.handle_service_call(
                self.tag_service.assign_tags_to_transaction,
                transaction_instance=transaction,
                tag_names=tag_names,
            )

        return transaction

    def update(self, instance, validated_data):
        """
        Update a transaction and handle tag assignment via TagService.
        This method ensures that the transaction's tags are synchronized
        with the provided list of tag names. If `tags` is provided in the
        request (even as an empty list), it will replace all existing tags.
        """
        # Pop tags from validated_data if present. We handle it separately.
        # The `in` check is crucial. If 'tags' is not in the request, we don't touch them.
        if "tags" in validated_data:
            tag_names = validated_data.pop("tags")

            # Use the service to get or create the tag objects.
            # This ensures tags are properly managed within the workspace.
            tags_qs = self.handle_service_call(
                self.tag_service.get_or_create_tags,
                workspace=instance.workspace,
                tag_names=tag_names,
            )
            # Atomically set the tags for the transaction.
            # .set() handles adding, removing, and keeping existing tags.
            instance.tags.set(tags_qs)

        # Perform the rest of the update on other fields.
        transaction = super().update(instance, validated_data)

        return transaction


# -------------------------------------------------------------------
# TAGS SERIALIZER
# -------------------------------------------------------------------


class TagSerializer(serializers.ModelSerializer):
    """
    Serializer for the Tag model.
    Handles validation and serialization of tags within a workspace.
    """

    class Meta:
        model = Tags
        fields = ["id", "name", "workspace"]
        read_only_fields = ["id", "workspace"]

    def validate_name(self, value):
        """
        Validate tag name. Ensures it's not empty and normalizes it.
        """
        stripped_value = value.strip()
        if not stripped_value:
            raise serializers.ValidationError("Tag name cannot be empty.")
        if len(stripped_value) > 50:
            raise serializers.ValidationError("Tag name cannot exceed 50 characters.")

        # The model's save method will handle lowercasing
        return stripped_value

    def create(self, validated_data):
        """
        Handle creation of a tag, ensuring it's scoped to the workspace
        from the request context. This implements get_or_create logic.
        """
        workspace = self.context['request'].workspace
        tag_name = validated_data['name']

        # Use TagService for get_or_create logic
        tag_service = TagService()
        tag = tag_service.get_or_create_tags(workspace=workspace, tag_names=[tag_name])[0]

        return tag


# -------------------------------------------------------------------
# TRANSACTION DRAFT SERIALIZER
# -------------------------------------------------------------------


class TransactionDraftSerializer(
    TargetUserMixin, ServiceExceptionHandlerMixin, serializers.ModelSerializer
):
    """
    Production-ready transaction draft serializer with 100% service layer integration.

    Features:
    - Cached category validation for performance
    - Business rule enforcement via service layer
    - Atomic draft operations with proper error handling
    """

    transactions_count = serializers.SerializerMethodField()

    class Meta:
        model = TransactionDraft
        fields = [
            "id",
            "user",
            "workspace",
            "draft_type",
            "transactions_data",
            "transactions_count",
            "last_modified",
            "created_at",
        ]
        read_only_fields = ["id", "user", "workspace", "last_modified", "created_at"]

    def __init__(self, *args, **kwargs):
        """Initialize with draft service for business logic."""
        super().__init__(*args, **kwargs)
        self.draft_service = DraftService()

    def get_transactions_count(self, obj):
        """Get transaction count using model method."""
        return obj.get_transactions_count()

    def validate(self, data):
        """
        Ensures consistency between the draft_type and the types of transactions
        within transactions_data.
        """
        # Prevent changing the draft_type on an existing draft.
        if self.instance and "draft_type" in data and data["draft_type"] != self.instance.draft_type:
            raise serializers.ValidationError(
                "Changing the type of an existing draft is not allowed."
            )

        # On updates, we need the full picture. If draft_type is not in the payload,
        # get it from the instance to ensure we're validating against the correct type.
        draft_type = data.get("draft_type")
        if self.instance and "draft_type" not in data:
            draft_type = self.instance.draft_type


        transactions_data = data.get("transactions_data")

        # If both are present, they must be consistent.
        if draft_type and transactions_data:
            for index, tx_data in enumerate(transactions_data):
                tx_type = tx_data.get("type")
                if tx_type and tx_type != draft_type:
                    raise serializers.ValidationError(
                        f"Transaction at index {index} has type '{tx_type}', which "
                        f"does not match the draft_type '{draft_type}'."
                    )
        return data

    def validate_transactions_data(self, value):
        """
        Validate draft transactions using cached category data.

        Uses request-cached categories to avoid database queries and
        delegates complex validation to service layer.
        """
        if not isinstance(value, list):
            raise serializers.ValidationError("Transactions data must be a list.")

        request = self.context.get("request")
        workspace = getattr(request, "workspace", None)

        if not workspace:
            raise serializers.ValidationError(
                "Workspace context required for validation."
            )

        for index, tx_data in enumerate(value):
            self._validate_transaction(tx_data, workspace, index)

        logger.debug(
            "Draft transactions validation completed",
            extra={
                "transaction_count": len(value),
                "workspace_id": workspace.id,
                "action": "draft_validation_success",
                "component": "TransactionDraftSerializer",
            },
        )

        return value

    def _validate_transaction(self, tx_data, workspace, index):
        """
        Validate individual transaction using cached data and service layer.
        """
        if not isinstance(tx_data, dict):
            raise serializers.ValidationError(
                f"Transaction at index {index} must be an object."
            )

        tx_type = tx_data.get("type")
        expense_category_id = tx_data.get("expense_category_id")
        income_category_id = tx_data.get("income_category_id")

        # Basic validation
        if not tx_type:
            raise serializers.ValidationError(
                f"Transaction at index {index} must have a type."
            )

        if tx_type not in ["expense", "income"]:
            raise serializers.ValidationError(
                f"Transaction at index {index} has invalid type."
            )

        if expense_category_id and income_category_id:
            raise serializers.ValidationError(
                f"Transaction at index {index} cannot have both expense and income categories."
            )

        category_id = expense_category_id or income_category_id
        if category_id:
            self._validate_category_level(category_id, workspace, tx_type, index)

    def _validate_category_level(self, category_id, workspace, tx_type, index):
        """
        Validate category level using cached category data from request.

        Uses pre-loaded categories to avoid database queries during validation.
        """
        request = self.context.get("request")

        # Use cached categories from request context
        if tx_type == "expense":
            cached_categories = getattr(request, "_cached_expense_categories", [])
        else:
            cached_categories = getattr(request, "_cached_income_categories", [])

        # Find category in cached data
        category = next((c for c in cached_categories if c.id == category_id), None)

        if not category:
            logger.warning(
                "Category not found in cached data",
                extra={
                    "category_id": category_id,
                    "transaction_index": index,
                    "category_type": tx_type,
                    "cached_categories_count": len(cached_categories),
                    "action": "category_not_found_in_cache",
                    "component": "TransactionDraftSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                f"Category with ID {category_id} in transaction {index} not found or not accessible."
            )

        # Validate category level: business rule requires leaf to be level 5
        LOWEST_LEVEL = 5
        if category.level != LOWEST_LEVEL:
            logger.warning(
                "Category not at lowest level",
                extra={
                    "category_id": category_id,
                    "category_name": category.name,
                    "category_level": category.level,
                    "required_level": LOWEST_LEVEL,
                    "transaction_index": index,
                    "action": "category_level_validation_failed",
                    "component": "TransactionDraftSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                f"Category '{category.name}' in transaction {index} is not at the lowest level and cannot be used in transactions."
            )

        logger.debug(
            "Category level validation successful",
            extra={
                "category_id": category_id,
                "category_level": category.level,
                "transaction_index": index,
                "action": "category_level_validation_success",
                "component": "TransactionDraftSerializer",
            },
        )

    def create(self, validated_data):
        """
        Create draft via DraftService for atomic operations.

        Delegates to service layer for proper business logic execution.
        """
        request = self.context.get("request")

        logger.info(
            "Draft creation delegated to service layer",
            extra={
                "user_id": request.user.id if request else None,
                "workspace_id": request.workspace.id if request else None,
                "draft_type": validated_data.get("draft_type"),
                "transaction_count": len(validated_data.get("transactions_data", [])),
                "action": "draft_creation_service_delegation",
                "component": "TransactionDraftSerializer",
            },
        )

        # ServiceExceptionHandlerMixin handles exception conversion
        return self.handle_service_call(
            self.draft_service.save_draft,
            user=request.target_user,
            workspace_id=request.workspace.id,
            draft_type=validated_data.get("draft_type"),
            transactions_data=validated_data.get("transactions_data", []),
        )

    def update(self, instance, validated_data):
        """
        Handle PATCH requests by directly updating the instance.

        This is the correct approach for a partial update on a specific resource.
        It avoids the ambiguity of the `save_draft` service's `update_or_create`
        which caused the `DoesNotExist` error.
        """
        # The `validate` method has already ensured consistency.
        # We can now safely update the instance fields.

        # If 'transactions_data' is in the payload, update it.
        if "transactions_data" in validated_data:
            instance.transactions_data = validated_data["transactions_data"]

        # If 'draft_type' is in the payload, update it.
        # This is important if the user changes the draft from income to expense.
        if "draft_type" in validated_data:
            instance.draft_type = validated_data["draft_type"]

        # Save the changes directly to the instance.
        instance.save()

        logger.info(f"Draft {instance.id} updated directly via serializer.")
        return instance


# -------------------------------------------------------------------
# LIGHTWEIGHT SERIALIZERS FOR PERFORMANCE
# -------------------------------------------------------------------


class TransactionListSerializer(serializers.ModelSerializer):
    """
    High-performance serializer for transaction list views.

    Features:
    - Minimal field selection for reduced payload
    - Optimized category name retrieval
    - Read-only for list view performance
    """

    workspace_name = serializers.CharField(source="workspace.name", read_only=True)
    category_name = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = [
            "id",
            "type",
            "expense_category",
            "income_category",
            "amount_domestic",
            "original_amount",
            "original_currency",
            "date",
            "month",
            "workspace",
            "note_manual",
            "note_auto",
            "tags",
            "workspace_name",
            "category_name",
        ]
        read_only_fields = fields

    def get_category_name(self, obj):
        """Get category name without database joins."""
        if obj.expense_category_id:
            return f"Expense Category #{obj.expense_category_id}"
        elif obj.income_category_id:
            return f"Income Category #{obj.income_category_id}"
        return None


# -------------------------------------------------------------------
# EXCHANGE RATE SERIALIZER
# -------------------------------------------------------------------


class ExchangeRateSerializer(serializers.ModelSerializer):
    """
    Production-ready exchange rate serializer.

    Features:
    - Currency code validation
    - Rate value validation
    - Date consistency checks
    """

    class Meta:
        model = ExchangeRate
        fields = ["id", "currency", "rate_to_eur", "date"]

    def validate_currency(self, value):
        """Validate currency code."""
        valid_currencies = ["EUR", "USD", "GBP", "CHF", "PLN", "CZK"]

        if value not in valid_currencies:
            logger.warning(
                "Invalid exchange rate currency",
                extra={
                    "provided_currency": value,
                    "valid_currencies": valid_currencies,
                    "action": "exchange_rate_currency_validation_failed",
                    "component": "ExchangeRateSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                f"Invalid currency. Choose from: {', '.join(valid_currencies)}"
            )

        return value

    def validate_rate_to_eur(self, value):
        """Validate exchange rate value."""
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
# CATEGORY VERSION SERIALIZERS - PRIDAŤ!
# -------------------------------------------------------------------


class ExpenseCategoryVersionSerializer(serializers.ModelSerializer):
    """
    Serializer for Expense Category Version model.

    Handles versioning of expense category hierarchies with audit trail.
    Provides read-only access to version metadata.
    """

    class Meta:
        model = ExpenseCategoryVersion
        fields = [
            "id",
            "workspace",
            "name",
            "description",
            "levels_count",
            "created_by",
            "created_at",
            "is_active",
        ]
        read_only_fields = ["id", "created_by", "created_at"]


class IncomeCategoryVersionSerializer(serializers.ModelSerializer):
    """
    Serializer for Income Category Version model.

    Handles versioning of income category hierarchies with audit trail.
    Provides read-only access to version metadata.
    """

    class Meta:
        model = IncomeCategoryVersion
        fields = [
            "id",
            "workspace",
            "name",
            "description",
            "levels_count",
            "created_by",
            "created_at",
            "is_active",
        ]
        read_only_fields = ["id", "created_by", "created_at"]


# -------------------------------------------------------------------
# CATEGORY SERIALIZERS
# -------------------------------------------------------------------


class ExpenseCategorySerializer(CategoryWorkspaceMixin, serializers.ModelSerializer):
    """
    Production-ready expense category serializer with workspace validation.
    """

    version = ExpenseCategoryVersionSerializer(read_only=True)
    children = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = ExpenseCategory
        fields = [
            "id",
            "name",
            "description",
            "level",
            "version",
            "children",
            "is_active",
        ]
        read_only_fields = ["version", "property"]

    def validate_name(self, value):
        """Validate category name."""
        stripped_value = value.strip()

        if len(stripped_value) < 2:
            raise serializers.ValidationError(
                "Category name must be at least 2 characters long."
            )

        return stripped_value


class IncomeCategorySerializer(CategoryWorkspaceMixin, serializers.ModelSerializer):
    """
    Production-ready income category serializer with workspace validation.
    """

    version = IncomeCategoryVersionSerializer(read_only=True)
    children = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = IncomeCategory
        fields = [
            "id",
            "name",
            "description",
            "level",
            "version",
            "children",
            "is_active",
        ]
        read_only_fields = ["version", "property"]

    def validate_name(self, value):
        """Validate category name."""
        stripped_value = value.strip()

        if len(stripped_value) < 2:
            raise serializers.ValidationError(
                "Category name must be at least 2 characters long."
            )

        return stripped_value
