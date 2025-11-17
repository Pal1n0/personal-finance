"""
Production-grade category service for hierarchical category management.
Handles category synchronization, validation, and workspace-scoped operations
with comprehensive security validation and audit logging.
"""

import logging

from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from rest_framework.exceptions import PermissionDenied

from ..models import (ExpenseCategory, ExpenseCategoryVersion, IncomeCategory,
                      IncomeCategoryVersion, Transaction)
from ..utils.category_utils import (check_category_usage, sync_categories_tree,
                                    validate_category_hierarchy)

logger = logging.getLogger(__name__)


class CategoryService:
    """
    High-performance category management service.
    Provides atomic operations for category hierarchies with workspace validation.
    """

    @transaction.atomic
    def sync_categories_tree(
        self, categories_data: list, version, category_model
    ) -> dict:
        """
        Atomically synchronize category hierarchy for specific version.

        Wrapper around existing sync_categories_tree function with service-level logging
        and error handling.

        Args:
            categories_data: List of category data dictionaries
            version: CategoryVersion instance (ExpenseCategoryVersion or IncomeCategoryVersion)
            category_model: Category model class (ExpenseCategory or IncomeCategory)

        Returns:
            dict: Synchronization results with created, updated, deleted counts

        Raises:
            ValidationError: If category data is invalid
            PermissionDenied: If user cannot modify categories
            DatabaseError: If database operation fails
        """
        logger.info(
            "Category tree synchronization initiated via service",
            extra={
                "version_id": version.id,
                "workspace_id": version.workspace.id,
                "category_type": category_model.__name__,
                "category_count": len(categories_data),
                "action": "category_sync_service_start",
                "component": "CategoryService",
            },
        )

        try:
            # Use existing sync function
            results = sync_categories_tree(categories_data, version, category_model)

            logger.info(
                "Category tree synchronization completed via service",
                extra={
                    "version_id": version.id,
                    "workspace_id": version.workspace.id,
                    "results": results,
                    "action": "category_sync_service_success",
                    "component": "CategoryService",
                },
            )

            return results

        except ValidationError as e:
            logger.warning(
                "Category tree synchronization validation failed",
                extra={
                    "version_id": version.id,
                    "workspace_id": version.workspace.id,
                    "error_message": str(e),
                    "action": "category_sync_validation_failed",
                    "component": "CategoryService",
                    "severity": "medium",
                },
            )
            raise
        except Exception as e:
            logger.error(
                "Category tree synchronization failed unexpectedly",
                extra={
                    "version_id": version.id,
                    "workspace_id": version.workspace.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "category_sync_service_failed",
                    "component": "CategoryService",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise

    def validate_category_usage(self, category) -> dict:
        """
        Check if category is used in transactions and determine move restrictions.

        Enhanced version with comprehensive usage analysis and move restrictions.

        Args:
            category: Category instance to check

        Returns:
            dict: Usage information and move restrictions
        """
        logger.debug(
            "Checking category usage in transactions via service",
            extra={
                "category_id": category.id,
                "category_name": category.name,
                "category_level": category.level,
                "action": "category_usage_check_service",
                "component": "CategoryService",
            },
        )

        try:
            # Use existing check function
            is_used = check_category_usage(category.id, type(category))

            # Enhanced move restriction analysis
            can_be_moved = (
                not is_used or category.level != 5
            )  # Non-leaf or unused leaf can be moved

            move_restrictions = {
                "reason": (
                    "Used in transactions"
                    if is_used and category.level == 5
                    else "None"
                ),
                "requires_confirmation": category.level != 5
                and not is_used,  # Non-leaf categories need confirmation
                "transaction_count": (
                    self._get_category_transaction_count(category) if is_used else 0
                ),
            }

            result = {
                "category_id": category.id,
                "category_name": category.name,
                "level": category.level,
                "is_used": is_used,
                "can_be_moved": can_be_moved,
                "move_restrictions": move_restrictions,
            }

            logger.info(
                "Category usage check completed via service",
                extra={
                    "category_id": category.id,
                    "is_used": is_used,
                    "can_be_moved": can_be_moved,
                    "action": "category_usage_check_service_completed",
                    "component": "CategoryService",
                },
            )

            return result

        except Exception as e:
            logger.error(
                "Category usage check failed via service",
                extra={
                    "category_id": category.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "category_usage_check_service_failed",
                    "component": "CategoryService",
                    "severity": "medium",
                },
            )
            raise

    def get_categories_for_workspace(self, workspace, category_type: str):
        """
        Get categories for workspace with proper scoping and optimization.

        Args:
            workspace: Workspace instance
            category_type: 'expense' or 'income'

        Returns:
            QuerySet: Filtered categories with prefetched relationships

        Raises:
            ValidationError: If category_type is invalid
        """
        logger.debug(
            "Retrieving categories for workspace via service",
            extra={
                "workspace_id": workspace.id,
                "category_type": category_type,
                "action": "workspace_categories_retrieval_service",
                "component": "CategoryService",
            },
        )

        try:
            if category_type == "expense":
                active_versions = ExpenseCategoryVersion.objects.filter(
                    workspace=workspace, is_active=True
                )
                categories = (
                    ExpenseCategory.objects.filter(version__in=active_versions)
                    .select_related("version")
                    .prefetch_related("property", "children")
                )

            elif category_type == "income":
                active_versions = IncomeCategoryVersion.objects.filter(
                    workspace=workspace, is_active=True
                )
                categories = (
                    IncomeCategory.objects.filter(version__in=active_versions)
                    .select_related("version")
                    .prefetch_related("property", "children")
                )

            else:
                raise ValidationError(
                    'Invalid category type. Must be "expense" or "income".'
                )

            logger.debug(
                "Workspace categories retrieved successfully via service",
                extra={
                    "workspace_id": workspace.id,
                    "category_type": category_type,
                    "categories_count": categories.count(),
                    "action": "workspace_categories_retrieved_service",
                    "component": "CategoryService",
                },
            )

            return categories

        except ValidationError:
            raise
        except Exception as e:
            logger.error(
                "Workspace categories retrieval failed via service",
                extra={
                    "workspace_id": workspace.id,
                    "category_type": category_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_categories_retrieval_service_failed",
                    "component": "CategoryService",
                    "severity": "medium",
                },
            )
            raise

    def get_category_tree_structure(self, workspace, category_type: str) -> list:
        """
        Get hierarchical category tree structure for frontend consumption.

        Args:
            workspace: Workspace instance
            category_type: 'expense' or 'income'

        Returns:
            list: Nested category tree structure
        """
        logger.debug(
            "Building category tree structure via service",
            extra={
                "workspace_id": workspace.id,
                "category_type": category_type,
                "action": "category_tree_build_service_start",
                "component": "CategoryService",
            },
        )

        try:
            categories = self.get_categories_for_workspace(workspace, category_type)

            if not categories.exists():
                logger.debug(
                    "No categories found for workspace",
                    extra={
                        "workspace_id": workspace.id,
                        "category_type": category_type,
                        "action": "category_tree_empty",
                        "component": "CategoryService",
                    },
                )
                return []

            # Build tree structure
            category_dict = {}
            root_categories = []

            # First pass: create all nodes
            for category in categories:
                category_dict[category.id] = {
                    "id": category.id,
                    "name": category.name,
                    "description": category.description,
                    "level": category.level,
                    "is_active": category.is_active,
                    "is_leaf": category.is_leaf,
                    "is_root": category.is_root,
                    "children": [],
                }

            # Second pass: build hierarchy
            for category in categories:
                node = category_dict[category.id]

                # Add to parent's children or to root
                parents = category.parents.all()
                if parents.exists():
                    for parent in parents:
                        if parent.id in category_dict:
                            category_dict[parent.id]["children"].append(node)
                else:
                    root_categories.append(node)

            logger.debug(
                "Category tree structure built successfully via service",
                extra={
                    "workspace_id": workspace.id,
                    "category_type": category_type,
                    "total_categories": len(category_dict),
                    "root_categories": len(root_categories),
                    "action": "category_tree_build_service_success",
                    "component": "CategoryService",
                },
            )

            return root_categories

        except Exception as e:
            logger.error(
                "Category tree structure build failed via service",
                extra={
                    "workspace_id": workspace.id,
                    "category_type": category_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "category_tree_build_service_failed",
                    "component": "CategoryService",
                    "severity": "medium",
                },
            )
            raise

    def validate_category_operations(
        self, workspace, category_type: str, operations_data: dict
    ) -> dict:
        """
        Validate category operations before execution.

        Args:
            workspace: Workspace instance
            category_type: 'expense' or 'income'
            operations_data: Dictionary with create, update, delete operations

        Returns:
            dict: Validation results with warnings and errors
        """
        logger.debug(
            "Validating category operations via service",
            extra={
                "workspace_id": workspace.id,
                "category_type": category_type,
                "operations_count": len(operations_data.get("create", []))
                + len(operations_data.get("update", []))
                + len(operations_data.get("delete", [])),
                "action": "category_operations_validation_service",
                "component": "CategoryService",
            },
        )

        try:
            # Get appropriate version and model

            if category_type == "expense":
                try:
                    version = ExpenseCategoryVersion.objects.get(
                        workspace=workspace, is_active=True
                    )
                except ExpenseCategoryVersion.DoesNotExist:
                    raise ValidationError(
                        "No active expense category version found for workspace"
                    )
                category_model = ExpenseCategory
            else:
                try:
                    version = IncomeCategoryVersion.objects.get(
                        workspace=workspace, is_active=True
                    )
                except IncomeCategoryVersion.DoesNotExist:
                    raise ValidationError(
                        "No active income category version found for workspace"
                    )
                category_model = IncomeCategory

            # Use existing validation function
            validate_category_hierarchy(operations_data, version, category_model)

            # Additional service-level validations
            validation_results = {"is_valid": True, "warnings": [], "errors": []}

            # Check for potential data loss
            delete_ids = operations_data.get("delete", [])
            if delete_ids:
                used_categories = []
                for category_id in delete_ids:
                    if check_category_usage(category_id, category_model):
                        category = category_model.objects.get(id=category_id)
                        used_categories.append(f"'{category.name}' (ID: {category_id})")

                if used_categories:
                    validation_results["warnings"].append(
                        f"Deleting categories used in transactions: {', '.join(used_categories)}"
                    )

            logger.debug(
                "Category operations validation completed via service",
                extra={
                    "workspace_id": workspace.id,
                    "is_valid": validation_results["is_valid"],
                    "warning_count": len(validation_results["warnings"]),
                    "action": "category_operations_validation_service_completed",
                    "component": "CategoryService",
                },
            )

            return validation_results

        except ValidationError as e:
            logger.warning(
                "Category operations validation failed - business rules",
                extra={
                    "workspace_id": workspace.id,
                    "category_type": category_type,
                    "error_message": str(e),
                    "action": "category_operations_validation_business_failed",
                    "component": "CategoryService",
                    "severity": "medium",
                },
            )
            return {"is_valid": False, "warnings": [], "errors": [str(e)]}

        except Exception as e:
            logger.error(
                "Category operations validation failed via service",
                extra={
                    "workspace_id": workspace.id,
                    "category_type": category_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "category_operations_validation_service_failed",
                    "component": "CategoryService",
                    "severity": "medium",
                },
            )
            raise

    def _get_category_transaction_count(self, category) -> int:
        """
        Get count of transactions using this category.

        Args:
            category: Category instance

        Returns:
            int: Number of transactions using this category
        """
        if isinstance(category, ExpenseCategory):
            return Transaction.objects.filter(expense_category=category).count()
        else:
            return Transaction.objects.filter(income_category=category).count()
