"""
Category hierarchy synchronization utilities.

This module provides functions for synchronizing category tree structures
with comprehensive validation, atomic operations, and proper error handling.
"""

import logging
from contextlib import contextmanager

from django.core.exceptions import ValidationError
from django.db import transaction

from finance.models import Transaction

# Get structured logger for this module
logger = logging.getLogger(__name__)


def check_category_usage(category_id, category_model):
    """
    Check if category is used in any transactions.
    """

    if category_model.__name__ == "ExpenseCategory":
        return Transaction.objects.filter(expense_category_id=category_id).exists()
    elif category_model.__name__ == "IncomeCategory":
        return Transaction.objects.filter(income_category_id=category_id).exists()
    return False


class CategorySyncError(Exception):
    """
    Custom exception for category synchronization failures.

    Provides detailed context about synchronization errors for better
    debugging and user feedback.
    """

    def __init__(
        self, message: str, category_id: int = None, category_name: str = None
    ):
        self.message = message
        self.category_id = category_id
        self.category_name = category_name
        super().__init__(self.message)


def _get_children_count(category):
    """
    Universal method to get children count for both Django models and mock objects.
    It prioritizes simulated children if they exist.
    """
    if hasattr(category, "_simulated_children"):
        return len(category._simulated_children)
    if hasattr(category, "is_temp"):  # It's a mock object
        return len(category.children)
    if hasattr(category.children, "count"):  # It's a real Django object
        return category.children.count()
    return 0


def _get_children_list(category):
    """
    Universal method to get children list for both Django models and mock objects.
    It prioritizes simulated children if they exist.
    """
    if hasattr(category, "_simulated_children"):
        return list(category._simulated_children)
    if hasattr(category, "is_temp"):  # It's a mock object
        return list(category.children)
    if hasattr(category.children, "all"):  # It's a real Django object
        return list(category.children.all())
    return []


def _get_parents_list(category):
    """
    Universal method to get parents list for both Django models and mock objects.
    """
    if hasattr(category, "is_temp"):  # It's a mock object
        return list(category.parents)
    if hasattr(category.parents, "all"):  # It's a real Django object
        return list(category.parents.all())
    return []


def _validate_single_category(category):
    """
    Validate individual category constraints - universal for Django models and mock objects.

    Args:
        category: Category to validate (Django model or mock object)

    Raises:
        ValidationError: If category constraints are violated
    """

    # Determine levels_count and min_level for this category (leaf is always 5)
    levels_count = int(getattr(getattr(category, "version", None), "levels_count", 5))
    min_level = 6 - levels_count

    # Root categories (those with no parents) can be any level, as long as they are not explicitly forced to min_level
    parents = _get_parents_list(category)

    # Check for root-level categories
    if len(parents) == 0:
        # A category with no parents is considered a root.
        # If it's at min_level, it's a true root. If it's higher, it's a root of a sub-hierarchy.
        # No specific parent count validation needed here for roots.
        pass  # This is valid, no error
    elif len(parents) != 1:
        # Non-root categories must have exactly one parent
        raise ValidationError(
            f"Non-root category '{category.name}' (level {category.level}) must have exactly one parent"
        )

    # Leaf categories (level 5) must have no children
    if category.level == 5:
        children_count = _get_children_count(category)
        if children_count > 0:
            raise ValidationError(
                f"Leaf category '{category.name}' (level 5) should not have children"
            )

    # Validate parent-child level relationships if parents exist
    for parent in parents:
        if parent.level != category.level - 1:
            raise ValidationError(
                f"Invalid parent level: '{category.name}' (L{category.level}) cannot have "
                f"parent '{parent.name}' (L{parent.level}). Expected parent level {category.level - 1}"
            )


def _validate_branch_flexible(root_category, category_map, visited=None):
    """
    Validate branch structure flexibly - universal for Django models and mock objects.

    Args:
        root_category: Starting category for the branch
        category_map: Dictionary of all categories
        visited: Set of visited categories

    Returns:
        set: All categories in this branch

    Raises:
        ValidationError: If branch structure is invalid
    """
    if visited is None:
        visited = set()

    if root_category in visited:
        return visited

    visited.add(root_category)

    # Validate this category
    _validate_single_category(root_category)

    # Recursively validate children
    children = _get_children_list(root_category)
    for child in children:
        # Validate level progression
        if child.level != root_category.level + 1:
            raise ValidationError(
                f"Invalid level progression: '{root_category.name}' (L{root_category.level}) -> "
                f"'{child.name}' (L{child.level}). Expected L{root_category.level + 1}"
            )

        _validate_branch_flexible(child, category_map, visited)

    return visited


def _check_circular_reference(category, visited, path=None):
    """
    Check for circular references in the category structure - universal for Django models and mock objects.

    Args:
        category: Current category to check
        visited: Set of visited category IDs
        path: Current path for cycle detection

    Raises:
        ValidationError: If circular reference detected
    """
    if path is None:
        path = []

    # Use a consistent ID for both mock and real objects
    category_id = getattr(category, "id", None)
    if not category_id:
        return

    if category_id in visited:
        if category_id in path:
            cycle_path = path[path.index(category_id) :] + [category_id]
            raise ValidationError(
                f"Circular reference detected: {' -> '.join(str(id) for id in cycle_path)}"
            )
        return

    visited.add(category_id)
    path.append(category_id)

    children = _get_children_list(category)
    for child in children:
        _check_circular_reference(child, visited, path)

    path.pop()


@contextmanager
def temporary_child_getter(new_getter):
    """
    Context manager to temporarily replace the global _get_children_list function.
    """
    global _get_children_list
    original_getter = _get_children_list
    _get_children_list = new_getter
    try:
        yield
    finally:
        _get_children_list = original_getter


def validate_category_hierarchy(categories_data: dict, version, category_model) -> None:
    """
    Validate category hierarchy structure - supports both tree and flat structures.

    Supports multiple scenarios:
    - Flat structure: Only level 5 categories (no hierarchy)
    - Partial tree: Some branches, some flat categories
    - Full tree: Complete hierarchy from root to level 5
    - Mixed: Any combination of the above

    Rules:
    - Leaf categories (level 5) must have no children
    - Non-leaf categories (level 1-4) should have children, but it's not required
    - Level progression must be consistent (+1 only)
    - No circular references
    - All categories must be properly connected

    Args:
        categories_data: Dictionary containing create, update, delete operations
        version: CategoryVersion instance for existing data lookup
        category_model: Category model class for database queries

    Raises:
        ValidationError: If hierarchy validation fails
    """
    # 1. BASIC INPUT VALIDATION
    if not isinstance(categories_data, dict):
        raise ValidationError("Categories data must be a dictionary")

    logger.debug(
        "Starting flexible category hierarchy validation",
        extra={
            "create_count": len(categories_data.get("create", [])),
            "update_count": len(categories_data.get("update", [])),
            "delete_count": len(categories_data.get("delete", [])),
            "version_id": version.id,
            "action": "flexible_hierarchy_validation_start",
            "component": "validate_category_hierarchy",
        },
    )

    # Determine levels_count and minimum root level for this version
    levels_count = int(getattr(version, "levels_count", 5))
    min_level = 6 - levels_count

    # Validate create operations
    for i, item in enumerate(categories_data.get("create", [])):
        if not item.get("name") or len(item["name"].strip()) < 2:
            raise ValidationError(
                f"Category name must be at least 2 characters long (item {i})"
            )

        if item.get("level") not in list(range(min_level, 6)):
            raise ValidationError(
                f"Invalid category level {item.get('level')} (item {i}), expected {min_level}..5"
            )

        if not item.get("temp_id"):
            raise ValidationError(f"Missing temp_id for new category (item {i})")

    # Validate update operations
    for i, item in enumerate(categories_data.get("update", [])):
        if not item.get("id"):
            raise ValidationError(f"Missing ID for update operation (item {i})")

        if not item.get("name") or len(item["name"].strip()) < 2:
            raise ValidationError(
                f"Category name must be at least 2 characters long (update item {i})"
            )

        if item.get("level") not in list(range(min_level, 6)):
            raise ValidationError(
                f"Invalid category level {item.get('level')} (update item {i}), expected {min_level}..5"
            )

    # Validate delete operations
    if categories_data.get("delete"):
        if not all(isinstance(item_id, int) for item_id in categories_data["delete"]):
            raise ValidationError("All delete IDs must be integers")

    # 2. SIMULATE THE FINAL TREE STRUCTURE
    logger.debug(
        "Simulating final category structure after operations",
        extra={
            "action": "structure_simulation_start",
            "component": "validate_category_hierarchy",
        },
    )

    # Get current categories from database (excluding those to be deleted)
    current_categories = category_model.objects.filter(version=version, is_active=True)
    if categories_data.get("delete"):
        current_categories = current_categories.exclude(
            id__in=categories_data["delete"]
        )

    # Build a map of mock objects representing the final state.
    # This completely decouples the validation logic from live Django instances.
    category_map = {
        cat.id: type(
            "MockCategory",
            (),
            {
                "id": cat.id,
                "name": cat.name,
                "level": cat.level,
                "children": set(),
                "parents": set(),
                "is_temp": False,  # Mark as representing a real object
                "original_obj": cat,
            },
        )()
        for cat in current_categories.prefetch_related("parents")
    }

    # Add/update categories from the sync data
    temp_id_map = {}

    # Process new categories - create mock objects with proper structure
    for item in categories_data.get("create", []):
        # Create a proper mock object that mimics Django model behavior
        mock_category = type(
            "MockCategory",
            (),
            {
                "id": f"temp_{item['temp_id']}",
                "name": item["name"],
                "level": item["level"],
                "children": set(),
                "parents": set(),
                "is_temp": True,
                "original_obj": None,
            },
        )()
        temp_id_map[item["temp_id"]] = mock_category
        category_map[mock_category.id] = mock_category

    # Apply attribute updates to existing categories before relationship changes
    for item in categories_data.get("update", []):
        cat_id = item.get("id")
        if cat_id in category_map:
            category_instance = category_map[cat_id]
            if "level" in item:
                category_instance.level = item["level"]
            if "name" in item:
                category_instance.name = item["name"]

    # Build initial parent-child relationships for existing categories in our mock map
    for cat_id, mock_cat in category_map.items():
        if not mock_cat.is_temp:
            original_parents = mock_cat.original_obj.parents.all()
            for parent in original_parents:
                if parent.id in category_map:  # Ensure parent is not being deleted
                    mock_parent = category_map[parent.id]
                    mock_cat.parents.add(mock_parent)
                    mock_parent.children.add(mock_cat)

    # 3. BUILD RELATIONSHIPS IN SIMULATED STRUCTURE
    logger.debug(
        "Building relationships in simulated structure",
        extra={
            "action": "relationship_building_start",
            "component": "validate_category_hierarchy",
        },
    )

    # First, detach all categories that are being moved from their old parents
    for item in categories_data.get("update", []):
        # This covers moving to a new parent or becoming a root (parent_id: null)
        if "parent_id" in item or "parent_temp_id" in item:
            child = category_map.get(item["id"])
            if child:
                # Detach from all current parents in the simulation
                for parent in list(child.parents):
                    parent.children.remove(child)
                child.parents.clear()

    # Now, build all new relationships for both created and updated items
    all_items_with_parents = categories_data.get("create", []) + categories_data.get(
        "update", []
    )

    for item in all_items_with_parents:
        child = None
        parent = None

        # Identify the child object
        if "temp_id" in item:  # It's a new category
            child = temp_id_map.get(item["temp_id"])
        elif "id" in item:  # It's an existing category
            child = category_map.get(item["id"])

        if not child:
            continue

        # Identify the parent object
        parent_id = item.get("parent_id")
        parent_temp_id = item.get("parent_temp_id")

        if parent_id is not None:
            parent = category_map.get(parent_id)
        elif parent_temp_id is not None:
            parent = temp_id_map.get(parent_temp_id)

        # If a parent is found, establish the relationship in our simulated map
        if parent:
            # All objects in our map are mocks, so this is safe.
            parent.children.add(child)
            # Always add the parent to the child's parents set
            child.parents.add(parent)

    # 4. VALIDATE CATEGORY CONSTRAINTS
    logger.debug(
        "Validating category constraints",
        extra={
            "total_categories": len(category_map),
            "action": "constraint_validation_start",
            "component": "validate_category_hierarchy",
        },
    )

    # Track all categories for connection validation
    all_categories = set(category_map.values())
    connected_categories = set()
    validation_errors = []

    # Rule 1: Validate individual category constraints
    for category in category_map.values():
        try:
            _validate_single_category(category)
            connected_categories.add(category)
        except ValidationError as e:
            validation_errors.append(str(e))

    # Rule 2: Validate hierarchical relationships (only if hierarchy exists)
    root_categories = [
        cat for cat in category_map.values() if len(_get_parents_list(cat)) == 0
    ]

    if root_categories:
        # We have some hierarchy - validate branches
        for root in root_categories:
            try:
                branch_categories = _validate_branch_flexible(root, category_map)
                connected_categories.update(branch_categories)
            except ValidationError as e:
                validation_errors.append(str(e))

    # Rule 3: Check for circular references
    for category in category_map.values():
        try:
            _check_circular_reference(category, set())
        except ValidationError as e:
            validation_errors.append(str(e))

    # Rule 4: Check for orphaned non-leaf categories
    non_leaf_categories = [cat for cat in category_map.values() if cat.level != 5]
    orphaned_non_leaf = [
        cat for cat in non_leaf_categories if cat not in connected_categories
    ]
    if orphaned_non_leaf:
        orphaned_names = [f"'{cat.name}' (L{cat.level})" for cat in orphaned_non_leaf]
        validation_errors.append(
            f"Non-leaf categories without proper connections: {', '.join(orphaned_names)}"
        )

    if validation_errors:
        raise ValidationError("; ".join(validation_errors))

    # Log successful validation scenarios
    flat_categories = [
        cat
        for cat in category_map.values()
        if cat.level == 5 and len(_get_parents_list(cat)) == 0
    ]
    hierarchical_categories = [
        cat
        for cat in category_map.values()
        if len(_get_parents_list(cat)) > 0 or len(_get_children_list(cat)) > 0
    ]

    logger.debug(
        "Flexible category hierarchy validation completed successfully",
        extra={
            "total_categories": len(category_map),
            "flat_categories_count": len(flat_categories),
            "hierarchical_categories_count": len(hierarchical_categories),
            "root_categories_count": len(root_categories),
            "validation_scenario": "flat_only" if not root_categories else "mixed",
            "action": "flexible_hierarchy_validation_success",
            "component": "validate_category_hierarchy",
        },
    )


def sync_categories_tree(categories_data: dict, version, category_model) -> dict:
    """
    Synchronize entire category tree from frontend with atomic operations.

    Performs create, update, and delete operations on category hierarchies
    within a single database transaction to ensure data consistency.
    Includes comprehensive validation and relationship management.

    Args:
        categories_data: Dictionary containing category operations:
            - create: List of new categories with temp_id
            - update: List of category updates with id
            - delete: List of category IDs to delete
        version: CategoryVersion instance for version control
        category_model: Category model class (ExpenseCategory or IncomeCategory)

    Returns:
        Dictionary with operation results:
            - created: List of created categories with temp_id to id mapping
            - updated: List of updated category IDs
            - deleted: List of IDs for categories that were hard-deleted
            - deactivated: List of IDs for categories that were soft-deleted (archived)
            - errors: List of error messages if any

    Raises:
        CategorySyncError: If synchronization fails
        ValidationError: If data validation fails
    """

    results = {
        "created": [],
        "updated": [],
        "deleted": [],
        "deactivated": [],
        "errors": [],
    }

    logger.info(
        "Category tree synchronization started",
        extra={
            "version_id": version.id,
            "category_model": category_model.__name__,
            "create_operations": len(categories_data.get("create", [])),
            "update_operations": len(categories_data.get("update", [])),
            "delete_operations": len(categories_data.get("delete", [])),
            "action": "category_sync_start",
            "component": "sync_categories_tree",
        },
    )

    try:
        # Pre-validation before transaction
        validate_category_hierarchy(categories_data, version, category_model)

        # Determine levels_count and min_level for this version (used in later validations)
        levels_count = int(getattr(version, "levels_count", 5))
        min_level = 6 - levels_count

        with transaction.atomic():  # All or nothing transaction
            temp_id_map = {}  # Maps temporary frontend IDs to database IDs

            # 1. DELETE / DEACTIVATE OPERATIONS
            if categories_data.get("delete"):
                logger.debug(
                    "Processing category deletions and deactivations",
                    extra={
                        "delete_ids": categories_data["delete"],
                        "action": "category_deletion_start",
                        "component": "sync_categories_tree",
                    },
                )

                # Verify categories exist and belong to the correct version
                existing_categories = category_model.objects.filter(
                    id__in=categories_data["delete"], version=version
                )
                existing_ids = existing_categories.values_list("id", flat=True)

                invalid_ids = set(categories_data["delete"]) - set(existing_ids)
                if invalid_ids:
                    logger.error(
                        "Invalid category IDs for deletion",
                        extra={
                            "invalid_ids": list(invalid_ids),
                            "valid_ids": list(existing_ids),
                            "action": "category_deletion_validation_failed",
                            "component": "sync_categories_tree",
                            "severity": "high",
                        },
                    )
                    raise ValidationError(f"Invalid IDs for deletion: {invalid_ids}")

                # Separate categories into hard-delete and soft-delete (deactivate) lists
                to_hard_delete_ids = []
                to_soft_delete_ids = []
                used_categories_errors = []
                for category in existing_categories:
                    if check_category_usage(category.id, category_model):
                        # Business Rule: Do not allow deletion (soft or hard) of used categories.
                        # Instead of soft-deleting, raise a validation error.
                        error_msg = f"Category '{category.name}' cannot be deleted because it is used in transactions."
                        used_categories_errors.append(error_msg)
                    else:
                        to_hard_delete_ids.append(category.id)

                if used_categories_errors:
                    raise ValidationError(used_categories_errors)

                # Perform soft-deletes (deactivation)
                if to_soft_delete_ids:
                    deactivated_count = category_model.objects.filter(
                        id__in=to_soft_delete_ids
                    ).update(is_active=False)
                    results["deactivated"] = to_soft_delete_ids
                    logger.info(
                        "Categories deactivated (soft-deleted)",
                        extra={
                            "deactivated_count": deactivated_count,
                            "deactivated_ids": to_soft_delete_ids,
                            "action": "category_deactivation_success",
                            "component": "sync_categories_tree",
                        },
                    )

                # Perform hard-deletes
                if to_hard_delete_ids:
                    deleted_count, _ = category_model.objects.filter(
                        id__in=to_hard_delete_ids
                    ).delete()
                    results["deleted"] = to_hard_delete_ids
                    logger.info(
                        "Unused categories permanently deleted",
                        extra={
                            "deleted_count": deleted_count,
                            "deleted_ids": to_hard_delete_ids,
                            "action": "category_hard_deletion_success",
                            "component": "sync_categories_tree",
                        },
                    )

            # 2. CREATE OPERATIONS (Two-phase approach)
            if categories_data.get("create"):
                # --- PHASE 1: Create all category instances ---
                created_instances = {}  # temp_id -> instance
                for item in categories_data["create"]:
                    category = category_model(
                        name=item["name"].strip(),
                        description=item.get("description", "").strip(),
                        level=item["level"],
                        version=version,
                        is_active=True,
                    )
                    created_instances[item["temp_id"]] = category

                # Bulk create new categories
                category_model.objects.bulk_create(list(created_instances.values()))

                # --- PHASE 2: Build temp_id to database ID mapping and results ---
                for temp_id, instance in created_instances.items():
                    temp_id_map[temp_id] = instance.id
                    results["created"].append(
                        {
                            "temp_id": temp_id,
                            "id": instance.id,
                            "name": instance.name,
                            "level": instance.level,
                        }
                    )

                logger.info(
                    "Category creations completed",
                    extra={
                        "created_count": len(created_instances),
                        "temp_id_mappings": temp_id_map,
                        "action": "category_creation_success",
                        "component": "sync_categories_tree",
                    },
                )

                # --- PHASE 3: Set relationships for newly created categories ---
                logger.debug(
                    "Setting relationships for new categories",
                    extra={
                        "action": "relationship_setup_start",
                        "component": "sync_categories_tree",
                    },
                )
                for item in categories_data["create"]:
                    child_instance = created_instances.get(item["temp_id"])
                    parent_id = item.get("parent_id")
                    parent_temp_id = item.get("parent_temp_id")

                    if child_instance and (parent_id or parent_temp_id):
                        try:
                            parent = None
                            if parent_id:
                                parent = category_model.objects.get(id=parent_id)
                            elif parent_temp_id:
                                real_parent_id = temp_id_map.get(parent_temp_id)
                                if real_parent_id:
                                    parent = category_model.objects.get(
                                        id=real_parent_id
                                    )

                            if parent:
                                parent.children.add(child_instance)

                        except category_model.DoesNotExist as e:
                            logger.error(
                                "Parent category not found for relationship setup",
                                extra={
                                    "parent_id": parent_id,
                                    "parent_temp_id": parent_temp_id,
                                    "child_temp_id": item["temp_id"],
                                    "action": "relationship_setup_failed",
                                    "component": "sync_categories_tree",
                                    "severity": "high",
                                },
                            )
                            raise CategorySyncError(
                                f"Parent category not found for relationship: {e}",
                                category_id=parent_id,
                            )

            # 3. UPDATE OPERATIONS
            if categories_data.get("update"):
                logger.debug(
                    "Processing category updates",
                    extra={
                        "update_count": len(categories_data["update"]),
                        "action": "category_update_start",
                        "component": "sync_categories_tree",
                    },
                )

                # CHECK USAGE FOR CATEGORIES BEING MOVED
                for item in categories_data["update"]:
                    if "parent_id" in item:  # This category is being moved
                        try:
                            category = category_model.objects.get(
                                id=item["id"], version=version
                            )

                            print(
                                f"\n\n[DEBUG] Checking usage for moving category: '{category.name}' (ID: {category.id}, Level: {category.level})"
                            )

                            # Per business rules, only check usage of Level 5 categories in the branch.
                            all_in_branch = category.get_descendants(include_self=True)
                            print(
                                f"[DEBUG] Descendants found: {[f'{c.name} (L{c.level})' for c in all_in_branch]}"
                            )

                            level_5_categories_in_branch = {
                                cat for cat in all_in_branch if cat.level == 5
                            }
                            print(
                                f"[DEBUG] Level 5 categories in branch: {[f'{c.name} (L{c.level})' for c in level_5_categories_in_branch]}"
                            )

                            if not level_5_categories_in_branch:
                                print(
                                    "[DEBUG] No Level 5 categories found in branch. Skipping usage check."
                                )
                                continue

                            level_5_ids = [
                                cat.id for cat in level_5_categories_in_branch
                            ]
                            print(
                                f"[DEBUG] Checking for transactions with these Level 5 category IDs: {level_5_ids}"
                            )

                            # Check if any of the L5 categories in the branch are used, and get the first conflict.
                            if category_model.__name__ == "ExpenseCategory":
                                conflicting_transaction = (
                                    Transaction.objects.filter(
                                        expense_category_id__in=level_5_ids
                                    )
                                    .select_related("expense_category")
                                    .first()
                                )
                            else:  # IncomeCategory
                                conflicting_transaction = (
                                    Transaction.objects.filter(
                                        income_category_id__in=level_5_ids
                                    )
                                    .select_related("income_category")
                                    .first()
                                )

                            print(
                                f"[DEBUG] Conflicting transaction found: {conflicting_transaction}\n\n"
                            )

                            if conflicting_transaction:
                                conflicting_category = conflicting_transaction.category
                                logger.warning(
                                    "Attempt to move a category branch with a used L5 subcategory",
                                    extra={
                                        "category_id": category.id,
                                        "category_name": category.name,
                                        "conflicting_category_id": conflicting_category.id,
                                        "conflicting_category_name": conflicting_category.name,
                                        "action": "category_branch_move_denied_l5_usage",
                                        "component": "sync_categories_tree",
                                        "severity": "medium",
                                    },
                                )
                                raise ValidationError(
                                    f"Cannot move category '{category.name}' because subcategory '{conflicting_category.name}' is used in transactions."
                                )

                        except category_model.DoesNotExist:
                            continue  # Will be caught later in the update process
                updates = []
                update_ids = []

                for item in categories_data["update"]:
                    try:
                        category = category_model.objects.get(
                            id=item["id"], version=version
                        )
                        category.name = item["name"].strip()
                        category.description = item.get("description", "").strip()
                        category.level = item["level"]
                        updates.append(category)
                        update_ids.append(item["id"])
                    except category_model.DoesNotExist:
                        logger.error(
                            "Category not found for update",
                            extra={
                                "category_id": item["id"],
                                "version_id": version.id,
                                "action": "category_update_not_found",
                                "component": "sync_categories_tree",
                                "severity": "high",
                            },
                        )
                        raise CategorySyncError(
                            f"Category not found for update: {item['id']}",
                            category_id=item["id"],
                        )

                # Bulk update categories
                category_model.objects.bulk_update(
                    updates, ["name", "description", "level"]
                )
                results["updated"] = update_ids

                # 4. SET RELATIONSHIPS FOR UPDATED CATEGORIES
                # This must happen AFTER bulk_update and BEFORE final validation.
                logger.debug(
                    "Updating relationships for modified categories",
                    extra={
                        "action": "relationship_update_start",
                        "component": "sync_categories_tree",
                    },
                )

                for item in categories_data["update"]:
                    if "parent_id" in item:
                        try:
                            category = category_model.objects.get(
                                id=item["id"], version=version
                            )
                            # Clear old relationships
                            category.parents.clear()
                            # Add new parent if specified
                            if item["parent_id"]:
                                parent = category_model.objects.get(
                                    id=item["parent_id"], version=version
                                )
                                parent.children.add(category)
                        except category_model.DoesNotExist as e:
                            logger.error(
                                "Category not found for relationship update",
                                extra={
                                    "category_id": item.get("id"),
                                    "parent_id": item.get("parent_id"),
                                    "action": "relationship_update_failed",
                                    "component": "sync_categories_tree",
                                    "severity": "high",
                                },
                            )
                            raise CategorySyncError(
                                f"Category not found for relationship update: {e}",
                                category_id=item.get("id"),
                            )

                logger.info(
                    "Category updates completed",
                    extra={
                        "updated_count": len(updates),
                        "updated_ids": update_ids,
                        "action": "category_update_success",
                        "component": "sync_categories_tree",
                    },
                )

            # 6. IDENTIFY AFFECTED CATEGORIES FOR FINAL VALIDATION
            affected_category_ids = set()

            # Add new categories and their parents
            if categories_data.get("create"):
                for item in categories_data["create"]:
                    if item.get("parent_temp_id"):
                        parent_id = temp_id_map.get(item["parent_temp_id"])
                        if parent_id:
                            affected_category_ids.add(parent_id)

            # Add updated categories and their parents
            if categories_data.get("update"):
                for item in categories_data["update"]:
                    affected_category_ids.add(item["id"])
                    if "parent_id" in item and item["parent_id"]:
                        affected_category_ids.add(item["parent_id"])

            # Add parents of deleted categories
            if categories_data.get("delete"):
                deleted_categories = category_model.objects.filter(
                    id__in=categories_data["delete"], version=version
                ).prefetch_related("parents")
                for category in deleted_categories:
                    for parent in category.parents.all():
                        affected_category_ids.add(parent.id)

            # 7. FINAL VALIDATION OF AFFECTED CATEGORIES
            if affected_category_ids:
                logger.debug(
                    "Validating affected categories",
                    extra={
                        "affected_count": len(affected_category_ids),
                        "action": "affected_validation_start",
                        "component": "sync_categories_tree",
                    },
                )

                categories_to_validate = category_model.objects.filter(
                    id__in=affected_category_ids, version=version
                ).prefetch_related("children")

                for category in categories_to_validate:
                    # Non-leaf must have at least one child (non-leaf validation)
                    if category.level != 5 and not category.children.exists():
                        logger.error(
                            "Category hierarchy validation failed",
                            extra={
                                "category_id": category.id,
                                "category_name": category.name,
                                "category_level": category.level,
                                "action": "hierarchy_validation_failed",
                                "component": "sync_categories_tree",
                                "severity": "high",
                            },
                        )
                        raise ValidationError(
                            f"Category '{category.name}' (level {category.level}) must have at least one child"
                        )

                logger.debug(
                    "Affected categories validation completed",
                    extra={
                        "validated_count": categories_to_validate.count(),
                        "action": "affected_validation_success",
                        "component": "sync_categories_tree",
                    },
                )

            logger.info(
                "Category tree synchronization completed successfully",
                extra={
                    "created_count": len(results["created"]),
                    "updated_count": len(results["updated"]),
                    "deleted_count": len(results["deleted"]),
                    "deactivated_count": len(results["deactivated"]),
                    "action": "category_sync_success",
                    "component": "sync_categories_tree",
                },
            )

            return results

    except (ValidationError, CategorySyncError) as e:
        logger.error(
            "Category synchronization failed with validation error",
            extra={
                "error_type": type(e).__name__,
                "error_message": str(e),
                "action": "category_sync_validation_failed",
                "component": "sync_categories_tree",
                "severity": "high",
            },
        )
        raise  # Re-raise the exception to be handled by the view layer

    except Exception as e:
        logger.error(
            "Category synchronization failed with unexpected error",
            extra={
                "error_type": type(e).__name__,
                "error_message": str(e),
                "action": "category_sync_unexpected_error",
                "component": "sync_categories_tree",
                "severity": "critical",
            },
            exc_info=True,
        )
        results["errors"] = [f"Unexpected error: {str(e)}"]
        return results
