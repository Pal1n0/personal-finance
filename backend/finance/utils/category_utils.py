"""
Category hierarchy synchronization utilities.

This module provides functions for synchronizing category tree structures
with comprehensive validation, atomic operations, and proper error handling.
"""

import logging
from django.db import transaction
from django.core.exceptions import ValidationError

# Get structured logger for this module
logger = logging.getLogger(__name__)


class CategorySyncError(Exception):
    """
    Custom exception for category synchronization failures.
    
    Provides detailed context about synchronization errors for better
    debugging and user feedback.
    """
    
    def __init__(self, message: str, category_id: int = None, category_name: str = None):
        self.message = message
        self.category_id = category_id
        self.category_name = category_name
        super().__init__(self.message)

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
    - Non-leaf categories (level 1-4) must have children
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
    logger.debug(
        "Starting flexible category hierarchy validation",
        extra={
            "create_count": len(categories_data.get('create', [])),
            "update_count": len(categories_data.get('update', [])),
            "delete_count": len(categories_data.get('delete', [])),
            "version_id": version.id,
            "action": "flexible_hierarchy_validation_start",
            "component": "validate_category_hierarchy",
        },
    )
    
    # 1. BASIC INPUT VALIDATION
    if not isinstance(categories_data, dict):
        raise ValidationError("Categories data must be a dictionary")
    
    # Validate create operations
    for i, item in enumerate(categories_data.get('create', [])):
        if not item.get('name') or len(item['name'].strip()) < 2:
            raise ValidationError(f"Category name must be at least 2 characters long (item {i})")
        
        if item.get('level') not in [1, 2, 3, 4, 5]:
            raise ValidationError(f"Invalid category level {item.get('level')} (item {i})")
        
        if not item.get('temp_id'):
            raise ValidationError(f"Missing temp_id for new category (item {i})")
    
    # Validate update operations
    for i, item in enumerate(categories_data.get('update', [])):
        if not item.get('id'):
            raise ValidationError(f"Missing ID for update operation (item {i})")
        
        if not item.get('name') or len(item['name'].strip()) < 2:
            raise ValidationError(f"Category name must be at least 2 characters long (update item {i})")
        
        if item.get('level') not in [1, 2, 3, 4, 5]:
            raise ValidationError(f"Invalid category level {item.get('level')} (update item {i})")
    
    # Validate delete operations
    if categories_data.get('delete'):
        if not all(isinstance(item_id, int) for item_id in categories_data['delete']):
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
    if categories_data.get('delete'):
        current_categories = current_categories.exclude(id__in=categories_data['delete'])
    
    # Build ID to category mapping
    category_map = {cat.id: cat for cat in current_categories.prefetch_related('children', 'parents')}
    
    # Add/update categories from the sync data
    temp_id_map = {}
    
    # Process new categories
    for item in categories_data.get('create', []):
        mock_category = type('MockCategory', (), {
            'id': f"temp_{item['temp_id']}",
            'name': item['name'],
            'level': item['level'],
            'children': set(),
            'parents': set(),
            'is_temp': True
        })()
        temp_id_map[item['temp_id']] = mock_category
        category_map[mock_category.id] = mock_category
    
    # Process updated categories
    for item in categories_data.get('update', []):
        if item['id'] in category_map:
            category_map[item['id']].name = item['name']
            category_map[item['id']].level = item['level']
    
    # 3. BUILD RELATIONSHIPS IN SIMULATED STRUCTURE
    logger.debug(
        "Building relationships in simulated structure",
        extra={
            "action": "relationship_building_start",
            "component": "validate_category_hierarchy",
        },
    )
    
    # Build relationships for new categories
    for item in categories_data.get('create', []):
        if item.get('parent_temp_id'):
            child = temp_id_map[item['temp_id']]
            parent = temp_id_map.get(item['parent_temp_id'])
            if parent:
                parent.children.add(child)
                child.parents.add(parent)
    
    # Build relationships for updated categories
    for item in categories_data.get('update', []):
        if 'parent_id' in item and item['parent_id']:
            child = category_map.get(item['id'])
            parent = category_map.get(item['parent_id'])
            if child and parent:
                # Clear existing relationships
                for old_parent in list(child.parents):
                    old_parent.children.discard(child)
                child.parents.clear()
                # Add new relationship
                parent.children.add(child)
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
    root_categories = [cat for cat in category_map.values() if not cat.parents]
    
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
    
    # Rule 4: Check for orphaned categories (categories not connected to any structure)
    # In flat structure, all categories are effectively "orphaned" but that's OK
    # We only care about orphaned categories that SHOULD be connected but aren't
    non_leaf_categories = [cat for cat in category_map.values() if cat.level != 5]
    orphaned_non_leaf = [cat for cat in non_leaf_categories if cat not in connected_categories]
    
    if orphaned_non_leaf:
        orphaned_names = [f"'{cat.name}' (L{cat.level})" for cat in orphaned_non_leaf]
        validation_errors.append(
            f"Non-leaf categories without proper connections: {', '.join(orphaned_names)}"
        )
    
    if validation_errors:
        raise ValidationError("; ".join(validation_errors))
    
    # Log successful validation scenarios
    flat_categories = [cat for cat in category_map.values() if cat.level == 5 and not cat.parents]
    hierarchical_categories = [cat for cat in category_map.values() if cat.parents or cat.children]
    
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


def _validate_single_category(category):
    """
    Validate individual category constraints.
    
    Args:
        category: Category to validate
        
    Raises:
        ValidationError: If category constraints are violated
    """
    # Leaf categories (level 5) must have no children
    if category.level == 5 and category.children:
        raise ValidationError(
            f"Leaf category '{category.name}' (level 5) should not have children"
        )
    
    # Non-leaf categories (level 1-4) should have children, but it's not required
    # They can exist without children (partial tree scenario)
    
    # Validate parent-child level relationships if parents exist
    for parent in category.parents:
        if parent.level != category.level - 1:
            raise ValidationError(
                f"Invalid parent level: '{category.name}' (L{category.level}) cannot have "
                f"parent '{parent.name}' (L{parent.level}). Expected parent level {category.level - 1}"
            )


def _validate_branch_flexible(root_category, category_map, visited=None):
    """
    Validate branch structure flexibly - doesn't require full depth to level 5.
    
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
    for child in root_category.children:
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
    Check for circular references in the category structure.
    
    Args:
        category: Current category to check
        visited: Set of visited category IDs
        path: Current path for cycle detection
        
    Raises:
        ValidationError: If circular reference detected
    """
    if path is None:
        path = []
    
    if category.id in visited:
        if category.id in path:
            cycle_path = path[path.index(category.id):] + [category.id]
            raise ValidationError(
                f"Circular reference detected: {' -> '.join(str(id) for id in cycle_path)}"
            )
        return
    
    visited.add(category.id)
    path.append(category.id)
    
    for child in category.children:
        _check_circular_reference(child, visited, path)
    
    path.pop()



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
            - deleted: List of deleted category IDs
            - errors: List of error messages if any
            
    Raises:
        CategorySyncError: If synchronization fails
        ValidationError: If data validation fails
    """
    
    results = {
        'created': [],
        'updated': [], 
        'deleted': [],
        'errors': []
    }
    
    logger.info(
        "Category tree synchronization started",
        extra={
            "version_id": version.id,
            "category_model": category_model.__name__,
            "create_operations": len(categories_data.get('create', [])),
            "update_operations": len(categories_data.get('update', [])),
            "delete_operations": len(categories_data.get('delete', [])),
            "action": "category_sync_start",
            "component": "sync_categories_tree",
        },
    )
    
    try:
        # Pre-validation before transaction
        validate_category_hierarchy(categories_data)
        
        with transaction.atomic():  # ✅ All or nothing transaction
            temp_id_map = {}  # Maps temporary frontend IDs to database IDs
            
            # 1. DELETE OPERATIONS
            if categories_data.get('delete'):
                logger.debug(
                    "Processing category deletions",
                    extra={
                        "delete_ids": categories_data['delete'],
                        "action": "category_deletion_start",
                        "component": "sync_categories_tree",
                    },
                )
                
                # Verify categories exist and belong to the correct version
                existing_ids = category_model.objects.filter(
                    id__in=categories_data['delete'],
                    version=version
                ).values_list('id', flat=True)
                
                invalid_ids = set(categories_data['delete']) - set(existing_ids)
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
                
                # Perform deletion
                deleted_count, _ = category_model.objects.filter(id__in=existing_ids).delete()
                results['deleted'] = list(existing_ids)
                
                logger.info(
                    "Category deletions completed",
                    extra={
                        "deleted_count": deleted_count,
                        "deleted_ids": list(existing_ids),
                        "action": "category_deletion_success",
                        "component": "sync_categories_tree",
                    },
                )
            
            # 2. CREATE OPERATIONS
            if categories_data.get('create'):
                logger.debug(
                    "Processing category creations",
                    extra={
                        "create_count": len(categories_data['create']),
                        "action": "category_creation_start",
                        "component": "sync_categories_tree",
                    },
                )
                
                new_categories = []
                for item in categories_data['create']:
                    category = category_model(
                        name=item['name'].strip(),
                        description=item.get('description', '').strip(),
                        level=item['level'],
                        version=version,
                        is_active=True
                    )
                    new_categories.append(category)
                
                # Bulk create new categories
                category_model.objects.bulk_create(new_categories)
                
                # Build temp_id to database ID mapping
                for i, item in enumerate(categories_data['create']):
                    temp_id_map[item['temp_id']] = new_categories[i].id
                    results['created'].append({
                        'temp_id': item['temp_id'],
                        'id': new_categories[i].id,
                        'name': new_categories[i].name,
                        'level': new_categories[i].level
                    })
                
                logger.info(
                    "Category creations completed",
                    extra={
                        "created_count": len(new_categories),
                        "temp_id_mappings": temp_id_map,
                        "action": "category_creation_success",
                        "component": "sync_categories_tree",
                    },
                )
            
            # 3. UPDATE OPERATIONS
            if categories_data.get('update'):
                logger.debug(
                    "Processing category updates",
                    extra={
                        "update_count": len(categories_data['update']),
                        "action": "category_update_start",
                        "component": "sync_categories_tree",
                    },
                )
                
                updates = []
                update_ids = []
                
                for item in categories_data['update']:
                    try:
                        category = category_model.objects.get(id=item['id'], version=version)
                        category.name = item['name'].strip()
                        category.description = item.get('description', '').strip()
                        category.level = item['level']
                        updates.append(category)
                        update_ids.append(item['id'])
                    except category_model.DoesNotExist:
                        logger.error(
                            "Category not found for update",
                            extra={
                                "category_id": item['id'],
                                "version_id": version.id,
                                "action": "category_update_not_found",
                                "component": "sync_categories_tree",
                                "severity": "high",
                            },
                        )
                        raise CategorySyncError(
                            f"Category not found for update: {item['id']}",
                            category_id=item['id']
                        )
                
                # Bulk update categories
                category_model.objects.bulk_update(updates, ['name', 'description', 'level'])
                results['updated'] = update_ids
                
                logger.info(
                    "Category updates completed",
                    extra={
                        "updated_count": len(updates),
                        "updated_ids": update_ids,
                        "action": "category_update_success",
                        "component": "sync_categories_tree",
                    },
                )
            
            # 4. SET RELATIONSHIPS FOR NEW CATEGORIES
            if categories_data.get('create'):
                logger.debug(
                    "Setting relationships for new categories",
                    extra={
                        "action": "relationship_setup_start",
                        "component": "sync_categories_tree",
                    },
                )
                
                for item in categories_data['create']:
                    if item.get('parent_temp_id'):
                        child_id = temp_id_map[item['temp_id']]
                        parent_id = temp_id_map.get(item['parent_temp_id'])
                        
                        if parent_id:
                            try:
                                child = category_model.objects.get(id=child_id)
                                parent = category_model.objects.get(id=parent_id)
                                parent.children.add(child)
                                
                                logger.debug(
                                    "Parent-child relationship created",
                                    extra={
                                        "parent_id": parent_id,
                                        "child_id": child_id,
                                        "action": "relationship_created",
                                        "component": "sync_categories_tree",
                                    },
                                )
                            except category_model.DoesNotExist as e:
                                logger.error(
                                    "Category not found for relationship setup",
                                    extra={
                                        "parent_id": parent_id,
                                        "child_id": child_id,
                                        "action": "relationship_setup_failed",
                                        "component": "sync_categories_tree",
                                        "severity": "high",
                                    },
                                )
                                raise CategorySyncError(
                                    f"Category not found for relationship: {e}",
                                    category_id=parent_id or child_id
                                )
            
            # 5. SET RELATIONSHIPS FOR UPDATED CATEGORIES
            if categories_data.get('update'):
                logger.debug(
                    "Updating relationships for modified categories",
                    extra={
                        "action": "relationship_update_start",
                        "component": "sync_categories_tree",
                    },
                )
                
                for item in categories_data['update']:
                    if 'parent_id' in item:
                        try:
                            category = category_model.objects.get(id=item['id'], version=version)
                            
                            # Clear old relationships
                            category.parents.clear()
                            
                            # Add new parent if specified
                            if item['parent_id']:
                                parent = category_model.objects.get(id=item['parent_id'], version=version)
                                parent.children.add(category)
                                
                                logger.debug(
                                    "Category relationship updated",
                                    extra={
                                        "category_id": item['id'],
                                        "parent_id": item['parent_id'],
                                        "action": "relationship_updated",
                                        "component": "sync_categories_tree",
                                    },
                                )
                                
                        except category_model.DoesNotExist as e:
                            logger.error(
                                "Category not found for relationship update",
                                extra={
                                    "category_id": item.get('id'),
                                    "parent_id": item.get('parent_id'),
                                    "action": "relationship_update_failed",
                                    "component": "sync_categories_tree",
                                    "severity": "high",
                                },
                            )
                            raise CategorySyncError(
                                f"Category not found for relationship update: {e}",
                                category_id=item.get('id')
                            )
            
            # 6. IDENTIFY AFFECTED CATEGORIES FOR VALIDATION
            affected_category_ids = set()
            
            # Add new categories and their parents
            if categories_data.get('create'):
                for item in categories_data['create']:
                    if item.get('parent_temp_id'):
                        parent_id = temp_id_map.get(item['parent_temp_id'])
                        if parent_id:
                            affected_category_ids.add(parent_id)
            
            # Add updated categories and their parents
            if categories_data.get('update'):
                for item in categories_data['update']:
                    affected_category_ids.add(item['id'])
                    if 'parent_id' in item and item['parent_id']:
                        affected_category_ids.add(item['parent_id'])
            
            # Add parents of deleted categories
            if categories_data.get('delete'):
                deleted_categories = category_model.objects.filter(
                    id__in=categories_data['delete'],
                    version=version
                ).prefetch_related('parents')
                for category in deleted_categories:
                    for parent in category.parents.all():
                        affected_category_ids.add(parent.id)
            
            # 7. VALIDATE AFFECTED CATEGORIES
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
                    id__in=affected_category_ids,
                    version=version
                ).prefetch_related('children')
                
                for category in categories_to_validate:
                    # Levels 2-5 must have at least one child (non-leaf validation)
                    if category.level != 1 and not category.children.exists():
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
                    "created_count": len(results['created']),
                    "updated_count": len(results['updated']),
                    "deleted_count": len(results['deleted']),
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
        results['errors'] = [str(e)]
        return results
        
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
        results['errors'] = [f"Unexpected error: {str(e)}"]
        return results