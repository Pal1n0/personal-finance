"""
Database models for financial management system.

This module defines all database models for the financial management application,
including workspaces, transactions, categories, exchange rates, and user settings.
"""

import collections
import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.utils import timezone

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

    # Define choices for currency and date format for consistency
    CURRENCY_CHOICES = [
        ("EUR", "Euro"),
        ("USD", "US Dollar"),
        ("GBP", "British Pound"),
        ("CHF", "Swiss Franc"),
        ("PLN", "Polish Zloty"),
        ("CZK", "Czech Koruna"),
    ]
    DATE_FORMAT_CHOICES = [
        ("DD.MM.YYYY", "DD.MM.YYYY"),
        ("MM/DD/YYYY", "MM/DD/YYYY"),
        ("YYYY-MM-DD", "YYYY-MM-DD"),
    ]
    LANGUAGE_CHOICES = settings.LANGUAGES

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="settings"
    )
    language = models.CharField(max_length=2, choices=LANGUAGE_CHOICES, default="en")
    preferred_currency = models.CharField(
        max_length=3, choices=CURRENCY_CHOICES, default="EUR"
    )
    date_format = models.CharField(
        max_length=10, choices=DATE_FORMAT_CHOICES, default="DD.MM.YYYY"
    )

    class Meta:
        verbose_name_plural = "User settings"

    def __str__(self):
        """String representation of UserSettings."""
        return f"{self.user.username} settings"

    def clean(self):
        """Validate user settings data."""
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
        related_name="owned_workspaces",
        null=False,
        blank=False,
    )
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="WorkspaceMembership",
        through_fields=("workspace", "user"),
        related_name="workspaces",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

        indexes = [
            models.Index(fields=["owner", "is_active"]),
            models.Index(fields=["is_active"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        """String representation of Workspace."""
        return f"{self.name} (Owner: {self.owner.username})"

    def clean(self):
        """Validate workspace data."""
        super().clean()

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
        self._validate_owner_consistency()

    def _validate_owner_consistency(self):
        """Validate that owner has correct role in membership."""
        try:
            owner_membership = WorkspaceMembership.objects.get(
                workspace=self, user=self.owner
            )
            if owner_membership.role != "owner":
                raise ValidationError(
                    {"owner": "Workspace owner must have 'owner' role in membership."}
                )
        except WorkspaceMembership.DoesNotExist:
            raise ValidationError(
                {"owner": "Workspace owner must exist in workspace membership."}
            )

    def save(self, *args, **kwargs):
        """Save workspace and ensure owner synchronization."""
        is_new = self.pk is None
        super().save(*args, **kwargs)
        self._sync_owner_to_membership(is_new)

    @property
    def member_count(self):
        """Get total number of members in workspace."""
        return self.members.count()

    @staticmethod
    def get_user_role_in_workspace(user, workspace):
        """
        Get user's role in workspace considering owner, admin, and regular members.
        """
        try:
            membership = WorkspaceMembership.objects.get(workspace=workspace, user=user)
            return membership.role
        except WorkspaceMembership.DoesNotExist:
            return None

    @staticmethod
    def is_workspace_admin(user, workspace):
        """
        Check if user is workspace admin.

        Args:
            user: User to check
            workspace: Workspace to check

        Returns:
            bool: True if user is workspace admin
        """
        return WorkspaceAdmin.objects.filter(
            user=user, workspace=workspace, is_active=True
        ).exists()

    @transaction.atomic
    def change_owner(self, new_owner, changed_by, old_owner_action="editor"):
        """
        Atomically change workspace owner with configurable old owner handling.

        Args:
            new_owner: User to become the new owner
            changed_by: User initiating the change
            old_owner_action: What to do with old owner - 'editor', 'viewer', or 'remove'

        Raises:
            PermissionError: If user cannot change ownership
            ValidationError: If ownership change is invalid
        """
        # Validate permission to change ownership
        if not self._can_change_ownership(changed_by):
            logger.warning(
                "Workspace ownership change permission denied",
                extra={
                    "workspace_id": self.id,
                    "requested_by_id": changed_by.id,
                    "current_owner_id": self.owner.id,
                    "new_owner_id": new_owner.id,
                    "action": "ownership_change_permission_denied",
                    "component": "Workspace",
                    "severity": "high",
                },
            )
            raise PermissionError("User cannot change workspace ownership.")

        # Validate new owner
        if new_owner == self.owner:
            logger.warning(
                "Workspace ownership change to same owner attempted",
                extra={
                    "workspace_id": self.id,
                    "owner_id": self.owner.id,
                    "action": "ownership_change_same_owner",
                    "component": "Workspace",
                    "severity": "medium",
                },
            )
            raise ValidationError("New owner cannot be the same as current owner.")

        if not self.members.filter(id=new_owner.id).exists():
            logger.warning(
                "Workspace ownership change to non-member attempted",
                extra={
                    "workspace_id": self.id,
                    "new_owner_id": new_owner.id,
                    "action": "ownership_change_non_member",
                    "component": "Workspace",
                    "severity": "medium",
                },
            )
            raise ValidationError("New owner must be a member of the workspace.")

        # Validate old_owner_action
        valid_actions = ["editor", "viewer", "remove"]
        if old_owner_action not in valid_actions:
            logger.warning(
                "Invalid old_owner_action provided",
                extra={
                    "workspace_id": self.id,
                    "old_owner_action": old_owner_action,
                    "valid_actions": valid_actions,
                    "action": "ownership_change_invalid_action",
                    "component": "Workspace",
                    "severity": "medium",
                },
            )
            raise ValidationError(
                f"old_owner_action must be one of: {', '.join(valid_actions)}"
            )

        old_owner = self.owner

        try:
            # CRITICAL: First handle old owner to avoid duplicate owners
            if old_owner_action == "remove":
                # Remove old owner completely from workspace
                WorkspaceMembership.objects.filter(
                    workspace=self, user=old_owner
                ).delete()
                WorkspaceAdmin.objects.filter(workspace=self, user=old_owner).update(
                    is_active=False
                )
                new_role = None
                logger.debug(
                    "Old owner removed from workspace",
                    extra={
                        "workspace_id": self.id,
                        "old_owner_id": old_owner.id,
                        "action": "old_owner_removed",
                        "component": "Workspace",
                    },
                )
            else:  # 'editor' or 'viewer'
                # Change old owner's role to specified role FIRST
                updated_count = WorkspaceMembership.objects.filter(
                    workspace=self, user=old_owner
                ).update(role=old_owner_action)
                new_role = old_owner_action
                logger.debug(
                    "Old owner role updated",
                    extra={
                        "workspace_id": self.id,
                        "old_owner_id": old_owner.id,
                        "new_role": old_owner_action,
                        "updated_count": updated_count,
                        "action": "old_owner_role_updated",
                        "component": "Workspace",
                    },
                )

            # NOW update workspace owner - this will create/update new owner membership
            self.owner = new_owner
            self.save()  # This will trigger _sync_owner_to_membership for NEW owner

            logger.info(
                "Workspace ownership changed successfully",
                extra={
                    "workspace_id": self.id,
                    "old_owner_id": old_owner.id,
                    "new_owner_id": new_owner.id,
                    "changed_by_id": changed_by.id,
                    "old_owner_action": old_owner_action,
                    "old_owner_new_role": new_role,
                    "action": "workspace_ownership_changed",
                    "component": "Workspace",
                },
            )

        except Exception as e:
            logger.error(
                "Workspace ownership change failed",
                extra={
                    "workspace_id": self.id,
                    "old_owner_id": old_owner.id,
                    "new_owner_id": new_owner.id,
                    "error": str(e),
                    "action": "workspace_ownership_change_failed",
                    "component": "Workspace",
                    "severity": "high",
                },
            )
            raise

    def _sync_owner_to_membership(self, is_new):
        """
        Synchronize workspace owner to membership table with constraint safety.
        """
        try:
            # Use update_or_create to handle both new and existing memberships safely
            membership, created = WorkspaceMembership.objects.update_or_create(
                workspace=self, user=self.owner, defaults={"role": "owner"}
            )
            logger.debug(
                "Owner synchronized to membership",
                extra={
                    "workspace_id": self.id,
                    "owner_id": self.owner.id,
                    "is_new_workspace": is_new,
                    "membership_created": created,
                    "existing_role_updated": not created,
                    "previous_role": membership.role if not created else "new",
                    "action": "owner_sync_completed",
                    "component": "Workspace",
                },
            )

        except Exception as e:
            logger.error(
                "Failed to sync owner to membership",
                extra={
                    "workspace_id": self.id,
                    "owner_id": self.owner.id,
                    "error": str(e),
                    "action": "owner_sync_failed",
                    "component": "Workspace",
                    "severity": "high",
                },
            )
            raise

    def _can_change_ownership(self, user):
        """
        Check if user can change workspace ownership.
        """
        # Superusers can always change ownership
        if user.is_superuser:
            return True

        # Current owner can transfer ownership
        if user == self.owner:
            return True

        # Workspace admins can change ownership
        return WorkspaceAdmin.objects.filter(
            user=user, workspace=self, is_active=True, can_manage_users=True
        ).exists()

    def get_all_workspace_users_with_roles(self):
        """
        Get all users with their roles in workspace from membership.

        Returns:
            list: List of user data with roles
        """
        # Get all data from membership in one query
        memberships = WorkspaceMembership.objects.filter(workspace=self).select_related(
            "user"
        )

        users_data = []
        for membership in memberships:
            users_data.append(
                {
                    "user_id": membership.user.id,
                    "username": membership.user.username,
                    "role": membership.role,
                    "is_owner": membership.role == "owner",
                    "is_admin": WorkspaceAdmin.objects.filter(
                        user=membership.user, workspace=self, is_active=True
                    ).exists(),
                    "joined_at": membership.joined_at,
                }
            )

        return users_data


# -------------------------------------------------------------------
# WORKSPACE ADMIN MANAGEMENT
# -------------------------------------------------------------------
# Workspace-level admin assignments with audit trail


class WorkspaceAdmin(models.Model):
    """
    Workspace-level administrator assignments.

    Allows superusers to assign specific users as administrators
    for specific workspaces with comprehensive audit trail.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="workspace_admin_assignments",
    )
    workspace = models.ForeignKey(
        Workspace, on_delete=models.CASCADE, related_name="admin_assignments"
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="assigned_workspace_admins",
    )
    assigned_at = models.DateTimeField(auto_now_add=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)
    deactivated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="deactivated_workspace_admins",
    )
    is_active = models.BooleanField(default=True)

    # Optional: Additional permissions for granular control
    can_impersonate = models.BooleanField(default=True)
    can_manage_users = models.BooleanField(default=True)
    can_manage_categories = models.BooleanField(default=True)
    can_manage_settings = models.BooleanField(default=True)

    class Meta:
        unique_together = ["user", "workspace"]
        verbose_name_plural = "Workspace admins"
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["workspace", "is_active"]),
            models.Index(fields=["assigned_at"]),
        ]
        ordering = ["-assigned_at"]

    def __str__(self):
        """String representation of WorkspaceAdmin."""
        return f"{self.user.username} - Admin of {self.workspace.name}"

    def clean(self):
        """Validate workspace admin assignment data."""
        super().clean()

        # Prevent duplicate active assignments
        if (
            WorkspaceAdmin.objects.filter(
                user=self.user, workspace=self.workspace, is_active=True
            )
            .exclude(pk=self.pk)
            .exists()
        ):
            raise ValidationError("User is already an active admin for this workspace.")

        # Ensure assigned_by is a superuser
        if not self.assigned_by.is_superuser:
            raise ValidationError("Only superusers can assign workspace admins.")

        logger.debug(
            "WorkspaceAdmin validation completed",
            extra={
                "workspace_id": self.workspace.id,
                "user_id": self.user.id,
                "assigned_by_id": self.assigned_by.id,
                "action": "workspace_admin_validation",
                "component": "WorkspaceAdmin",
            },
        )

    @property
    def can_impersonate_users(self):
        """Check if this admin can impersonate users in the workspace."""
        return self.is_active and self.can_impersonate

    def deactivate(self, deactivated_by):
        """Deactivate workspace admin assignment with audit trail."""
        if not deactivated_by.is_superuser:
            raise ValidationError("Only superusers can deactivate workspace admins.")

        self.is_active = False
        self.deactivated_at = timezone.now()
        self.deactivated_by = deactivated_by
        self.save()

        logger.info(
            "Workspace admin deactivated",
            extra={
                "workspace_id": self.workspace.id,
                "user_id": self.user.id,
                "deactivated_by_id": deactivated_by.id,
                "action": "workspace_admin_deactivated",
                "component": "WorkspaceAdmin",
            },
        )


class WorkspaceMembership(models.Model):
    """
    Workspace membership model with role-based permissions.

    Defines the relationship between users and workspaces with specific roles
    that determine access levels and permissions.
    """

    ROLE_CHOICES = [
        ("owner", "Owner"),
        ("editor", "Editor"),
        ("viewer", "Viewer"),
    ]

    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default="viewer")
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["workspace", "user"]
        verbose_name_plural = "Workspace memberships"
        indexes = [
            models.Index(fields=["user", "role"]),
            models.Index(fields=["workspace", "role"]),
            models.Index(fields=["joined_at"]),
        ]

        constraints = [
            models.UniqueConstraint(
                fields=["workspace"],
                condition=models.Q(role="owner"),
                name="unique_owner_per_workspace",
            )
        ]

    def __str__(self):
        """String representation of WorkspaceMembership."""
        return f"{self.user.username} in {self.workspace.name} as {self.role}"

    def clean(self):
        """Validate workspace membership data."""
        super().clean()

        # Prevent duplicate memberships
        if (
            WorkspaceMembership.objects.filter(workspace=self.workspace, user=self.user)
            .exclude(pk=self.pk)
            .exists()
        ):
            raise ValidationError("User is already a member of this workspace.")

        if self.user == self.workspace.owner:
            raise ValidationError(
                "Workspace owner should not be added as a regular membership."
            )

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
        ("EUR", "Euro"),
        ("USD", "US Dollar"),
        ("GBP", "British Pound"),
        ("CHF", "Swiss Franc"),
        ("PLN", "Polish Zloty"),
    ]

    FISCAL_YEAR_START_CHOICES = [
        (1, "January"),
        (2, "February"),
        (3, "March"),
        (4, "April"),
        (5, "May"),
        (6, "June"),
        (7, "July"),
        (8, "August"),
        (9, "September"),
        (10, "October"),
        (11, "November"),
        (12, "December"),
    ]

    DISPLAY_MODE_CHOICES = [
        ("month", "Month only"),
        ("day", "Full date"),
    ]

    workspace = models.OneToOneField(
        Workspace, on_delete=models.CASCADE, related_name="settings"
    )
    domestic_currency = models.CharField(
        max_length=3, choices=CURRENCY_CHOICES, default="EUR"
    )
    fiscal_year_start = models.PositiveSmallIntegerField(
        choices=FISCAL_YEAR_START_CHOICES, default=1
    )
    display_mode = models.CharField(
        max_length=5, choices=DISPLAY_MODE_CHOICES, default="month"
    )
    accounting_mode = models.BooleanField(default=False)

    def __str__(self):
        """String representation of WorkspaceSettings."""
        return f"{self.workspace.name} settings"

    def clean(self):
        """Validate workspace settings data."""
        super().clean()

        if self.fiscal_year_start not in [
            choice[0] for choice in self.FISCAL_YEAR_START_CHOICES
        ]:
            raise ValidationError("Invalid fiscal year start month.")

        logger.debug(
            "WorkspaceSettings validation completed",
            extra={
                "workspace_id": self.workspace.id,
                "domestic_currency": self.domestic_currency,
                "fiscal_year_start": self.fiscal_year_start,
                "accounting_mode": self.accounting_mode,
                "action": "workspace_settings_validation",
                "component": "WorkspaceSettings",
            },
        )


# -------------------------------------------------------------------
# EXPENSE CATEGORIES
# -------------------------------------------------------------------
# Hierarchical expense category system with version control


class CategoryDescendantsMixin:
    """
    A mixin for category models to provide a method for getting all descendants.
    """

    def get_descendants(self, include_self=False):
        """
        Retrieves all descendant categories for a given category instance
        using a breadth-first search (BFS) approach.

        This method traverses the category tree downwards from the current
        category, collecting all children, grandchildren, and so on.

        Args:
            include_self (bool): If True, the instance category will be included
                                 in the result set. Defaults to False.

        Returns:
            set: A set of category instances representing the full descendant tree.
                 Returns an empty set if the category has no children.
        """
        descendants = set()
        if include_self:
            descendants.add(self)

        # --- OPTIMIZATION: Avoid N+1 queries by fetching all relevant categories at once ---

        # 1. Get all categories from the same version in a single query.
        # This is much more efficient than traversing the tree with individual queries.
        all_categories = self.__class__.objects.filter(
            version=self.version
        ).prefetch_related("parents")

        # 2. Build an in-memory map of parent-child relationships.
        # This avoids hitting the database inside the loop.
        children_map = collections.defaultdict(list)
        for category in all_categories:
            for parent in category.parents.all():
                children_map[parent.id].append(category)

        # 3. Use a queue for a breadth-first search (BFS) on the in-memory map.
        queue = collections.deque()
        # Start the queue with the direct children of the current instance from our map.
        queue.extend(children_map.get(self.id, []))

        while queue:
            child = queue.popleft()
            if child not in descendants:
                descendants.add(child)
                # Get the next level of children from our in-memory map, not the database.
                if child.id in children_map:
                    queue.extend(children_map[child.id])

        return descendants


class ExpenseCategoryVersion(models.Model):
    """
    Version control for expense category hierarchies.

    Enables multiple versions of expense category structures for audit trails
    and historical tracking within workspaces.
    """

    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "Expense category versions"
        ordering = ["-created_at"]

    def __str__(self):
        """String representation of ExpenseCategoryVersion."""
        return f"{self.workspace.name} - Expense"

    # Number of levels for this version (1..5). Frontend may change this per-version.
    levels_count = models.PositiveSmallIntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(5)]
    )

    def clean(self):
        """Validate expense category version data."""
        super().clean()

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


class ExpenseCategory(CategoryDescendantsMixin, models.Model):
    """
    Hierarchical expense category structure.

    Represents a tree-like structure for organizing expense categories
    with multiple levels and parent-child relationships.
    """

    LEVEL_CHOICES = [
        (1, "Level 1 - Root"),
        (2, "Level 2"),
        (3, "Level 3"),
        (4, "Level 4"),
        (5, "Level 5 - Leaf"),
    ]

    version = models.ForeignKey(
        ExpenseCategoryVersion, on_delete=models.CASCADE, related_name="categories"
    )
    name = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)
    children = models.ManyToManyField(
        "self", symmetrical=False, related_name="parents", blank=True
    )
    level = models.PositiveIntegerField(choices=LEVEL_CHOICES)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "Expense categories"
        ordering = ["level", "name"]

    @property
    def is_leaf(self):
        """Check if category is a leaf node (has no children)."""
        return not self.children.exists()

    @property
    def is_root(self):
        """Check if category is a root node (has no parents)."""
        return not self.parents.exists()

    def add_child(self, child):
        """Safely add child category with comprehensive validation."""
        # 1. Validate self-reference
        if child.id and child.id == self.id:
            logger.warning(
                "Self-reference attempt blocked",
                extra={
                    "category_id": self.id,
                    "category_name": self.name,
                    "action": "self_reference_blocked",
                    "component": "ExpenseCategory",
                    "severity": "high",
                },
            )
            raise ValidationError("Cannot add category as its own child")

        # 2. Validate existing parent
        if child.parents.exists():
            logger.warning(
                "Attempt to add child with existing parent",
                extra={
                    "parent_id": self.id,
                    "parent_name": self.name,
                    "child_id": child.id,
                    "child_name": child.name,
                    "existing_parents_count": child.parents.count(),
                    "action": "child_addition_failed_existing_parent",
                    "component": "ExpenseCategory",
                    "severity": "medium",
                },
            )
            raise ValidationError(f"Category '{child.name}' already has a parent")

        # 3. Validate circular reference
        if self._is_ancestor_of(child):
            logger.warning(
                "Circular reference attempt blocked",
                extra={
                    "parent_id": self.id,
                    "parent_name": self.name,
                    "child_id": child.id,
                    "child_name": child.name,
                    "action": "circular_reference_blocked",
                    "component": "ExpenseCategory",
                    "severity": "high",
                },
            )
            raise ValidationError(
                "Circular reference detected - cannot create category cycle"
            )

        # 4. Validate level hierarchy
        if child.level <= self.level:
            logger.warning(
                "Invalid level hierarchy attempt",
                extra={
                    "parent_id": self.id,
                    "parent_level": self.level,
                    "child_id": child.id,
                    "child_level": child.level,
                    "action": "invalid_level_hierarchy",
                    "component": "ExpenseCategory",
                    "severity": "medium",
                },
            )
            raise ValidationError("Child category must have higher level than parent")

        # All validations passed - add child
        self.children.add(child)

        logger.debug(
            "Child category added successfully",
            extra={
                "parent_id": self.id,
                "parent_name": self.name,
                "parent_level": self.level,
                "child_id": child.id,
                "child_name": child.name,
                "child_level": child.level,
                "action": "child_addition_success",
                "component": "ExpenseCategory",
            },
        )

    def _is_ancestor_of(self, potential_child):
        """
        Production-grade cycle detection using optimized BFS.

        Args:
            potential_child: Category to check for ancestry relationship

        Returns:
            bool: True if this category is an ancestor of potential_child
        """
        if not potential_child.id:
            return False

        visited = set()
        queue = collections.deque([self])

        logger.debug(
            "Initiating ancestry check",
            extra={
                "root_category_id": self.id,
                "target_category_id": potential_child.id,
                "action": "ancestry_check_started",
                "component": "ExpenseCategory",
            },
        )

        nodes_checked = 0
        max_depth = 100  # Safety limit for very deep trees

        while queue and nodes_checked < max_depth:
            current = queue.popleft()

            # Skip already visited nodes
            if current.id in visited:
                continue

            visited.add(current.id)
            nodes_checked += 1

            # Found potential child in ancestry - cycle detected
            if current.id == potential_child.id:
                logger.debug(
                    "Cycle detected in ancestry check",
                    extra={
                        "root_category_id": self.id,
                        "target_category_id": potential_child.id,
                        "nodes_checked": nodes_checked,
                        "action": "cycle_detected",
                        "component": "ExpenseCategory",
                    },
                )
                return True

            # Efficiently fetch and process children
            try:
                children = current.children.all().only("id")
                for child in children:
                    if child.id not in visited:
                        queue.append(child)
            except Exception as e:
                logger.error(
                    "Error during ancestry check",
                    extra={
                        "current_category_id": current.id,
                        "error": str(e),
                        "action": "ancestry_check_error",
                        "component": "ExpenseCategory",
                        "severity": "medium",
                    },
                )
                # On error, assume safe to prevent false negatives
                return False

        # Safety limit reached - log warning but allow operation
        if nodes_checked >= max_depth:
            logger.warning(
                "Ancestry check depth limit reached",
                extra={
                    "root_category_id": self.id,
                    "target_category_id": potential_child.id,
                    "nodes_checked": nodes_checked,
                    "max_depth": max_depth,
                    "action": "ancestry_check_depth_limit",
                    "component": "ExpenseCategory",
                    "severity": "low",
                },
            )

        logger.debug(
            "Ancestry check completed - no cycle detected",
            extra={
                "root_category_id": self.id,
                "target_category_id": potential_child.id,
                "nodes_checked": nodes_checked,
                "action": "ancestry_check_completed",
                "component": "ExpenseCategory",
            },
        )

        return False

    def clean(self):
        """Validate category data and relationships with comprehensive checks."""
        super().clean()

        # Determine allowed range from version-configured levels_count.
        # Business rule: leaf is always level 5. `levels_count` represents how many
        # levels exist ending at level 5 (e.g., levels_count=3 -> valid levels 3..5).
        levels_count = int(getattr(self.version, "levels_count", 5))
        min_level = 6 - levels_count
        if self.level < min_level or self.level > 5:
            raise ValidationError(f"Category level must be between {min_level} and 5")

        # Validate name
        if not self.name or len(self.name.strip()) < 2:
            raise ValidationError("Category name must be at least 2 characters long")

        # Parent constraints: non-root must have exactly one parent; root must have none
        parent_count = self.parents.count()
        if self.level == min_level and parent_count > 0:
            raise ValidationError(f"Level {min_level} category cannot have a parent")
        if self.level > min_level and parent_count != 1:
            raise ValidationError("Non-root categories must have exactly one parent")

        # Child constraints: leaves (level 5) must have no children; non-leaves (level < 5) must have at least one child
        if self.level == 5 and self.children.exists():
            raise ValidationError(
                f"Leaf category '{self.name}' (level 5) should not have children"
            )
        if self.level < 5 and not self.children.exists():
            raise ValidationError(
                f"Non-leaf category '{self.name}' (level {self.level}) must have at least one child"
            )

        # Validate child relationships with enhanced checks
        for child in self.children.all():
            # Check for multiple parents (should not happen with proper add_child usage)
            if child.parents.exclude(pk=self.pk).exists():
                logger.warning(
                    "Category validation failed - child has other parents",
                    extra={
                        "category_id": self.id,
                        "category_name": self.name,
                        "child_id": child.id,
                        "child_name": child.name,
                        "conflicting_parents_count": child.parents.exclude(
                            pk=self.pk
                        ).count(),
                        "action": "category_validation_failed_multiple_parents",
                        "component": "ExpenseCategory",
                        "severity": "high",  # Increased severity as this indicates data inconsistency
                    },
                )
                raise ValidationError(
                    f"Child '{child.name}' already has another parent"
                )

            # Check level hierarchy in existing relationships
            if child.level <= self.level:
                logger.warning(
                    "Invalid level hierarchy in existing relationship",
                    extra={
                        "parent_id": self.id,
                        "parent_level": self.level,
                        "child_id": child.id,
                        "child_level": child.level,
                        "action": "invalid_level_hierarchy_existing",
                        "component": "ExpenseCategory",
                        "severity": "high",
                    },
                )
                raise ValidationError(
                    "Child category must have higher level than parent"
                )

            # Check for circular references in existing relationships
            if child._is_ancestor_of(self): # Check if child is an ancestor of self
                logger.error(
                    "Circular reference detected in existing data",
                    extra={
                        "parent_id": self.id,
                        "child_id": child.id,
                        "action": "circular_reference_existing_data",
                        "component": "ExpenseCategory",
                        "severity": "critical",  # Critical as this indicates corrupted data
                    },
                )
                raise ValidationError(
                    "Circular reference detected in category hierarchy"
                )

        logger.debug(
            "ExpenseCategory validation completed successfully",
            extra={
                "category_id": self.id if self.id else "new",
                "category_name": self.name,
                "level": self.level,
                "child_count": self.children.count(),
                "is_leaf": not self.children.exists(),
                "is_root": not self.parents.exists(),
                "action": "expense_category_validation_success",
                "component": "ExpenseCategory",
            },
        )

    def __str__(self):
        """String representation of ExpenseCategory."""
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
    description = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "Income category versions"
        ordering = ["-created_at"]

    def __str__(self):
        """String representation of IncomeCategoryVersion."""
        return f"{self.workspace.name} - Income"

    # Number of levels for this version (1..5). Frontend may change this per-version.
    levels_count = models.PositiveSmallIntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(5)]
    )

    def clean(self):
        """Validate income category version data."""
        super().clean()

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


class IncomeCategory(CategoryDescendantsMixin, models.Model):
    """
    Hierarchical income category structure.

    Represents a tree-like structure for organizing income categories
    with multiple levels and parent-child relationships.
    """

    LEVEL_CHOICES = [
        (1, "Level 1 - Root"),
        (2, "Level 2"),
        (3, "Level 3"),
        (4, "Level 4"),
        (5, "Level 5 - Leaf"),
    ]

    version = models.ForeignKey(
        IncomeCategoryVersion, on_delete=models.CASCADE, related_name="categories"
    )
    name = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)
    children = models.ManyToManyField(
        "self", symmetrical=False, related_name="parents", blank=True
    )
    level = models.PositiveIntegerField(choices=LEVEL_CHOICES)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "Income categories"
        ordering = ["level", "name"]

    @property
    def is_leaf(self):
        """Check if category is a leaf node (has no children)."""
        return not self.children.exists()

    @property
    def is_root(self):
        """Check if category is a root node (has no parents)."""
        return not self.parents.exists()

    def add_child(self, child):
        """Safely add child category with comprehensive validation."""
        # 1. Validate self-reference
        if child.id and child.id == self.id:
            logger.warning(
                "Self-reference attempt blocked",
                extra={
                    "category_id": self.id,
                    "category_name": self.name,
                    "action": "self_reference_blocked",
                    "component": "IncomeCategory",
                    "severity": "high",
                },
            )
            raise ValidationError("Cannot add category as its own child")

        # 2. Validate existing parent
        if child.parents.exists():
            logger.warning(
                "Attempt to add child with existing parent",
                extra={
                    "parent_id": self.id,
                    "parent_name": self.name,
                    "child_id": child.id,
                    "child_name": child.name,
                    "existing_parents_count": child.parents.count(),
                    "action": "child_addition_failed_existing_parent",
                    "component": "IncomeCategory",
                    "severity": "medium",
                },
            )
            raise ValidationError(f"Category '{child.name}' already has a parent")

        # 3. Validate circular reference
        if self._is_ancestor_of(child):
            logger.warning(
                "Circular reference attempt blocked",
                extra={
                    "parent_id": self.id,
                    "parent_name": self.name,
                    "child_id": child.id,
                    "child_name": child.name,
                    "action": "circular_reference_blocked",
                    "component": "IncomeCategory",
                    "severity": "high",
                },
            )
            raise ValidationError(
                "Circular reference detected - cannot create category cycle"
            )

        # 4. Validate level hierarchy
        if child.level <= self.level:
            logger.warning(
                "Invalid level hierarchy attempt",
                extra={
                    "parent_id": self.id,
                    "parent_level": self.level,
                    "child_id": child.id,
                    "child_level": child.level,
                    "action": "invalid_level_hierarchy",
                    "component": "IncomeCategory",
                    "severity": "medium",
                },
            )
            raise ValidationError("Child category must have higher level than parent")

        # All validations passed - add child
        self.children.add(child)

        logger.debug(
            "Child category added successfully",
            extra={
                "parent_id": self.id,
                "parent_name": self.name,
                "parent_level": self.level,
                "child_id": child.id,
                "child_name": child.name,
                "child_level": child.level,
                "action": "child_addition_success",
                "component": "IncomeCategory",
            },
        )

    def _is_ancestor_of(self, potential_child):
        """
        Production-grade cycle detection using optimized BFS.

        Args:
            potential_child: Category to check for ancestry relationship

        Returns:
            bool: True if this category is an ancestor of potential_child
        """
        if not potential_child.id:
            return False

        visited = set()
        queue = collections.deque([self])

        logger.debug(
            "Initiating ancestry check",
            extra={
                "root_category_id": self.id,
                "target_category_id": potential_child.id,
                "action": "ancestry_check_started",
                "component": "IncomeCategory",
            },
        )

        nodes_checked = 0
        max_depth = 100  # Safety limit for very deep trees

        while queue and nodes_checked < max_depth:
            current = queue.popleft()

            # Skip already visited nodes
            if current.id in visited:
                continue

            visited.add(current.id)
            nodes_checked += 1

            # Found potential child in ancestry - cycle detected
            if current.id == potential_child.id:
                logger.debug(
                    "Cycle detected in ancestry check",
                    extra={
                        "root_category_id": self.id,
                        "target_category_id": potential_child.id,
                        "nodes_checked": nodes_checked,
                        "action": "cycle_detected",
                        "component": "IncomeCategory",
                    },
                )
                return True

            # Efficiently fetch and process children
            try:
                children = current.children.all().only("id")
                for child in children:
                    if child.id not in visited:
                        queue.append(child)
            except Exception as e:
                logger.error(
                    "Error during ancestry check",
                    extra={
                        "current_category_id": current.id,
                        "error": str(e),
                        "action": "ancestry_check_error",
                        "component": "IncomeCategory",
                        "severity": "medium",
                    },
                )
                # On error, assume safe to prevent false negatives
                return False

        # Safety limit reached - log warning but allow operation
        if nodes_checked >= max_depth:
            logger.warning(
                "Ancestry check depth limit reached",
                extra={
                    "root_category_id": self.id,
                    "target_category_id": potential_child.id,
                    "nodes_checked": nodes_checked,
                    "max_depth": max_depth,
                    "action": "ancestry_check_depth_limit",
                    "component": "IncomeCategory",
                    "severity": "low",
                },
            )

        logger.debug(
            "Ancestry check completed - no cycle detected",
            extra={
                "root_category_id": self.id,
                "target_category_id": potential_child.id,
                "nodes_checked": nodes_checked,
                "action": "ancestry_check_completed",
                "component": "IncomeCategory",
            },
        )

        return False

    def clean(self):
        """Validate category data and relationships with comprehensive checks."""
        super().clean()

        # Determine allowed range from version-configured levels_count.
        # Business rule: leaf is always level 5. `levels_count` represents how many
        # levels exist ending at level 5 (e.g., levels_count=3 -> valid levels 3..5).
        levels_count = int(getattr(self.version, "levels_count", 5))
        min_level = 6 - levels_count
        if self.level < min_level or self.level > 5:
            raise ValidationError(f"Category level must be between {min_level} and 5")

        # Validate name
        if not self.name or len(self.name.strip()) < 2:
            raise ValidationError("Category name must be at least 2 characters long")

        # Parent constraints: non-root must have exactly one parent; root must have none
        parent_count = self.parents.count()
        if self.level == min_level and parent_count > 0:
            raise ValidationError(f"Level {min_level} category cannot have a parent")
        if self.level > min_level and parent_count != 1:
            raise ValidationError("Non-root categories must have exactly one parent")

        # Child constraints: leaves (level 5) must have no children; non-leaves (level < 5) must have at least one child
        if self.level == 5 and self.children.exists():
            raise ValidationError(
                f"Leaf category '{self.name}' (level 5) should not have children"
            )
        if self.level < 5 and not self.children.exists():
            raise ValidationError(
                f"Non-leaf category '{self.name}' (level {self.level}) must have at least one child"
            )

        # Validate child relationships with enhanced checks
        for child in self.children.all():
            # Check for multiple parents (should not happen with proper add_child usage)
            if child.parents.exclude(pk=self.pk).exists():
                logger.warning(
                    "Category validation failed - child has other parents",
                    extra={
                        "category_id": self.id,
                        "category_name": self.name,
                        "child_id": child.id,
                        "child_name": child.name,
                        "conflicting_parents_count": child.parents.exclude(
                            pk=self.pk
                        ).count(),
                        "action": "category_validation_failed_multiple_parents",
                        "component": "IncomeCategory",
                        "severity": "high",
                    },
                )
                raise ValidationError(
                    f"Child '{child.name}' already has another parent"
                )

            # Check level hierarchy in existing relationships
            if child.level <= self.level:
                logger.warning(
                    "Invalid level hierarchy in existing relationship",
                    extra={
                        "parent_id": self.id,
                        "parent_level": self.level,
                        "child_id": child.id,
                        "child_level": child.level,
                        "action": "invalid_level_hierarchy_existing",
                        "component": "IncomeCategory",
                        "severity": "high",
                    },
                )
                raise ValidationError(
                    "Child category must have higher level than parent"
                )

            # Check for circular references in existing relationships
            if child._is_ancestor_of(self): # Check if child is an ancestor of self
                logger.error(
                    "Circular reference detected in existing data",
                    extra={
                        "parent_id": self.id,
                        "child_id": child.id,
                        "action": "circular_reference_existing_data",
                        "component": "IncomeCategory",
                        "severity": "critical",
                    },
                )
                raise ValidationError(
                    "Circular reference detected in category hierarchy"
                )

        logger.debug(
            "IncomeCategory validation completed successfully",
            extra={
                "category_id": self.id if self.id else "new",
                "category_name": self.name,
                "level": self.level,
                "child_count": self.children.count(),
                "is_leaf": not self.children.exists(),
                "is_root": not self.parents.exists(),
                "action": "income_category_validation_success",
                "component": "IncomeCategory",
            },
        )

    def __str__(self):
        """String representation of IncomeCategory."""
        return f"{self.name} (Level {self.level})"


# -------------------------------------------------------------------
# CATEGORY PROPERTIES
# -------------------------------------------------------------------
# Additional properties and constraints for categories


class ExpenseCategoryProperty(models.Model):
    """
    Property definitions for expense categories.

    Defines specific properties and constraints for expense categories
    like cost/expense classification.
    """

    PROPERTY_CHOICES = [
        ("cost", "Only cost"),
        ("expense", "Only expense"),
    ]

    category = models.OneToOneField(
        ExpenseCategory, on_delete=models.CASCADE, related_name="property"
    )
    property_type = models.CharField(max_length=10, choices=PROPERTY_CHOICES)

    class Meta:
        verbose_name_plural = "Expense category properties"

    def __str__(self):
        return f"{self.category.name} - {self.property_type}"

    def clean(self):
        """Validate expense category property data."""
        super().clean()

        logger.debug(
            "ExpenseCategoryProperty validation completed",
            extra={
                "category_id": self.category.id,
                "property_type": self.property_type,
                "action": "expense_category_property_validation",
                "component": "ExpenseCategoryProperty",
            },
        )


class IncomeCategoryProperty(models.Model):
    """
    Property definitions for income categories.

    Defines specific properties and constraints for income categories
    like revenue/income classification.
    """

    PROPERTY_CHOICES = [
        ("revenue", "Only revenue"),
        ("income", "Only income"),
    ]

    category = models.OneToOneField(
        IncomeCategory, on_delete=models.CASCADE, related_name="property"
    )
    property_type = models.CharField(max_length=10, choices=PROPERTY_CHOICES)

    class Meta:
        verbose_name_plural = "Income category properties"

    def __str__(self):
        return f"{self.category.name} - {self.property_type}"

    def clean(self):
        """Validate income category property data."""
        super().clean()

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
        unique_together = ("currency", "date")
        ordering = ["-date"]
        verbose_name_plural = "Exchange rates"

    def __str__(self):
        """String representation of ExchangeRate."""
        return f"{self.currency} - {self.rate_to_eur} ({self.date})"

    def clean(self):
        """Validate exchange rate data."""
        super().clean()

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
# TAGS
# -------------------------------------------------------------------
# Tags used with transactions


class Tags(models.Model):
    """
    Reusable tag inside a workspace.
    Each workspace has its own isolated tag namespace.
    """

    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)

    class Meta:
        unique_together = ("workspace", "name")
        ordering = ["name"]

    def save(self, *args, **kwargs):
        """Ensure tag name is always lowercase."""
        self.name = self.name.lower()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


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
        ("income", "Income"),
        ("expense", "Expense"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    expense_category = models.ForeignKey(
        ExpenseCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="expense_transactions",
    )
    income_category = models.ForeignKey(
        IncomeCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="income_transactions",
    )
    original_amount = models.DecimalField(max_digits=20, decimal_places=4)
    original_currency = models.CharField(max_length=3)
    amount_domestic = models.DecimalField(
        max_digits=20, decimal_places=4
    )  # Stored in domestic currency
    date = models.DateField()
    month = models.DateField()
    tags = models.ManyToManyField("Tags", blank=True, related_name="transactions")
    note_manual = models.TextField(blank=True)
    note_auto = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "date"]),
            models.Index(fields=["user", "month"]),
            models.Index(fields=["user", "type"]),
            models.Index(fields=["workspace", "date"]),
            models.Index(fields=["workspace", "month"], name="idx_workspace_month"),
            models.Index(
                fields=["workspace", "type", "date"], name="idx_workspace_type_date"
            ),
            models.Index(fields=["workspace", "user"], name="idx_workspace_user"),
        ]
        ordering = ["-date", "-created_at"]

    def save(self, *args, **kwargs):
        """Save transaction with atomic operation for data consistency."""
        with transaction.atomic():
            # Calculate month from date
            if self.date:
                self.month = self.date.replace(day=1)

            # Determine if recalculation is needed
            needs_recalculation = self._needs_recalculation()

            # Recalculate domestic amount if needed
            if needs_recalculation:
                self._recalculate_domestic_amount_with_logging()

            super().save(*args, **kwargs)

    def _needs_recalculation(self):
        """Check if transaction needs domestic amount recalculation."""
        if not self.pk:
            return True

        try:
            old = Transaction.objects.get(pk=self.pk)
            return (
                old.original_amount != self.original_amount
                or old.original_currency != self.original_currency
                or old.date != self.date
            )
        except Transaction.DoesNotExist:
            return True

    def _recalculate_domestic_amount_with_logging(self):
        """Recalculate domestic amount with comprehensive logging."""
        logger.debug(
            "Transaction recalculation triggered",
            extra={
                "transaction_id": self.id if self.id else "new",
                "needs_recalculation": True,
                "action": "transaction_recalculation_triggered",
                "component": "Transaction",
            },
        )

        try:
            from .utils.currency_utils import recalculate_transactions_domestic_amount

            transactions = recalculate_transactions_domestic_amount(
                [self], self.workspace
            )

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

    @property
    def category(self):
        """Get the associated category regardless of type."""
        return self.expense_category or self.income_category

    def clean(self):
        """Validate transaction data and business rules."""
        super().clean()

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
        if self.type == "expense" and self.income_category:
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

        if self.type == "income" and self.expense_category:
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
        """String representation of Transaction."""
        domestic_currency = getattr(self.workspace.settings, "domestic_currency", "EUR")
        return f"{self.user} | {self.type} | {self.amount_domestic} {domestic_currency}"


# -------------------------------------------------------------------
# TRANSACTION DRAFTS
# -------------------------------------------------------------------
# Single transaction draft per workspace for UX work-in-progress


class TransactionDraft(models.Model):
    """
    Single transaction draft per workspace for temporary work-in-progress.

    Allows users to save incomplete bulk transactions and continue later.
    Automatically deleted on successful save or explicit discard.
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)

    # Draft data - similar to bulk transaction structure
    transactions_data = models.JSONField(default=list)  # List of transaction objects
    draft_type = models.CharField(
        max_length=10,
        choices=[("income", "Income"), ("expense", "Expense")],
        blank=True,
        null=True,
    )

    # Metadata
    last_modified = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "workspace", "draft_type"],
                name="unique_draft_per_workspace_type",
            )
        ]
        indexes = [
            models.Index(fields=["user", "workspace", "draft_type"]),
            models.Index(fields=["last_modified"]),
        ]
        ordering = ["-last_modified"]
        verbose_name_plural = "Transaction drafts"

    def clean(self):
        """Basic validation for draft data structure."""
        super().clean()

        if not isinstance(self.transactions_data, list):
            raise ValidationError("Transactions data must be a list")

        # Validate each transaction in the draft
        for i, transaction_data in enumerate(self.transactions_data):
            if not isinstance(transaction_data, dict):
                raise ValidationError(f"Transaction at index {i} must be a dictionary")

            # Basic field validation
            if "type" in transaction_data and transaction_data["type"] not in [
                "income",
                "expense",
            ]:
                raise ValidationError(f"Invalid transaction type at index {i}")

            if "original_amount" in transaction_data:
                try:
                    amount = float(transaction_data["original_amount"])
                    if amount <= 0:
                        raise ValidationError(f"Invalid amount at index {i}")
                except (TypeError, ValueError):
                    raise ValidationError(f"Invalid amount format at index {i}")

    def get_transactions_count(self):
        """Get number of transactions in draft."""
        return len(self.transactions_data) if self.transactions_data else 0

    def __str__(self):
        """String representation of TransactionDraft."""
        count = self.get_transactions_count()
        return (
            f"Draft: {self.user} | {self.draft_type or 'mixed'} | {count} transactions"
        )
