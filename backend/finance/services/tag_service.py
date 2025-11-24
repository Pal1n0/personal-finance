"""
Production-grade service for tag management.
Handles tag lifecycle within workspaces with comprehensive validation and logging.
"""

import logging

from django.db import transaction
from rest_framework.exceptions import ValidationError

from ..models import Tags, Transaction, Workspace

logger = logging.getLogger(__name__)


class TagService:
    """
    Service for handling tag operations with workspace scoping and validation.
    """

    @staticmethod
    def get_or_create_tags(workspace: Workspace, tag_names: list[str]) -> list[Tags]:
        """
        Get existing tags or create new ones for a given workspace.
        Ensures all tag names are lowercase and unique per workspace.

        Args:
            workspace: The workspace instance.
            tag_names: A list of tag names (strings).

        Returns:
            A list of Tag model instances.
        """
        if not tag_names:
            return []

        # Normalize all tag names to lowercase
        normalized_names = {name.lower().strip() for name in tag_names if name.strip()}

        # Find existing tags in a single query
        existing_tags = Tags.objects.filter(
            workspace=workspace, name__in=normalized_names
        )
        existing_names = {tag.name for tag in existing_tags}

        # Determine which tags need to be created
        new_names = normalized_names - existing_names
        new_tags_to_create = [
            Tags(workspace=workspace, name=name) for name in new_names
        ]

        # Bulk create new tags if any
        if new_tags_to_create:
            Tags.objects.bulk_create(new_tags_to_create)
            logger.info(
                f"Bulk created {len(new_tags_to_create)} new tags.",
                extra={
                    "workspace_id": workspace.id,
                    "new_tags": list(new_names),
                    "action": "tags_bulk_created",
                    "component": "TagService",
                },
            )

        # Return all relevant tags
        all_tags = list(existing_tags) + new_tags_to_create
        return all_tags

    @staticmethod
    @transaction.atomic
    def assign_tags_to_transaction(
        transaction_instance: Transaction, tag_names: list[str]
    ) -> Transaction:
        """
        Assign a list of tags to a transaction, creating new tags if necessary.
        This replaces all existing tags on the transaction.

        Args:
            transaction_instance: The transaction to update.
            tag_names: A list of tag names to assign.

        Returns:
            The updated transaction instance.
        """
        workspace = transaction_instance.workspace
        tags = TagService.get_or_create_tags(workspace, tag_names)

        transaction_instance.tags.set(tags)

        logger.info(
            f"Assigned {len(tags)} tags to transaction.",
            extra={
                "transaction_id": transaction_instance.id,
                "workspace_id": workspace.id,
                "assigned_tags": [tag.name for tag in tags],
                "action": "tags_assigned_to_transaction",
                "component": "TagService",
            },
        )
        return transaction_instance

    @staticmethod
    def delete_tag(tag: Tags):
        """
        Deletes a tag.

        For simplicity, we allow deleting tags even if they are used.
        The relationship is ManyToMany, so deleting a tag just removes it
        from all associated transactions, but does not delete the transactions.

        Args:
            tag: The Tag instance to delete.
        """
        tag_id = tag.id
        tag_name = tag.name
        workspace_id = tag.workspace_id

        tag.delete()

        logger.warning(
            f"Tag '{tag_name}' deleted.",
            extra={
                "tag_id": tag_id,
                "tag_name": tag_name,
                "workspace_id": workspace_id,
                "action": "tag_deleted",
                "component": "TagService",
                "severity": "medium",
            },
        )

    @staticmethod
    def update_tag(tag: Tags, new_name: str) -> Tags:
        """
        Updates the name of a tag.

        Args:
            tag: The Tag instance to update.
            new_name: The new name for the tag.

        Returns:
            The updated Tag instance.

        Raises:
            ValidationError: If a tag with the new name already exists in the workspace.
        """
        normalized_new_name = new_name.lower().strip()
        if tag.name == normalized_new_name:
            return tag  # No change needed

        if Tags.objects.filter(
            workspace=tag.workspace, name=normalized_new_name
        ).exists():
            raise ValidationError(
                f"A tag with the name '{new_name}' already exists in this workspace."
            )

        tag.name = normalized_new_name
        tag.save(update_fields=["name"])
        return tag
