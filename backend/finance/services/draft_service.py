"""
Production-grade draft service for transaction draft management.
Handles draft operations with atomic safety, workspace validation, and comprehensive audit logging.
"""

import logging

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from rest_framework.exceptions import PermissionDenied

from ..models import TransactionDraft, Workspace

logger = logging.getLogger(__name__)


class DraftService:
    """
    High-performance transaction draft management service.
    Provides atomic operations for draft lifecycle with workspace security validation.
    """

    @transaction.atomic
    def save_draft(
        self, user, workspace_id: int, draft_type: str, transactions_data: list
    ) -> TransactionDraft:
        """
        Atomically save transaction draft with replacement strategy.

        Implements single draft per workspace-type combination with atomic replacement
        to prevent race conditions and data corruption.

        Args:
            user: User instance saving the draft
            workspace_id: Workspace ID for draft association
            draft_type: Type of draft ('income' or 'expense')
            transactions_data: List of transaction data dictionaries

        Returns:
            TransactionDraft: Created or updated draft instance

        Raises:
            PermissionDenied: If user cannot access workspace
            ValidationError: If draft data is invalid
            DatabaseError: If database operation fails
        """
        logger.info(
            "Transaction draft save initiated",
            extra={
                "user_id": user.id,
                "workspace_id": workspace_id,
                "draft_type": draft_type,
                "transaction_count": len(transactions_data),
                "action": "draft_save_start",
                "component": "DraftService",
            },
        )

        try:
            # Get workspace with security validation
            workspace = self._get_workspace_with_access(user, workspace_id)

            # Validate draft data
            self._validate_draft_data(transactions_data, draft_type)

            # Atomic draft replacement
            with transaction.atomic():
                # Delete existing draft for this workspace and type
                deleted_count, _ = TransactionDraft.objects.filter(
                    user=user, workspace=workspace, draft_type=draft_type
                ).delete()

                # Create new draft with provided data
                draft = TransactionDraft.objects.create(
                    user=user,
                    workspace=workspace,
                    draft_type=draft_type,
                    transactions_data=transactions_data,
                )

            logger.info(
                "Transaction draft saved atomically",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_id": draft.id,
                    "draft_type": draft_type,
                    "transaction_count": len(transactions_data),
                    "previous_drafts_deleted": deleted_count,
                    "action": "draft_save_success",
                    "component": "DraftService",
                },
            )

            return draft

        except (PermissionDenied, ValidationError):
            raise
        except Exception as e:
            logger.error(
                "Transaction draft save failed",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_type": draft_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "draft_save_failed",
                    "component": "DraftService",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise

    def get_workspace_draft(
        self, user, workspace_id: int, draft_type: str
    ) -> TransactionDraft:
        """
        Retrieve workspace-specific draft with security validation.

        Args:
            user: User instance requesting the draft
            workspace_id: Workspace ID for draft retrieval
            draft_type: Type of draft to retrieve

        Returns:
            TransactionDraft: Draft instance or raises DoesNotExist

        Raises:
            PermissionDenied: If user cannot access workspace
            TransactionDraft.DoesNotExist: If no draft found
        """
        logger.debug(
            "Retrieving workspace draft",
            extra={
                "user_id": user.id,
                "workspace_id": workspace_id,
                "draft_type": draft_type,
                "action": "draft_retrieval_start",
                "component": "DraftService",
            },
        )

        try:
            # Get workspace with security validation
            workspace = self._get_workspace_with_access(user, workspace_id)

            draft = TransactionDraft.objects.select_related("workspace", "user").get(
                user=user, workspace_id=workspace_id, draft_type=draft_type
            )

            logger.debug(
                "Workspace draft retrieved successfully",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_type": draft_type,
                    "draft_id": draft.id,
                    "transaction_count": draft.get_transactions_count(),
                    "action": "draft_retrieval_success",
                    "component": "DraftService",
                },
            )

            return draft

        except TransactionDraft.DoesNotExist:
            logger.debug(
                "No draft found for workspace and type",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_type": draft_type,
                    "action": "draft_not_found",
                    "component": "DraftService",
                },
            )
            raise
        except PermissionDenied:
            raise
        except Exception as e:
            logger.error(
                "Workspace draft retrieval failed",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_type": draft_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "draft_retrieval_failed",
                    "component": "DraftService",
                    "severity": "medium",
                },
            )
            raise

    def get_or_create_draft(
        self, user, workspace_id: int, draft_type: str
    ) -> TransactionDraft:
        """
        Get existing draft or create empty one with security validation.

        Args:
            user: User instance
            workspace_id: Workspace ID for draft
            draft_type: Type of draft

        Returns:
            TransactionDraft: Existing or newly created draft

        Raises:
            PermissionDenied: If user cannot access workspace
        """
        logger.debug(
            "Getting or creating draft",
            extra={
                "user_id": user.id,
                "workspace_id": workspace_id,
                "draft_type": draft_type,
                "action": "draft_get_or_create_start",
                "component": "DraftService",
            },
        )

        try:
            # Get workspace ID with security validation
            self._get_workspace_with_access(user, workspace_id)

            draft, created = TransactionDraft.objects.get_or_create(
                user=user,
                workspace_id=workspace_id,
                draft_type=draft_type,
                defaults={"transactions_data": []},
            )

            action_type = "draft_created" if created else "draft_retrieved"
            logger.debug(
                f"Draft {action_type} successfully",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_id": draft.id,
                    "draft_type": draft_type,
                    "was_created": created,
                    "transaction_count": draft.get_transactions_count(),
                    "action": f"draft_get_or_create_{action_type}",
                    "component": "DraftService",
                },
            )

            return draft

        except PermissionDenied:
            raise
        except Exception as e:
            logger.error(
                "Draft get or create failed",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_type": draft_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "draft_get_or_create_failed",
                    "component": "DraftService",
                    "severity": "medium",
                },
            )
            raise

    @transaction.atomic
    def discard_draft(self, user, workspace_id: int, draft_type: str) -> bool:
        """
        Permanently discard transaction draft with security validation.

        Args:
            user: User instance discarding the draft
            workspace_id: Workspace ID containing the draft
            draft_type: Type of draft to discard

        Returns:
            bool: True if draft was discarded, False if no draft existed

        Raises:
            PermissionDenied: If user cannot access workspace
        """
        logger.info(
            "Transaction draft discard initiated",
            extra={
                "user_id": user.id,
                "workspace_id": workspace_id,
                "draft_type": draft_type,
                "action": "draft_discard_start",
                "component": "DraftService",
            },
        )

        try:
            # Get workspace with security validation
            workspace = self._get_workspace_with_access(user, workspace_id)

            # Get draft to be discarded
            try:
                draft = TransactionDraft.objects.get(
                    user=user, workspace=workspace, draft_type=draft_type
                )
            except TransactionDraft.DoesNotExist:
                logger.debug(
                    "No draft to discard",
                    extra={
                        "user_id": user.id,
                        "workspace_id": workspace_id,
                        "draft_type": draft_type,
                        "action": "draft_discard_skip",
                        "component": "DraftService",
                    },
                )
                return False

            draft_id = draft.id
            transaction_count = draft.get_transactions_count()

            # Perform deletion
            draft.delete()

            logger.info(
                "Transaction draft discarded successfully",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_type": draft_type,
                    "draft_id": draft_id,
                    "discarded_transaction_count": transaction_count,
                    "action": "draft_discard_success",
                    "component": "DraftService",
                },
            )

            return True

        except PermissionDenied:
            raise
        except Exception as e:
            logger.error(
                "Transaction draft discard failed",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "draft_type": draft_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "draft_discard_failed",
                    "component": "DraftService",
                    "severity": "medium",
                },
            )
            raise

    def cleanup_drafts_for_transaction(
        self, user, workspace_id: int, transaction_type: str
    ) -> int:
        """
        Cleanup drafts after successful transaction save.

        Args:
            user: User instance
            workspace_id: Workspace ID
            transaction_type: Type of transactions saved

        Returns:
            int: Number of drafts cleaned up
        """
        logger.debug(
            "Cleaning up drafts after transaction save",
            extra={
                "user_id": user.id,
                "workspace_id": workspace_id,
                "transaction_type": transaction_type,
                "action": "draft_cleanup_start",
                "component": "DraftService",
            },
        )

        try:
            # Get workspace with security validation
            workspace = self._get_workspace_with_access(user, workspace_id)

            deleted_count, _ = TransactionDraft.objects.filter(
                user=user, workspace=workspace, draft_type=transaction_type
            ).delete()

            if deleted_count > 0:
                logger.info(
                    "Transaction drafts cleaned up after successful save",
                    extra={
                        "user_id": user.id,
                        "workspace_id": workspace_id,
                        "transaction_type": transaction_type,
                        "drafts_deleted": deleted_count,
                        "action": "draft_cleanup_success",
                        "component": "DraftService",
                    },
                )

            return deleted_count

        except PermissionDenied:
            raise
        except Exception as e:
            logger.error(
                "Draft cleanup failed",
                extra={
                    "user_id": user.id,
                    "workspace_id": workspace_id,
                    "transaction_type": transaction_type,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "draft_cleanup_failed",
                    "component": "DraftService",
                    "severity": "high",
                },
            )
            raise

    def get_user_drafts_summary(self, user) -> dict:
        """
        Get summary of all user drafts across workspaces.

        Args:
            user: User instance

        Returns:
            dict: Draft summary with counts per workspace and type
        """
        logger.debug(
            "Getting user drafts summary",
            extra={
                "user_id": user.id,
                "action": "draft_summary_start",
                "component": "DraftService",
            },
        )

        try:
            drafts = (
                TransactionDraft.objects.filter(user=user)
                .select_related("workspace")
                .order_by("-last_modified")
            )

            summary = {
                "total_drafts": drafts.count(),
                "workspaces": {},
                "by_type": {"income": 0, "expense": 0},
            }

            for draft in drafts:
                # Count by workspace
                workspace_id = draft.workspace.id
                if workspace_id not in summary["workspaces"]:
                    summary["workspaces"][workspace_id] = {
                        "workspace_name": draft.workspace.name,
                        "draft_count": 0,
                        "types": [],
                    }

                summary["workspaces"][workspace_id]["draft_count"] += 1
                summary["workspaces"][workspace_id]["types"].append(draft.draft_type)

                # Count by type
                summary["by_type"][draft.draft_type] += 1

            logger.debug(
                "User drafts summary retrieved successfully",
                extra={
                    "user_id": user.id,
                    "total_drafts": summary["total_drafts"],
                    "workspace_count": len(summary["workspaces"]),
                    "action": "draft_summary_success",
                    "component": "DraftService",
                },
            )

            return summary

        except Exception as e:
            logger.error(
                "User drafts summary retrieval failed",
                extra={
                    "user_id": user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "draft_summary_failed",
                    "component": "DraftService",
                    "severity": "low",
                },
            )
            raise


    def _get_workspace_with_access(self, user, workspace_id: int) -> Workspace:
        """
        Get workspace with security validation.

        Args:
            user: User instance
            workspace_id: Workspace ID

        Returns:
            Workspace: Workspace instance

        Raises:
            PermissionDenied: If user cannot access workspace
        """
        try:
            workspace = Workspace.objects.get(id=workspace_id)

            # Check if user is workspace member
            if not workspace.members.filter(id=user.id).exists():
                raise PermissionDenied("You don't have access to this workspace")

            return workspace

        except Workspace.DoesNotExist:
            raise PermissionDenied("Workspace not found")

    def _validate_draft_data(self, transactions_data: list, draft_type: str) -> None:
        """
        Validate draft transaction data.

        Args:
            transactions_data: List of transaction data dictionaries
            draft_type: Type of draft for validation

        Raises:
            ValidationError: If draft data is invalid
        """

        if draft_type not in ["income", "expense"]:
            raise ValidationError(f"Invalid draft type: {draft_type}")

        if not isinstance(transactions_data, list):
            raise ValidationError("Transactions data must be a list")

        for i, tx_data in enumerate(transactions_data):
            if not isinstance(tx_data, dict):
                raise ValidationError(f"Transaction at index {i} must be an object")

            # Basic type validation
            tx_type = tx_data.get("type")
            if not tx_type:
                raise ValidationError(f"Transaction at index {i} must have a type")

            if tx_type not in ["income", "expense"]:
                raise ValidationError(f"Transaction at index {i} has invalid type")

            # Type consistency with draft
            if tx_type != draft_type:
                raise ValidationError(
                    f"Transaction at index {i} type '{tx_type}' doesn't match draft type '{draft_type}'"
                )

            # Amount validation
            if "original_amount" in tx_data:
                try:
                    amount = float(tx_data["original_amount"])
                    if amount <= 0:
                        raise ValidationError(f"Invalid amount at index {i}")
                except (TypeError, ValueError):
                    raise ValidationError(f"Invalid amount format at index {i}")
