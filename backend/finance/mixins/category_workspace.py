# finance/mixins/category_workspace.py
"""
Production-grade security-focused mixin for category workspace validation.
Prevents cross-workspace access during admin impersonation sessions.
"""

import logging

from rest_framework.exceptions import ValidationError as DRFValidationError

logger = logging.getLogger(__name__)


class CategoryWorkspaceMixin:
    """
    Security-focused mixin for category workspace validation.
    """

    def validate(self, data):
        """
        Validate category belongs to current workspace context.

        Args:
            data: Serializer data

        Returns:
            dict: Validated data

        Raises:
            DRFValidationError: If workspace validation fails
        """
        request = self.context.get("request")

        if request and hasattr(request, "workspace"):
            workspace = request.workspace
            version = data.get("version") or (
                self.instance.version if self.instance else None
            )

            if version and version.workspace_id != workspace.id:
                logger.warning(
                    "Category workspace security violation prevented",
                    extra={
                        "category_version_id": version.id,
                        "version_workspace_id": version.workspace_id,
                        "request_workspace_id": workspace.id,
                        "impersonation_active": getattr(
                            request, "is_admin_impersonation", False
                        ),
                        "action": "cross_workspace_access_blocked",
                        "component": "CategoryWorkspaceMixin",
                        "severity": "high",
                    },
                )
                raise DRFValidationError(
                    "Category version does not belong to this workspace"
                )

        return data
