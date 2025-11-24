# finance/mixins/workspace_context.py
"""
Production-grade workspace context mixin.
Thin wrapper around workspace context service with proper error propagation.
"""

import logging

from ..services.workspace_context_service import WorkspaceContextService

logger = logging.getLogger(__name__)


class WorkspaceContextMixin:
    """
    Optimized mixin for workspace context building.
    Ensures context is available BEFORE permission checks.
    """

    # Service instance for thread-safe access
    context_service = WorkspaceContextService()

    def initial(self, request, *args, **kwargs):
        """
        Initialize workspace context - called AFTER URL parsing but BEFORE permission checks.

        CRITICAL: Context must be set BEFORE super().initial() to ensure permissions
        have access to workspace context during their checks.

        Args:
            request: HTTP request object (now with populated kwargs)
            *args: Additional arguments
            **kwargs: Additional keyword arguments from URL routing
        """

        # PHASE 1: Build workspace context FIRST (before permissions)
        self._process_workspace_context(request, kwargs)

        # Debug verification that context is set before permissions
        logger.debug(
            "Workspace context initialized BEFORE permission checks",
            extra={
                "user_id": getattr(request.user, "id", "anonymous"),
                "has_user_permissions": hasattr(request, "user_permissions"),
                "workspace_exists": getattr(
                    request.user_permissions, "workspace_exists", False
                ),
                "current_workspace_id": getattr(
                    request.user_permissions, "current_workspace_id", None
                ),
                "view_kwargs_provided": bool(kwargs),
                "action": "workspace_context_pre_permissions",
                "component": "WorkspaceContextMixin",
            },
        )

        # PHASE 2: NOW call super - permission classes will see the context
        super().initial(request, *args, **kwargs)

        logger.debug(
            "Workspace context flow completed successfully",
            extra={
                "user_id": getattr(request.user, "id", "anonymous"),
                "workspace_role": getattr(
                    request.user_permissions, "workspace_role", None
                ),
                "action": "workspace_context_complete",
                "component": "WorkspaceContextMixin",
            },
        )

    def _process_workspace_context(self, request, view_kwargs):
        """
        Process workspace context using optimized service with proper error handling.

        Args:
            request: HTTP request object
            view_kwargs: kwargs from URL routing containing workspace ID
        """
        try:
            self.context_service.build_request_context(request, view_kwargs)
        except Exception as e:
            logger.error(
                "Workspace context processing failed",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "error": str(e),
                    "view_kwargs": view_kwargs,
                    "action": "workspace_context_processing_failed",
                    "component": "WorkspaceContextMixin",
                    "severity": "high",
                },
            )
            # Propagate exception to DRF for proper error handling
            raise
