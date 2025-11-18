# finance/services/workspace_context_service.py
"""
Production-grade workspace context service.
Builds complete request context with optimized data access and proper error propagation.
"""

import logging

from django.db import DatabaseError

from ..models import Workspace
from .impersonation_service import ImpersonationService
from .membership_cache_service import MembershipCacheService

logger = logging.getLogger(__name__)


class WorkspaceContextService:
    """
    High-performance workspace context builder.
    Provides complete request context with optimized data access and proper error handling.
    """

    impersonation_service = ImpersonationService()
    membership_service = MembershipCacheService()

    def build_request_context(self, request, view_kwargs=None):
        """
        Build complete request context with optimized queries and proper error propagation.

        Args:
            request: HTTP request object
            view_kwargs: Optional view kwargs for explicit workspace ID extraction

        Raises:
            DatabaseError: On database connectivity issues
            Exception: On unexpected critical errors
        """
        try:

            self._initialize_request_defaults(request)

            if not request.user.is_authenticated:
                return

            user_id_param = self._get_user_id_param(request)
            workspace_id = self._get_validated_workspace_id(request, view_kwargs)

            self._set_basic_permissions(request)

            if user_id_param:
                self._process_impersonation_context(
                    request, user_id_param, workspace_id
                )
            elif workspace_id:
                self._process_workspace_context(request, workspace_id)

        except DatabaseError as e:
            logger.error(
                "Database error during context resolution",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "error": str(e),
                    "action": "database_error",
                    "component": "WorkspaceContextService",
                    "severity": "high",
                },
            )
            self._reset_impersonation(request)
            raise
        except Exception as e:
            logger.error(
                "Unexpected error in context service",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "error": str(e),
                    "action": "unexpected_service_error",
                    "component": "WorkspaceContextService",
                    "severity": "critical",
                },
            )
            self._reset_impersonation(request)
            raise

    def _initialize_request_defaults(self, request):
        """Initialize secure request defaults."""
        request.target_user = getattr(request, "user", None)
        request.is_admin_impersonation = False
        request.impersonation_type = None
        request.impersonation_workspace_ids = []
        request.workspace = None

        request.user_permissions = {
            "is_superuser": False,
            "is_workspace_admin": False,
            "workspace_role": None,
            "current_workspace_id": None,
            "workspace_exists": False,
        }

    def _get_user_id_param(self, request):
        """Extract and validate user_id parameter from request."""
        user_id = request.GET.get("user_id") or getattr(request, "data", {}).get(
            "user_id"
        )

        if user_id:
            try:
                return int(user_id)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid user_id parameter format",
                    extra={
                        "user_id": user_id,
                        "admin_id": request.user.id,
                        "action": "invalid_user_id_format",
                        "component": "WorkspaceContextService",
                    },
                )
        return None

    def _get_validated_workspace_id(self, request, view_kwargs=None):
        """
        Extract and validate workspace ID from multiple sources with priority.

        Priority order:
        1. Explicit view_kwargs (from mixin)
        2. Request kwargs (URL parameters)
        3. Query parameters
        4. Request data
        """
        logger.debug(
            "🔍 DEBUG _get_validated_workspace_id - STARTING EXTRACTION",
            extra={
                "user_id": getattr(request.user, "id", "anonymous"),
                "view_kwargs_provided": view_kwargs is not None,
                "action": "debug_extraction_start",
                "component": "WorkspaceContextService",
            },
        )
        # Priority 1: Explicit view kwargs (highest priority for tests)
        workspace_id = self._extract_from_view_kwargs(view_kwargs)

        logger.debug(
            "🔍 DEBUG: After view_kwargs extraction",
            extra={
                "workspace_id": workspace_id,
                "source": "view_kwargs",
                "action": "debug_extraction_step",
                "component": "WorkspaceContextService",
            },
        )

        # Priority 2: Request kwargs (URL parameters)
        if not workspace_id:
            workspace_id = self._extract_from_request_kwargs(request)

        # Priority 3: Query parameters
        if not workspace_id:
            workspace_id = request.GET.get("workspace_id")

        # Priority 4: Request data
        if not workspace_id:
            workspace_id = getattr(request, "data", {}).get("workspace_id")

        logger.debug(
            "Workspace ID extraction - COMPREHENSIVE DEBUG",
            extra={
                "user_id": getattr(request.user, "id", "anonymous"),
                "extracted_workspace_id": workspace_id,
                "sources_checked": {
                    "view_kwargs_provided": view_kwargs is not None,
                    "view_kwargs_pk": view_kwargs.get("pk") if view_kwargs else None,
                    "request_kwargs_pk": getattr(request, "kwargs", {}).get("pk"),
                    "request_kwargs_workspace_pk": getattr(request, "kwargs", {}).get(
                        "workspace_pk"
                    ),
                    "GET_workspace_id": request.GET.get("workspace_id"),
                    "data_workspace_id": getattr(request, "data", {}).get(
                        "workspace_id"
                    ),
                },
                "action": "workspace_id_extraction_comprehensive",
                "component": "WorkspaceContextService",
            },
        )

        return self._validate_workspace_existence(request, workspace_id)

    def _extract_from_view_kwargs(self, view_kwargs):
        """Extract workspace ID from explicit view kwargs (highest priority)."""
        if not view_kwargs:
            return None

        return (
            view_kwargs.get("pk")
            or view_kwargs.get("workspace_pk")
            or view_kwargs.get("workspace_id")
        )

    def _extract_from_request_kwargs(self, request):
        """Extract workspace ID from request kwargs (URL parameters)."""
        return (
            getattr(request, "kwargs", {}).get("pk")
            or getattr(request, "kwargs", {}).get("workspace_pk")
            or getattr(request, "kwargs", {}).get("workspace_id")
        )

    def _validate_workspace_existence(self, request, workspace_id):
        """
        Validate workspace existence, fetch the object, and set request permissions.

        Optimized to use a single database query (get) instead of two (filter/exists and get).
        """
        """DEBUG VERSION - Add this temporarily"""
        logger.debug(
            "🔍 DEBUG _validate_workspace_existence",
            extra={
                "workspace_id": workspace_id,
                "workspace_id_type": type(workspace_id).__name__,
                "workspace_id_repr": repr(workspace_id),
            },
        )
        # Reset workspace state to secure defaults
        request.user_permissions["workspace_exists"] = False
        request.user_permissions["current_workspace_id"] = None
        request.workspace = None

        if not workspace_id:
            logger.debug(
                "No workspace ID provided in request",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "action": "workspace_id_not_provided",
                    "component": "WorkspaceContextService",
                },
            )
            return None

        try:
            # 1. Clean and validate ID format
            workspace_id = int(workspace_id)
            
            # 2. OPTIMIZATION: Single database query to fetch the object
            # Using select_related('owner') to preemptively optimize owner access
            workspace = Workspace.objects.select_related('owner').get(id=workspace_id)
            
            # 3. Set successful context
            request.workspace = workspace
            request.user_permissions["workspace_exists"] = True
            request.user_permissions["current_workspace_id"] = workspace_id

            logger.debug(
                "Workspace validated and retrieved successfully",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "workspace_id": workspace_id,
                    "action": "workspace_validation_success",
                    "component": "WorkspaceContextService",
                },
            )
            
            return workspace_id

        except (ValueError, TypeError):
            # Handles non-integer ID format
            logger.warning(
                "Invalid workspace ID format",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "workspace_id": workspace_id,
                    "action": "invalid_workspace_id",
                    "component": "WorkspaceContextService",
                    "severity": "medium",
                },
            )
            return None
            
        except Workspace.DoesNotExist:
            # Handles valid integer ID for a non-existent workspace
            # We set current_workspace_id for consistent logging/error tracing
            request.user_permissions["current_workspace_id"] = workspace_id
            
            logger.warning(
                "Access attempt to non-existent workspace",
                extra={
                    "user_id": getattr(request.user, "id", "anonymous"),
                    "workspace_id": workspace_id,
                    "action": "workspace_not_found",
                    "component": "WorkspaceContextService",
                    "severity": "medium",
                },
            )
            # request.user_permissions["workspace_exists"] remains False
            return None

    def _set_basic_permissions(self, request):
        """Set basic user permissions without database queries."""
        request.user_permissions["is_superuser"] = request.user.is_superuser

    def _process_impersonation_context(self, request, user_id_param, workspace_id):
        """Process impersonation context with optimized service."""

        if not self.impersonation_service.check_rate_limit(request.user.id):
            logger.warning(
                "Impersonation rate limit exceeded",
                extra={
                    "admin_id": request.user.id,
                    "action": "impersonation_rate_limit_exceeded",
                    "component": "WorkspaceContextService",
                    "severity": "high",
                },
            )
            self._reset_impersonation(request)
            return

        target_user, granted, imp_type, workspace_ids = (
            self.impersonation_service.process_impersonation(
                request.user, user_id_param, workspace_id
            )
        )

        if granted:
            request.target_user = target_user
            request.is_admin_impersonation = True
            request.impersonation_type = imp_type
            request.impersonation_workspace_ids = workspace_ids

            logger.info(
                f"{imp_type} impersonation activated successfully",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_count": len(workspace_ids),
                    "impersonation_type": imp_type,
                    "action": "impersonation_activated",
                    "component": "WorkspaceContextService",
                },
            )
        else:
            self._reset_impersonation(request)
            logger.warning(
            "Impersonation denied/failed",
            extra={
                "admin_id": request.user.id,
                "target_user_id": user_id_param,
                "action": "impersonation_denied",
                "component": "WorkspaceContextService",
                "severity": "medium",
            },
        )

    def _process_workspace_context(self, request, workspace_id):
        """Process workspace context with optimized data access."""
        if not request.user_permissions.get("workspace_exists"):
            logger.warning(
                "Workspace access attempt to non-existent workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_access_invalid",
                    "component": "WorkspaceContextService",
                    "severity": "medium",
                },
            )
            return

        role = self.membership_service.get_user_workspace_role(
            request.user.id, workspace_id
        )
        if role:
            request.user_permissions["workspace_role"] = role
            request.user_permissions["is_workspace_admin"] = (
                self.membership_service.is_workspace_admin(
                    request.user.id, workspace_id
                )
            )

            logger.debug(
                "Workspace access permissions validated and set",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "role": role,
                    "is_workspace_admin": request.user_permissions[
                        "is_workspace_admin"
                    ],
                    "action": "workspace_permissions_set",
                    "component": "WorkspaceContextService",
                },
            )
        else:
            logger.warning(
                "User is not a member of the requested workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_access_denied",
                    "component": "WorkspaceContextService",
                    "severity": "medium",
                },
            )

    def _reset_impersonation(self, request):
        """Reset impersonation settings to secure defaults."""
        request.target_user = request.user
        request.is_admin_impersonation = False
        request.impersonation_type = None
        request.impersonation_workspace_ids = []
