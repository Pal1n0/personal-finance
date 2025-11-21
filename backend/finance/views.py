"""
Core API views for financial management system.

This module provides viewsets and API endpoints for handling transactions,
user settings, workspace settings, categories, exchange rates, and bulk operations
in the financial management application.
"""

import logging
from datetime import date

from django.core.cache import cache
from django.db import models, transaction
from django.shortcuts import get_object_or_404
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .mixins.service_exception_handler import ServiceExceptionHandlerMixin
from .mixins.workspace_context import WorkspaceContextMixin
from .mixins.workspace_membership import WorkspaceMembershipMixin
from .models import (ExchangeRate, ExpenseCategory, ExpenseCategoryVersion, Tags,
                     IncomeCategory, IncomeCategoryVersion, Transaction,
                     TransactionDraft, UserSettings, Workspace, WorkspaceAdmin,
                     WorkspaceMembership, WorkspaceSettings)
from .permissions import (IsSuperuser, IsWorkspaceAdmin, IsWorkspaceEditor,
                          IsWorkspaceMember, IsWorkspaceOwner)
from .serializers import (ExchangeRateSerializer, ExpenseCategorySerializer, TagSerializer,
                          IncomeCategorySerializer, TransactionDraftSerializer,
                          TransactionListSerializer, TransactionSerializer,
                          UserSettingsSerializer, WorkspaceAdminSerializer,
                          WorkspaceMembershipSerializer, WorkspaceSerializer,
                          WorkspaceSettingsSerializer)
from .services.currency_service import CurrencyService
from .services.draft_service import DraftService
from .services.membership_service import MembershipService
from .services.tag_service import TagService
from .services.transaction_service import TransactionService
from .services.workspace_service import WorkspaceService
from .utils.category_utils import sync_categories_tree

WorkspaceService


# Get structured logger for this module
logger = logging.getLogger(__name__)


class BaseWorkspaceViewSet(WorkspaceContextMixin, viewsets.ModelViewSet):
    """
    Base ViewSet for ALL workspace-related views.
    Now properly initializes workspace context BEFORE permission checks in DRF lifecycle.

    DRF Request Flow (FIXED):
    1. initialize_request() - Creates DRF request object
    2. initialize() - Called automatically by DRF (NOW triggers WorkspaceContextMixin.initialize())
    3. Workspace context is fully initialized BEFORE permission checks
    4. Permission checks have access to workspace context
    5. View processing continues with proper context
    """

    # No custom initialize_request needed - DRF will call initialize() automatically
    # WorkspaceContextMixin.initialize() now handles context setup at the right time
    pass


# -------------------------------------------------------------------
# WORKSPACE ADMIN MANAGEMENT
# -------------------------------------------------------------------


class WorkspaceAdminViewSet(BaseWorkspaceViewSet, ServiceExceptionHandlerMixin):
    """
    Production-optimized workspace administrator management.
    Uses ServiceExceptionHandlerMixin for unified error handling and BaseWorkspaceViewSet for context.
    """

    serializer_class = WorkspaceAdminSerializer  
    permission_classes = [IsAuthenticated, IsSuperuser]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.workspace_service = WorkspaceService()

    def get_permissions(self):
        """Enforce superuser requirement for all administrative actions."""
        return [IsAuthenticated(), IsSuperuser()]
    
    def get_queryset(self):
        """
        Secure queryset - returns empty for non-superusers to prevent information leakage.
        """
        if not self.request.user.is_superuser:
            return WorkspaceAdmin.objects.none()

        queryset = WorkspaceAdmin.objects.select_related(
            "user", "workspace", "assigned_by"
        ).order_by("-assigned_at")

        workspace_id = self.request.query_params.get('workspace')
        if workspace_id:
            queryset = queryset.filter(workspace_id=workspace_id)
            
        return queryset
    
    @action(detail=False, methods=["post"])
    def assign_admin(self, request, workspace_pk=None):
        """
        Assign workspace administrator privileges with comprehensive validation.

        Args:
            request: HTTP request with user context
            workspace_pk: Target workspace ID

        Returns:
            Response: Assignment result with metadata
        """
        workspace = get_object_or_404(Workspace, pk=workspace_pk)
        user_id = request.data.get("user_id")

        if not user_id:
            return Response(
                {"error": "User ID is required for admin assignment"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate workspace access using request context
        if not request.user_permissions.get("workspace_exists"):
            logger.warning(
                "Workspace access denied for admin assignment",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_pk,
                    "action": "admin_assignment_access_denied",
                    "component": "WorkspaceAdminViewSet",
                    "severity": "high",
                },
            )
            return Response(
                {"error": "Workspace access denied"}, status=status.HTTP_403_FORBIDDEN
            )

        target_user = request.target_user

        # Verify target user matches requested user_id
        if target_user.id != int(user_id):
            logger.warning(
                "User ID mismatch in admin assignment",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "requested_user_id": user_id,
                    "action": "admin_assignment_user_mismatch",
                    "component": "WorkspaceAdminViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "User ID mismatch with request context"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check membership using cached data
        user_memberships = getattr(request, "_cached_user_memberships", {})
        is_member = workspace.id in user_memberships

        if not is_member:
            logger.warning(
                "User not workspace member for admin assignment",
                extra={
                    "user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace_pk,
                    "action": "admin_assignment_not_member",
                    "component": "WorkspaceAdminViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "User must be workspace member before admin assignment"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create or update admin assignment
        assigning_admin = request.user

        try:
            admin_assignment, created = WorkspaceAdmin.objects.get_or_create(
                user=target_user,
                workspace=workspace,
                defaults={"assigned_by": assigning_admin, "is_active": True},
            )

            if not created:
                admin_assignment.is_active = True
                admin_assignment.assigned_by = assigning_admin
                admin_assignment.save()

            # Invalidate cached permissions
            self._invalidate_admin_caches(target_user.id, workspace.id)

            logger.info(
                "Workspace administrator privileges assigned successfully",
                extra={
                    "admin_user_id": assigning_admin.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "assignment_created": created,
                    "action": "workspace_admin_assigned",
                    "component": "WorkspaceAdminViewSet",
                },
            )

            return Response(
                {
                    "message": f"Administrator privileges assigned to {target_user.username}",
                    "admin_assignment_id": admin_assignment.id,
                    "assigned_at": admin_assignment.assigned_at,
                    "assigned_by_admin_id": assigning_admin.id,
                },
                status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(
                "Admin assignment failed",
                extra={
                    "admin_user_id": assigning_admin.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "error": str(e),
                    "action": "admin_assignment_failed",
                    "component": "WorkspaceAdminViewSet",
                    "severity": "high",
                },
            )
            return Response(
                {"error": "Admin assignment failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _invalidate_admin_caches(self, user_id, workspace_id):
        """
        Comprehensive cache invalidation for admin permission changes.
        """
        cache_keys = [
            f"workspace_admin_{user_id}_{workspace_id}",
            f"user_admin_workspaces_{user_id}",
            f"comprehensive_membership_{user_id}",
            f"workspace_member_{user_id}_{workspace_id}",
            f"user_permissions_{user_id}_{workspace_id}",
        ]

        for key in cache_keys:
            cache.delete(key)

        logger.debug(
            "Admin permission caches invalidated",
            extra={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "cache_keys_invalidated": len(cache_keys),
                "action": "admin_caches_invalidated",
                "component": "WorkspaceAdminViewSet",
            },
        )

    @action(detail=True, methods=['post'])
    def deactivate_admin(self, request, pk=None):
        """
        THIN deactivate admin - delegates to WorkspaceService.
        """
        logger.info(
            "Workspace admin deactivation delegated to service",
            extra={
                "admin_assignment_id": pk,
                "deactivated_by_id": request.user.id,
                "action": "workspace_admin_deactivation_delegated",
                "component": "WorkspaceAdminViewSet",
            },
        )

        try:
            # Delegate to service
            deactivated = self.handle_service_call(
                self.workspace_service.deactivate_workspace_admin,
                admin_assignment_id=pk,
                deactivated_by=request.user,
            )

            if deactivated:
                return Response(
                    {
                        "message": "Workspace admin deactivated successfully",
                        "admin_assignment_id": pk,
                    },
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"error": "Workspace admin assignment not found or already inactive"},
                    status=status.HTTP_404_NOT_FOUND
                )

        except WorkspaceAdmin.DoesNotExist:
            return Response(
                {"error": "Workspace admin assignment not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except ValidationError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

# -------------------------------------------------------------------
# WORKSPACE MANAGEMENT
# -------------------------------------------------------------------
# Workspace CRUD operations and membership management


class WorkspaceViewSet(
    BaseWorkspaceViewSet, WorkspaceMembershipMixin, ServiceExceptionHandlerMixin
):
    """
    FINAL THIN ViewSet - deleguje VŠETKU business logiku na Serializer a Services.
    Uses BaseWorkspaceViewSet for consistent context and ModelViewSet functionality.
    """

    serializer_class = WorkspaceSerializer
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.workspace_service = WorkspaceService()
        self.membership_service = MembershipService()

    def get_permissions(self):
        """THIN permissions - iba access control"""
        if self.action in ["list", "create"]:
            return [IsAuthenticated()]
        elif self.action in ["update", "partial_update", "activate"]:
            return [IsAuthenticated(), IsWorkspaceEditor()]
        elif self.action in ["destroy", "hard_delete", "update_member_role"]:
            return [IsAuthenticated(), IsWorkspaceOwner()]
        elif self.action in ["change_owner"]:
            return [IsAuthenticated(), IsWorkspaceAdmin()]
        return [IsAuthenticated(), IsWorkspaceMember()]
    
    def get_queryset(self):
        """THIN queryset - only security filtering"""
        target_user = self.request.target_user
    
        # Build query - get all workspaces where user is member
        workspaces = Workspace.objects.filter(members=target_user)

        # Apply impersonation or normal filtering
        if (
            self.request.is_admin_impersonation
            and hasattr(self.request, "impersonation_workspace_ids")
            and self.request.impersonation_workspace_ids
        ):
            # Impersonation: filter to allowed workspace IDs
            workspaces = workspaces.filter(id__in=self.request.impersonation_workspace_ids)
        else:
            # Normal case: owners see all workspaces, members see only active
            workspaces = workspaces.filter(
                models.Q(owner=target_user) | models.Q(is_active=True)
            )

        # Apply optimizations - single database query
        workspaces = workspaces.select_related("owner").prefetch_related("members")
        
        return workspaces

    def perform_create(self, serializer):
        """
        COMPLETELY THIN - serializer handles ALL business logic
        ServiceExceptionHandlerMixin handles any exceptions from serializer
        """
        logger.debug(
            "Workspace creation delegated entirely to serializer",
            extra={
                "user_id": self.request.user.id,
                "target_user_id": self.request.target_user.id,
                "action": "workspace_creation_delegated_to_serializer",
                "component": "WorkspaceViewSet",
            },
        )

        # Serializer.create() handles ALL business logic including:
        # - Atomic transaction
        # - Owner membership sync
        # - Error handling (via ServiceExceptionHandlerMixin in serializer)
        # - Logging
        # ServiceExceptionHandlerMixin will catch any exceptions
        serializer.save()

    def perform_destroy(self, instance):
        """
        THIN soft delete - delegate to service with unified exception handling
        ServiceExceptionHandlerMixin will convert service exceptions to DRF exceptions
        """
        target_user = self.request.target_user

        logger.info(
            "Workspace soft delete delegated to service",
            extra={
                "user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": instance.id,
                "action": "workspace_soft_delete_delegated",
                "component": "WorkspaceViewSet",
            },
        )

        # ServiceExceptionHandlerMixin handles exception conversion
        self.handle_service_call(
            self.workspace_service.soft_delete_workspace,
            workspace=instance,
            user=target_user,
        )

    @action(detail=True, methods=['get'])
    def membership_info(self, request, pk=None):
        """
        THIN membership info - get current user's membership information
        """
        workspace = self.get_object()

        logger.debug(
            "Membership info retrieval delegated to service",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "action": "membership_info_retrieval_delegated",
                "component": "WorkspaceViewSet",
            },
        )

        # Get role from request context (pre-calculated in middleware)
        role = request.user_permissions.get("workspace_role")
        is_owner = workspace.owner_id == request.user.id
        is_admin = request.user_permissions.get("is_workspace_admin", False)

        membership_info = {
            "workspace_id": workspace.id,
            "workspace_name": workspace.name,
            "user_id": request.user.id,
            "role": role,
            "is_owner": is_owner,
            "is_admin": is_admin,
            "permissions": {
                "can_edit": role in ["owner", "editor", "admin"],
                "can_delete": is_owner or is_admin,
                "can_manage_users": is_owner or is_admin,
                "can_impersonate": is_admin,
            }
        }

        if request.is_admin_impersonation:
            membership_info["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        logger.info(
            "Membership info retrieved successfully",
            extra={
                "workspace_id": workspace.id,
                "user_id": request.user.id,
                "role": role,
                "is_owner": is_owner,
                "is_admin": is_admin,
                "action": "membership_info_retrieved",
                "component": "WorkspaceViewSet",
            },
        )

        return Response(membership_info)

    @action(detail=True, methods=["delete"])
    def hard_delete(self, request, pk=None):
        """
        THIN hard delete - delegate to service with unified exception handling
        """
        workspace = self.get_object()

        logger.warning(
            "Workspace hard delete delegated to service",
            extra={
                "user_id": request.user.id,
                "target_user_id": request.target_user.id,
                "workspace_id": workspace.id,
                "action": "workspace_hard_delete_delegated",
                "component": "WorkspaceViewSet",
                "severity": "high",
            },
        )

        # ServiceExceptionHandlerMixin handles all exception conversion
        result = self.handle_service_call(
            self.workspace_service.hard_delete_workspace,
            workspace=workspace,
            requesting_user=request.user,
            confirmation_data=request.data.get("confirmation", {}),
        )

        # Add impersonation context
        if request.is_admin_impersonation:
            result["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        return Response(result, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        """
        THIN activate - delegate to service with unified exception handling
        """
        workspace = self.get_object()

        logger.info(
            "Workspace activation delegated to service",
            extra={
                "user_id": request.user.id,
                "target_user_id": request.target_user.id,
                "workspace_id": workspace.id,
                "action": "workspace_activation_delegated",
                "component": "WorkspaceViewSet",
            },
        )

        # ServiceExceptionHandlerMixin handles exception conversion
        self.handle_service_call(
            self.workspace_service.activate_workspace,
            workspace=workspace,
            user=request.target_user,
        )

        response_data = {
            "message": "Workspace activated successfully.",
            "is_active": True,
        }

        if request.is_admin_impersonation:
            response_data["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def change_owner(self, request, pk=None):
        """
        THIN change owner - delegate to service with unified exception handling
        """
        workspace = self.get_object()

        logger.info(
            "Workspace ownership change delegated to service",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "new_owner_id": request.data.get("new_owner_id"),
                "action": "workspace_ownership_change_delegated",
                "component": "WorkspaceViewSet",
            },
        )

        # ServiceExceptionHandlerMixin handles exception conversion
        self.handle_service_call(
            self.workspace_service.change_ownership,
            workspace=workspace,
            new_owner_id=request.data.get("new_owner_id"),
            changed_by=request.user,
            old_owner_action=request.data.get("old_owner_action", "editor"),
        )

        return Response(
            {
                "message": f"Workspace ownership transferred to user {request.data.get('new_owner_id')}.",
                "new_owner_id": request.data.get("new_owner_id"),
                "old_owner_action": request.data.get("old_owner_action", "editor"),
            }
        )

    @action(detail=True, methods=["post"])
    def update_member_role(self, request, pk=None):
        """
        THIN update member role - delegate to MembershipService with unified exception handling
        """
        workspace = self.get_object()

        logger.info(
            "Member role update delegated to service",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "target_user_id": request.data.get("user_id"),
                "new_role": request.data.get("role"),
                "action": "member_role_update_delegated",
                "component": "WorkspaceViewSet",
            },
        )

        # ServiceExceptionHandlerMixin handles exception conversion
        self.handle_service_call(
            self.membership_service.update_member_role,
            workspace=workspace,
            target_user_id=request.data.get("user_id"),
            new_role=request.data.get("role"),
            requesting_user=request.user,
        )

        return Response(
            {
                "message": f"User role updated to {request.data.get('role')}.",
                "user_id": request.data.get("user_id"),
                "new_role": request.data.get("role"),
            }
        )

    @action(detail=True, methods=["get"])
    def members(self, request, pk=None):
        """THIN members list - delegate to service with unified exception handling"""
        workspace = self.get_object()

        logger.debug(
            "Workspace members retrieval delegated to service",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "action": "workspace_members_retrieval_delegated",
                "component": "WorkspaceViewSet",
            },
        )

        # ServiceExceptionHandlerMixin handles exception conversion
        members_data = self.handle_service_call(
            self.membership_service.get_workspace_members_with_roles,
            workspace=workspace,
            requesting_user=request.user,
        )

        response_data = {
            "workspace_id": workspace.id,
            "workspace_name": workspace.name,
            "members": members_data,
            "total_members": len(members_data),
        }

        if request.is_admin_impersonation:
            response_data["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        return Response(response_data)


# -------------------------------------------------------------------
# WORKSPACE SETTINGS MANAGEMENT
# -------------------------------------------------------------------
# Workspace configuration with atomic currency changes


class WorkspaceSettingsViewSet(
    BaseWorkspaceViewSet,
    ServiceExceptionHandlerMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """
    THIN ViewSet for workspace settings management with atomic currency changes.
    Uses ServiceExceptionHandlerMixin for unified error handling.
    """

    serializer_class = WorkspaceSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """
        Dynamic permissions - owner required for updates.
        """
        if self.action in ["update", "partial_update"]:
            return [IsAuthenticated(), IsWorkspaceOwner()]
        return [IsAuthenticated(), IsWorkspaceMember()]

    def get_queryset(self):
        """
        THIN queryset - basic security filtering.
        """
        target_user = self.request.target_user

        logger.debug(
            "Retrieving workspace settings queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "action": "workspace_settings_queryset",
                "component": "WorkspaceSettingsViewSet",
            },
        )

        return WorkspaceSettings.objects.filter(
            workspace__members=target_user.id
        ).select_related("workspace")

    def update(self, request, *args, **kwargs):
        """
        THIN update - handles currency changes via service.
        """
        instance = self.get_object()

        if "domestic_currency" in request.data:
            return self._handle_currency_change(request, instance)

        response = super().update(request, *args, **kwargs)
        return self._add_impersonation_context(response, request)

    def partial_update(self, request, *args, **kwargs):
        """
        THIN partial update - handles currency changes via service.
        """
        instance = self.get_object()

        if "domestic_currency" in request.data:
            return self._handle_currency_change(request, instance)

        response = super().partial_update(request, *args, **kwargs)
        return self._add_impersonation_context(response, request)

    def retrieve(self, request, *args, **kwargs):
        """
        THIN retrieve - adds impersonation context if needed.
        """
        response = super().retrieve(request, *args, **kwargs)
        return self._add_impersonation_context(response, request)

    def _handle_currency_change(self, request, instance):
        """
        Handle currency change with service-layer delegation.
        """
        new_currency = request.data["domestic_currency"]
        target_user = request.target_user

        logger.info(
            "Currency change request received",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": instance.workspace.id,
                "new_currency": new_currency,
                "current_currency": instance.domestic_currency,
                "action": "currency_change_request",
                "component": "WorkspaceSettingsViewSet",
            },
        )

        try:
            # Delegate to CurrencyService
            result = CurrencyService.change_workspace_currency(instance, new_currency)

            if result["changed"]:
                logger.info(
                    "Currency change completed successfully",
                    extra={
                        "request_user_id": request.user.id,
                        "workspace_id": instance.workspace.id,
                        "transactions_updated": result["transactions_updated"],
                        "action": "currency_change_success",
                        "component": "WorkspaceSettingsViewSet",
                    },
                )

            serializer = self.get_serializer(instance)
            response_data = {
                **serializer.data,
                "recalculation_details": {
                    "transactions_updated": result["transactions_updated"],
                    "currency_changed": result["changed"],
                },
            }

            return self._add_impersonation_context(Response(response_data), request)

        except Exception as e:
            logger.error(
                "Currency change failed",
                extra={
                    "request_user_id": request.user.id,
                    "workspace_id": instance.workspace.id,
                    "new_currency": new_currency,
                    "error": str(e),
                    "action": "currency_change_failed",
                    "component": "WorkspaceSettingsViewSet",
                    "severity": "high",
                },
            )

            error_response = {
                "error": "Currency update failed",
                "code": "currency_change_failed",
                "detail": str(e),
            }

            return self._add_impersonation_context(
                Response(error_response, status=status.HTTP_400_BAD_REQUEST), request
            )

    def _add_impersonation_context(self, response, request):
        """
        Add impersonation context to response if applicable.
        """
        if (
            request.is_admin_impersonation
            and response.status_code == status.HTTP_200_OK
            and isinstance(response.data, dict)
        ):

            response.data["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        return response


# -------------------------------------------------------------------
# USER SETTINGS MANAGEMENT
# -------------------------------------------------------------------
# User preferences and personalization


class UserSettingsViewSet(
    BaseWorkspaceViewSet,
    ServiceExceptionHandlerMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """
    THIN ViewSet for user settings management.
    Uses ServiceExceptionHandlerMixin for unified error handling.
    """

    serializer_class = UserSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        THIN queryset - filtered by target user.
        """
        target_user = self.request.target_user

        logger.debug(
            "Retrieving user settings queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "action": "user_settings_queryset",
                "component": "UserSettingsViewSet",
            },
        )

        return UserSettings.objects.filter(user=target_user.id)

    def partial_update(self, request, *args, **kwargs):
        """
        THIN partial update with field-level validation.
        """
        target_user = request.target_user

        # Validate allowed fields
        allowed_fields = {"language"}
        invalid_fields = [
            key for key in request.data.keys() if key not in allowed_fields
        ]

        if invalid_fields:
            logger.warning(
                "Invalid fields in user settings update",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "invalid_fields": invalid_fields,
                    "action": "user_settings_invalid_fields",
                    "component": "UserSettingsViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {
                    "error": f"Fields not allowed for update: {', '.join(invalid_fields)}"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        logger.info(
            "User settings update initiated",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "updated_fields": list(request.data.keys()),
                "action": "user_settings_update",
                "component": "UserSettingsViewSet",
            },
        )

        response = super().partial_update(request, *args, **kwargs)
        return self._add_impersonation_context(response, request)

    def retrieve(self, request, *args, **kwargs):
        """
        THIN retrieve with impersonation context.
        """
        response = super().retrieve(request, *args, **kwargs)
        return self._add_impersonation_context(response, request)

    def _add_impersonation_context(self, response, request):
        """
        Add impersonation context to response if applicable.
        """
        if (
            request.is_admin_impersonation
            and response.status_code == status.HTTP_200_OK
            and isinstance(response.data, dict)
        ):

            response.data["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        return response


# -------------------------------------------------------------------
# EXPENSE CATEGORIES MANAGEMENT
# -------------------------------------------------------------------
# Read-only access to expense category hierarchies


class ExpenseCategoryViewSet(
    BaseWorkspaceViewSet, ServiceExceptionHandlerMixin, viewsets.ReadOnlyModelViewSet
):
    """
    THIN ViewSet for expense categories with service exception handling.
    """

    serializer_class = ExpenseCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        THIN queryset - basic security filtering.
        """
        target_user = self.request.target_user

        logger.debug(
            "Retrieving expense categories queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "action": "expense_categories_queryset",
                "component": "ExpenseCategoryViewSet",
            },
        )

        active_versions = ExpenseCategoryVersion.objects.filter(
            workspace__members=target_user.id, is_active=True
        ).select_related("workspace")

        return (
            ExpenseCategory.objects.filter(version__in=active_versions)
            .select_related("version")
            .prefetch_related("property", "children")
        )

    @action(detail=True, methods=["get"])
    def usage(self, request, pk=None):
        """
        Check category usage with proper permission validation.
        """
        category = self.get_object()
        workspace = category.version.workspace
        target_user = request.target_user

        logger.debug(
            "Checking category usage",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "category_id": category.id,
                "workspace_id": workspace.id,
                "action": "category_usage_check",
                "component": "ExpenseCategoryViewSet",
            },
        )

        # Check workspace membership
        if not WorkspaceMembership.objects.filter(
            workspace=workspace, user=target_user
        ).exists():
            logger.warning(
                "User not member of category workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "action": "category_usage_access_denied",
                    "component": "ExpenseCategoryViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Check permissions
        user_role = self._get_user_role(workspace, target_user)
        if user_role not in ["editor", "admin", "owner"]:
            logger.warning(
                "Insufficient permissions for category usage check",
                extra={
                    "request_user_id": request.user.id,
                    "user_role": user_role,
                    "action": "category_usage_permission_denied",
                    "component": "ExpenseCategoryViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {
                    "error": "You need editor or higher permissions to check category usage."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        is_used = Transaction.objects.filter(expense_category=category).exists()

        response_data = {
            "category_id": category.id,
            "category_name": category.name,
            "level": category.level,
            "is_used": is_used,
            "can_be_moved": not is_used or category.level != 5,
            "move_restrictions": {
                "reason": (
                    "Used in transactions"
                    if is_used and category.level == 5
                    else "None"
                ),
                "requires_confirmation": category.level != 5 and not is_used,
            },
        }

        return Response(response_data)

    def _get_user_role(self, workspace, user):
        """
        Get user role in workspace using cached data.
        """
        memberships = getattr(self.request, "_cached_user_memberships", {})
        workspace_membership = memberships.get(workspace.id)
        return workspace_membership.get("role") if workspace_membership else None


# -------------------------------------------------------------------
# INCOME CATEGORIES MANAGEMENT
# -------------------------------------------------------------------
# Read-only access to income category hierarchies


class IncomeCategoryViewSet(
    BaseWorkspaceViewSet, ServiceExceptionHandlerMixin, viewsets.ReadOnlyModelViewSet
):
    """
    THIN ViewSet for income categories with service exception handling.
    Provides read-only access to income categories with proper workspace validation.
    """

    serializer_class = IncomeCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        THIN queryset - security filtered income categories.
        """
        target_user = self.request.target_user

        logger.debug(
            "Retrieving income categories queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "action": "income_categories_queryset",
                "component": "IncomeCategoryViewSet",
            },
        )

        active_versions = IncomeCategoryVersion.objects.filter(
            workspace__members=target_user.id, is_active=True
        ).select_related("workspace")

        return (
            IncomeCategory.objects.filter(version__in=active_versions)
            .select_related("version")
            .prefetch_related("property", "children")
        )

    @action(detail=True, methods=["get"])
    def usage(self, request, pk=None):
        """
        Check income category usage with permission validation.
        """
        category = self.get_object()
        workspace = category.version.workspace
        target_user = request.target_user

        logger.debug(
            "Checking income category usage",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "category_id": category.id,
                "workspace_id": workspace.id,
                "action": "income_category_usage_check",
                "component": "IncomeCategoryViewSet",
            },
        )

        # Validate workspace access
        if not self._has_workspace_access(workspace, target_user):
            logger.warning(
                "Workspace access denied for income category usage check",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "action": "income_category_usage_access_denied",
                    "component": "IncomeCategoryViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Check permissions
        if not self._has_editor_permissions(workspace, target_user):
            logger.warning(
                "Insufficient permissions for income category usage check",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "action": "income_category_usage_permission_denied",
                    "component": "IncomeCategoryViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {
                    "error": "You need editor or higher permissions to check category usage."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        is_used = Transaction.objects.filter(income_category=category).exists()

        response_data = {
            "category_id": category.id,
            "category_name": category.name,
            "level": category.level,
            "is_used": is_used,
            "can_be_moved": not is_used or category.level != 5,
            "move_restrictions": {
                "reason": (
                    "Used in transactions"
                    if is_used and category.level == 5
                    else "None"
                ),
                "requires_confirmation": category.level != 5 and not is_used,
            },
        }

        logger.info(
            "Income category usage check completed",
            extra={
                "category_id": category.id,
                "is_used": is_used,
                "can_be_moved": response_data["can_be_moved"],
                "action": "income_category_usage_check_completed",
                "component": "IncomeCategoryViewSet",
            },
        )

        return Response(response_data)

    def _has_workspace_access(self, workspace, user):
        """Check if user has access to workspace."""
        memberships = getattr(self.request, "_cached_user_memberships", {})
        return workspace.id in memberships

    def _has_editor_permissions(self, workspace, user):
        """Check if user has editor or higher permissions."""
        memberships = getattr(self.request, "_cached_user_memberships", {})
        workspace_membership = memberships.get(workspace.id)
        user_role = workspace_membership.get("role") if workspace_membership else None
        return user_role in ["editor", "admin", "owner"]


# -------------------------------------------------------------------
# CATEGORY SYNCHRONIZATION MANAGEMENT
# -------------------------------------------------------------------


class CategorySyncViewSet(BaseWorkspaceViewSet, ServiceExceptionHandlerMixin):
    """
    THIN ViewSet for category synchronization with service exception handling.
    Delegates all business logic to category_utils with proper validation.
    """

    permission_classes = [IsAuthenticated, IsWorkspaceEditor]

    @action(
        detail=False,
        methods=["post"],
        url_path="workspaces/(?P<workspace_id>[^/.]+)/(?P<category_type>expense|income)",
    )
    def sync_categories(self, request, workspace_id=None, category_type=None):
        """
        Synchronize category hierarchies with comprehensive validation.

        Args:
            request: HTTP request with category data
            workspace_id: Workspace ID for synchronization
            category_type: Type of categories ('expense' or 'income')

        Returns:
            Response: Synchronization results with admin context
        """
        logger.info(
            "Category synchronization initiated",
            extra={
                "user_id": request.user.id,
                "target_user_id": request.target_user.id,
                "workspace_id": workspace_id,
                "category_type": category_type,
                "category_count": (
                    len(request.data) if isinstance(request.data, list) else 0
                ),
                "action": "category_sync_start",
                "component": "CategorySyncViewSet",
            },
        )

        try:
            # Validate workspace existence
            if not request.user_permissions.get("workspace_exists"):
                logger.warning(
                    "Workspace not found for category sync",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace_id,
                        "action": "category_sync_workspace_not_found",
                        "component": "CategorySyncViewSet",
                        "severity": "medium",
                    },
                )
                return Response(
                    {"error": "Workspace not found"}, status=status.HTTP_404_NOT_FOUND
                )

            # Get workspace instance
            workspace = Workspace.objects.get(id=workspace_id)

            # Validate and resolve category type
            if category_type == "expense":
                version = get_object_or_404(
                    ExpenseCategoryVersion.objects.select_related("workspace"),
                    workspace=workspace,
                    is_active=True,
                )
                category_model = ExpenseCategory
            elif category_type == "income":
                version = get_object_or_404(
                    IncomeCategoryVersion.objects.select_related("workspace"),
                    workspace=workspace,
                    is_active=True,
                )
                category_model = IncomeCategory
            else:
                logger.warning(
                    "Invalid category type provided",
                    extra={
                        "user_id": request.user.id,
                        "category_type": category_type,
                        "action": "category_sync_invalid_type",
                        "component": "CategorySyncViewSet",
                        "severity": "medium",
                    },
                )
                return Response(
                    {"error": 'Invalid category type. Must be "expense" or "income".'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Execute synchronization with service exception handling
            results = self.handle_service_call(
                sync_categories_tree, request.data, version, category_model
            )

            response_data = results

            # Add impersonation context if applicable
            if request.is_admin_impersonation:
                response_data["admin_impersonation"] = {
                    "target_user_id": request.target_user.id,
                    "target_username": request.target_user.username,
                    "requested_by_admin_id": request.user.id,
                }

            logger.info(
                "Category synchronization completed successfully",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "category_type": category_type,
                    "results": results,
                    "action": "category_sync_success",
                    "component": "CategorySyncViewSet",
                },
            )

            return Response(response_data)

        except Exception as e:
            logger.error(
                "Category synchronization failed",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "category_type": category_type,
                    "error": str(e),
                    "action": "category_sync_failed",
                    "component": "CategorySyncViewSet",
                    "severity": "high",
                },
                exc_info=True,
            )

            return Response(
                {
                    "error": "Category synchronization failed",
                    "code": "sync_operation_failed",
                    "detail": str(e),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


# -------------------------------------------------------------------
# TRANSACTION MANAGEMENT
# -------------------------------------------------------------------
# Financial transaction CRUD with filtering and bulk operations


class TransactionViewSet(BaseWorkspaceViewSet, ServiceExceptionHandlerMixin):
    """
    COMPLETE THIN ViewSet for transaction management.
    Delegates ALL business logic to services and serializers.
    """

    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.transaction_service = TransactionService()
        self.draft_service = DraftService()

    def get_permissions(self):
        """
        THIN permissions - services handle business logic.
        """
        if self.action in [
            "create",
            "update",
            "partial_update",
            "destroy",
            "bulk_delete",
            "bulk_sync",
        ]:
            return [IsAuthenticated(), IsWorkspaceEditor()]
        return [IsAuthenticated(), IsWorkspaceMember()]

    def get_serializer_class(self):
        """
        Dynamic serializer selection for performance optimization.
        """
        light_mode = self.request.query_params.get("light") == "true"

        if light_mode and self.action == "list":
            logger.debug(
                "Lightweight serializer selected for transaction list",
                extra={
                    "user_id": self.request.user.id,
                    "action": "lightweight_transaction_serializer",
                    "component": "TransactionViewSet",
                },
            )
            return TransactionListSerializer

        return TransactionSerializer

    def get_queryset(self):
        """
        THIN queryset with performance optimizations.
        """
        target_user = self.request.target_user

        logger.debug(
            "Building transactions queryset",
            extra={
                "user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "action": "transactions_queryset_building",
                "component": "TransactionViewSet",
            },
        )

        # Get workspace_pk from URL
        workspace_pk = (
            self.kwargs.get("workspace_pk")
            or getattr(self.request, "workspace", None) and self.request.workspace.id
        )
        
        if not workspace_pk:
            logger.warning(
                "Transaction queryset requested without workspace_pk in URL.",
                extra={
                    "user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "action": "transactions_queryset_no_workspace_pk",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
            )

            # This should not happen with correct URL configuration, but as a safeguard:
            logger.warning("Transaction queryset requested without workspace_pk in URL.")
            return Transaction.objects.none()

        # Base queryset for the given workspace. Permissions are handled by IsWorkspaceEditor.
        qs = Transaction.objects.filter(workspace_id=workspace_pk)

        # Performance optimizations
        light_mode = self.request.query_params.get("light") == "true"
        if light_mode and self.action == "list": # Note: This is now part of get_serializer_class logic
            qs = qs.select_related("workspace").only(
                "id",
                "type",
                "amount_domestic",
                "original_amount",
                "original_currency",
                "date",
                "description",
                "tags",
                "workspace_id",
                "expense_category_id",
                "income_category_id",
            )
        else:
            qs = qs.select_related(
                "workspace", "workspace__settings", "user"
            ).prefetch_related("tags")

        # Apply filters
        tx_type = self.request.query_params.get("type")
        if tx_type in ["income", "expense"]:
            qs = qs.filter(type=tx_type)

        logger.info(
            "Transactions queryset prepared",
            extra={
                "user_id": self.request.user.id,
                "queryset_count": qs.count(),
                "workspace_id": workspace_pk,
                "filters_applied": {
                    "type": tx_type,
                },
                "action": "transactions_queryset_prepared",
                "component": "TransactionViewSet",
            },
        )

        return qs

    def perform_create(self, serializer):
        """
        THIN create - delegates to TransactionSerializer.
        """
        logger.debug(
            "Transaction creation delegated to serializer",
            extra={
                "user_id": self.request.user.id,
                "target_user_id": self.request.target_user.id,
                "action": "transaction_create_delegated",
                "component": "TransactionViewSet",
            },
        )

        # TransactionSerializer.create() handles all business logic
        serializer.save(user=self.request.target_user, workspace=self.request.workspace)

    def perform_update(self, serializer):
        """
        THIN update - delegates to TransactionSerializer.
        """
        logger.debug(
            "Transaction update delegated to serializer",
            extra={
                "user_id": self.request.user.id,
                "transaction_id": serializer.instance.id,
                "action": "transaction_update_delegated",
                "component": "TransactionViewSet",
            },
        )

        # TransactionSerializer.update() handles all business logic
        serializer.save()

    def perform_destroy(self, instance):
        """
        THIN delete - delegates to TransactionService.
        """
        target_user = self.request.target_user

        logger.info(
            "Transaction deletion delegated to service",
            extra={
                "user_id": self.request.user.id,
                "transaction_id": instance.id,
                "action": "transaction_delete_delegated",
                "component": "TransactionViewSet",
            },
        )

        self.handle_service_call(
            self.transaction_service.delete_transaction,
            transaction=instance,
            user=target_user,
        )

    '''@action(detail=False, methods=["post"])
    def bulk_delete(self, request):
        """
        THIN bulk delete - delegates to TransactionService.
        """
        transaction_ids = request.data.get("ids", [])
        target_user = request.target_user

        logger.info(
            "Bulk transaction delete delegated to service",
            extra={
                "user_id": request.user.id,
                "transaction_count": len(transaction_ids),
                "action": "bulk_delete_delegated",
                "component": "TransactionViewSet",
            },
        )

        result = self.handle_service_call(
            self.transaction_service.bulk_delete_transactions,
            transaction_ids=transaction_ids,
            user=target_user,
        )

        return self._add_impersonation_context(Response(result), request)'''

    @action(
        detail=False,
        methods=["post"],
        url_path="workspaces/(?P<workspace_id>[^/.]+)/bulk-sync",
    )
    def bulk_sync(self, request, workspace_id=None):
        """
        THIN bulk sync - delegates to TransactionService.
        """
        target_user = request.target_user

        logger.info(
            "Bulk transaction sync delegated to service",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_id,
                "action": "bulk_sync_delegated",
                "component": "TransactionViewSet",
            },
        )

        # Get workspace with validation
        workspace = self.handle_service_call(
            self._get_workspace_with_access, workspace_id=workspace_id, user=target_user
        )

        # Delegate sync to service
        results = self.handle_service_call(
            self.transaction_service.bulk_sync_transactions,
            transactions_data=request.data,
            workspace=workspace,
            user=target_user,
        )

        # Handle draft cleanup
        self._cleanup_drafts_after_sync(workspace, target_user, request.data)

        return self._add_impersonation_context(Response(results), request)

    def _get_workspace_with_access(self, workspace_id, user):
        """
        Get workspace with access validation.
        """
        try:
            return Workspace.objects.get(id=workspace_id, members=user.id)
        except Workspace.DoesNotExist:
            raise ValidationError("Workspace not found or access denied")

    def _cleanup_drafts_after_sync(self, workspace, user, transactions_data):
        """
        Cleanup drafts after successful sync.
        """
        transaction_types = set()
        for operation_type in ["create", "update"]:
            for tx in transactions_data.get(operation_type, []):
                if isinstance(tx, dict) and tx.get("type") in [
                    "income",
                    "expense",
                ]:
                    transaction_types.add(tx["type"])

        for draft_type in transaction_types:
            deleted_count = self.draft_service.cleanup_drafts_for_transaction(
                user=user, workspace_id=workspace.id, transaction_type=draft_type
            )

            if deleted_count > 0:
                logger.info(
                    "Drafts cleaned after bulk sync",
                    extra={
                        "user_id": user.id,
                        "workspace_id": workspace.id,
                        "draft_type": draft_type,
                        "drafts_deleted": deleted_count,
                        "action": "drafts_cleaned_after_sync",
                        "component": "TransactionViewSet",
                    },
                )

    def _add_impersonation_context(self, response, request):
        """
        Add impersonation context to response.
        """
        if (
            request.is_admin_impersonation
            and response.status_code == status.HTTP_200_OK
            and isinstance(response.data, dict)
        ):

            response.data["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        return response

# -------------------------------------------------------------------
# TAGS MANAGEMENT
# -------------------------------------------------------------------


class TagViewSet(BaseWorkspaceViewSet, ServiceExceptionHandlerMixin):
    """
    THIN ViewSet for managing Tags within a workspace.
    Delegates all business logic to the TagService.
    """

    serializer_class = TagSerializer
    permission_classes = [IsAuthenticated, IsWorkspaceMember]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_service = TagService()

    def get_permissions(self):
        """Editors can modify, members can only view."""
        if self.action in ["create", "update", "partial_update", "destroy"]:
            return [IsAuthenticated(), IsWorkspaceEditor()]
        return super().get_permissions()

    def get_queryset(self):
        """
        Returns tags scoped to the current workspace from the request context.
        """
        workspace = getattr(self.request, "workspace", None)
        if not workspace:
            # This should be caught by permission classes, but as a safeguard:
            logger.warning("Tag queryset requested without a workspace context.")
            return Tags.objects.none()

        return Tags.objects.filter(workspace=workspace)

    def perform_create(self, serializer):
        """
        Delegates tag creation to the TagService to handle `get_or_create` logic.
        """
        workspace = self.request.workspace
        tag_name = serializer.validated_data["name"]

        # The service handles finding or creating the tag.
        tag = self.handle_service_call(
            self.tag_service.get_or_create_tags,
            workspace=workspace,
            tag_names=[tag_name],
        )[0]

        # We need to set the instance on the serializer to return the correct data
        serializer.instance = tag

    def perform_update(self, serializer):
        """
        Delegates tag update to the TagService to handle validation.
        """
        new_name = serializer.validated_data.get("name", serializer.instance.name)
        self.handle_service_call(
            self.tag_service.update_tag, tag=serializer.instance, new_name=new_name
        )

    def perform_destroy(self, instance):
        """
        Delegates tag deletion to the TagService.
        """
        self.handle_service_call(self.tag_service.delete_tag, tag=instance)

    @action(
        detail=True,
        methods=["post"],
        url_path="assign-to-transaction",
        permission_classes=[IsAuthenticated, IsWorkspaceEditor],
    )
    def assign_to_transaction(self, request, pk=None):
        """
        This is an example action. A better approach is to handle tags
        during transaction creation/update or via a dedicated transaction action.
        For now, this demonstrates service delegation.
        """
        return Response(
            {"message": "This is an example. Tag assignment should be part of transaction operations."},
            status=status.HTTP_501_NOT_IMPLEMENTED
        )


# -------------------------------------------------------------------
# EXCHANGE RATES MANAGEMENT
# -------------------------------------------------------------------
# Currency exchange rate retrieval and filtering


class ExchangeRateViewSet(
    BaseWorkspaceViewSet, ServiceExceptionHandlerMixin, viewsets.GenericViewSet
):
    """
    THIN ViewSet for exchange rate retrieval with filtering.
    Uses ServiceExceptionHandlerMixin for unified error handling.
    """

    serializer_class = ExchangeRateSerializer
    permission_classes = [IsAuthenticated]
    queryset = ExchangeRate.objects.all()

    def get_queryset(self):
        """
        THIN queryset with currency and date filtering.
        """
        logger.debug(
            "Building exchange rates queryset",
            extra={
                "user_id": self.request.user.id,
                "query_params": dict(self.request.query_params),
                "action": "exchange_rates_queryset",
                "component": "ExchangeRateViewSet",
            },
        )

        qs = super().get_queryset()

        # Currency filtering
        currencies = self.request.query_params.get("currencies")
        if currencies:
            currency_list = [c.strip().upper() for c in currencies.split(",")]
            qs = qs.filter(currency__in=currency_list)

        # Date range filtering
        date_from = self.request.query_params.get("date_from")
        if date_from:
            qs = qs.filter(date__gte=date_from)

        date_to = self.request.query_params.get("date_to")
        if date_to:
            qs = qs.filter(date__lte=date_to)

        logger.info(
            "Exchange rates queryset prepared",
            extra={
                "user_id": self.request.user.id,
                "result_count": qs.count(),
                "filters_applied": {
                    "currencies": currencies,
                    "date_from": date_from,
                    "date_to": date_to,
                },
                "action": "exchange_rates_queryset_prepared",
                "component": "ExchangeRateViewSet",
            },
        )

        return qs


# -------------------------------------------------------------------
# TRANSACTION DRAFTS MANAGEMENT - OPTIMIZED
# -------------------------------------------------------------------
# Single draft operations per workspace with atomic replacement and cached permissions


class TransactionDraftViewSet(BaseWorkspaceViewSet, ServiceExceptionHandlerMixin):
    """
    THIN ViewSet for transaction draft management.
    Uses ServiceExceptionHandlerMixin for unified error handling.
    """

    serializer_class = TransactionDraftSerializer

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.draft_service = DraftService()

    def get_permissions(self):
        """
        THIN permissions - editor required for modifications.
        """
        if self.action in [
            "create",
            "update",
            "partial_update",
            "destroy",
            "save_draft",
            "discard",
        ]:
            return [IsAuthenticated(), IsWorkspaceEditor()]
        return [IsAuthenticated(), IsWorkspaceMember()]

    def get_queryset(self):
        """
        THIN queryset with optimized workspace filtering.
        """
        target_user = self.request.target_user

        logger.debug(
            "Building transaction drafts queryset",
            extra={
                "user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "action": "drafts_queryset",
                "component": "TransactionDraftViewSet",
            },
        )

        # Optimized filtering using cached workspace IDs
        if self.request.is_admin_impersonation and hasattr(
            self.request, "impersonation_workspace_ids"
        ):

            workspace_ids = self.request.impersonation_workspace_ids
            queryset = TransactionDraft.objects.filter(
                user=target_user, workspace_id__in=workspace_ids
            )
        else:
            queryset = TransactionDraft.objects.filter(
                user=target_user, workspace__members=target_user.id
            )

        return queryset.select_related("workspace", "user")

    @action(detail=False, methods=["post"])
    def save_draft(self, request, workspace_pk=None):
        """
        THIN save draft - delegates to DraftService.
        """
        target_user = request.target_user

        logger.info(
            "Draft save delegated to service",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_pk,
                "action": "draft_save_delegated",
                "component": "TransactionDraftViewSet",
            },
        )

        # Validate workspace access
        if not self._has_workspace_access(workspace_pk, request):
            raise PermissionDenied("You don't have access to this workspace")

        # Delegate to service
        draft = self.handle_service_call(
            self.draft_service.save_draft,
            user=target_user,
            workspace_id=workspace_pk,
            draft_type=request.data.get("draft_type"),
            transactions_data=request.data.get("transactions_data", []),
        )

        response_data = TransactionDraftSerializer(draft).data
        return self._add_impersonation_context(Response(response_data), request)

    @action(detail=False, methods=["get"])
    def get_workspace_draft(self, request, workspace_pk=None):
        """
        THIN get draft - delegates to DraftService.
        """
        target_user = request.target_user

        logger.debug(
            "Workspace draft retrieval delegated to service",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_pk,
                "draft_type": request.query_params.get("type"),
                "action": "workspace_draft_retrieval",
                "component": "TransactionDraftViewSet",
            },
        )

        # Validate workspace access
        if not self._has_workspace_access(workspace_pk, request):
            return Response(
                {"error": "You don't have access to this workspace."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            draft = self.handle_service_call(
                self.draft_service.get_workspace_draft,
                user=target_user,
                workspace_id=workspace_pk,
                draft_type=request.query_params.get("type"),
            )

            response_data = TransactionDraftSerializer(draft).data
            return self._add_impersonation_context(Response(response_data), request)

        except TransactionDraft.DoesNotExist:
            return Response({"transactions_data": []})

    def _has_workspace_access(self, workspace_id, request):
        """Check if user has access to workspace."""
        permissions_data = getattr(request, "user_permissions", {})
        workspace_exists = permissions_data.get("workspace_exists", False)
        current_workspace_id = permissions_data.get("current_workspace_id")
        return workspace_exists and current_workspace_id == int(workspace_id)

    def _add_impersonation_context(self, response, request):
        """Add impersonation context to response."""
        if (
            request.is_admin_impersonation
            and response.status_code == status.HTTP_200_OK
            and isinstance(response.data, dict)
        ):

            response.data["admin_impersonation"] = {
                "target_user_id": request.target_user.id,
                "target_username": request.target_user.username,
                "requested_by_admin_id": request.user.id,
            }

        return response
    
    @action(detail=True, methods=['delete'])
    def discard(self, request, pk=None):
        """
        THIN discard draft - delegates to DraftService.
        """
        target_user = request.target_user

        logger.info(
            "Draft discard delegated to service",
            extra={
                "user_id": request.user.id,
                "draft_id": pk,
                "action": "draft_discard_delegated",
                "component": "TransactionDraftViewSet",
            },
        )

        try:
            draft = self.get_object()
            
            # Delegate to service
            discarded = self.handle_service_call(
                self.draft_service.discard_draft,
                user=target_user,
                workspace_id=draft.workspace.id,
                draft_type=draft.draft_type,
            )

            if discarded:
                return Response(status=status.HTTP_204_NO_CONTENT)
            else:
                return Response(
                    {"error": "Draft not found or already discarded"},
                    status=status.HTTP_404_NOT_FOUND
                )

        except TransactionDraft.DoesNotExist:
            return Response(
                {"error": "Draft not found"},
                status=status.HTTP_404_NOT_FOUND
            )
