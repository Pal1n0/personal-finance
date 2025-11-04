"""
Core API views for financial management system.

This module provides viewsets and API endpoints for handling transactions,
user settings, workspace settings, categories, exchange rates, and bulk operations
in the financial management application.
"""

import logging
from datetime import date
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, mixins, serializers, status
from rest_framework.decorators import api_view, action
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from .permissions import IsWorkspaceMember, IsWorkspaceEditor, IsWorkspaceAdmin, IsWorkspaceOwner
from rest_framework.response import Response

from .models import (
    Transaction, UserSettings, Workspace, 
    WorkspaceSettings, WorkspaceMembership,
    ExpenseCategoryVersion, IncomeCategoryVersion, 
    ExpenseCategory, IncomeCategory, ExchangeRate,
    TransactionDraft
) 
from .serializers import (
    TransactionSerializer, UserSettingsSerializer, WorkspaceSettingsSerializer,
    ExchangeRateSerializer, ExpenseCategorySerializer, IncomeCategorySerializer,
    WorkspaceMembershipSerializer, WorkspaceSerializer, TransactionDraftSerializer,
    TransactionListSerializer 
)
from .services.transaction_service import TransactionService
from .services.currency_service import CurrencyService
from .utils.category_utils import sync_categories_tree
from .mixins import WorkspaceMembershipMixin

# Get structured logger for this module
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# WORKSPACE MANAGEMENT
# -------------------------------------------------------------------
# Workspace CRUD operations and membership management


class WorkspaceViewSet(WorkspaceMembershipMixin, viewsets.ModelViewSet):
    """
    ViewSet for managing workspaces and workspace memberships.
    
    Provides CRUD operations for workspaces with two-level deletion:
    - Soft delete (inactive): Temporary deactivation (admin/owner only)
    - Hard delete: Permanent removal (owner only)
    
    Security rules:
    - Viewers/editors can only see active workspaces
    - Only admins/owners can see inactive workspaces
    - Only admins/owners can perform soft delete
    - Only owners can perform hard delete
    
    Admin features:
    - Superusers can impersonate any user via user_id parameter
    - All operations are performed on behalf of the target user
    - Comprehensive logging for admin actions
    """
    
    serializer_class = WorkspaceSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """
        Dynamically assign permissions based on action type.
        """
        if self.action in ['create']:
            return [IsAuthenticated()]
        elif self.action in ['update', 'partial_update', 'destroy', 'activate']:
            return [IsAuthenticated(), IsWorkspaceAdmin()]
        elif self.action in ['hard_delete']:
            return [IsAuthenticated(), IsWorkspaceOwner()]
        return [IsAuthenticated(), IsWorkspaceMember()]

    def get_queryset(self):
        """
        Get workspaces based on user role with optimized queries.
        Supports admin impersonation.
        """
        logger.debug(
            "Retrieving workspaces queryset with role-based filtering",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": self.request.target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "action": "role_based_workspaces_retrieval",
                "component": "WorkspaceViewSet",
            },
        )

        if not self.request.user.is_authenticated:
            return Workspace.objects.none()
        
        target_user = self.request.target_user
        
        workspaces = Workspace.objects.filter(
            members=target_user.id
        ).select_related('owner').prefetch_related('members').annotate(
            member_count=models.Count('members')
        )
        
        memberships = self._get_user_memberships(self.request)
        has_admin_owner_role = any(
            m.role in ['admin', 'owner'] for m in memberships.values()
        )
        
        if not has_admin_owner_role:
            workspaces = workspaces.filter(is_active=True)
        
        logger.debug(
            "Workspaces queryset prepared",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "total_workspaces_count": workspaces.count(),
                "has_admin_owner_access": has_admin_owner_role,
                "action": "workspaces_queryset_prepared",
                "component": "WorkspaceViewSet",
            },
        )
        
        return workspaces

    def get_serializer_context(self):
        """Add additional context to serializer for frontend needs."""
        context = super().get_serializer_context()
        
        if self.request.user.is_authenticated:
            context['user_memberships'] = self._get_user_memberships(self.request)
        
        return context
    
    def list(self, request, *args, **kwargs):
        """
        Custom list method to provide additional metadata about workspaces.
        Supports admin impersonation.
        """
        response = super().list(request, *args, **kwargs)
        
        workspaces = self.get_queryset()
        active_count = workspaces.filter(is_active=True).count()
        inactive_count = workspaces.filter(is_active=False).count()
        
        target_user = request.target_user
        
        memberships = self._get_user_memberships(request)
        role_counts = {}
        for membership in memberships.values():
            role_counts[membership.role] = role_counts.get(membership.role, 0) + 1
        
        has_admin_owner_access = any(
            m.role in ['admin', 'owner'] for m in memberships.values()
        )
        
        response_data = {
            'workspaces': response.data,
            'summary': {
                'total_workspaces': workspaces.count(),
                'active_workspaces': active_count,
                'inactive_workspaces': inactive_count if has_admin_owner_access else 0,
                'role_distribution': role_counts,
                'access_level': 'admin_owner' if has_admin_owner_access else 'viewer_editor'
            }
        }
        
        if request.is_admin_impersonation:
            response_data['admin_impersonation'] = {
                'target_user_id': target_user.id,
                'target_username': target_user.username,
                'requested_by_admin_id': request.user.id
            }
        
        response.data = response_data
        
        return response

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve single workspace with additional security checks.
        Supports admin impersonation.
        """
        instance = self.get_object()
        
        target_user = request.target_user
        
        memberships = self._get_user_memberships(request)
        user_membership = memberships.get(instance.id)
        
        if not user_membership:
            logger.warning(
                "Membership not found for user in workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.id,
                    "action": "membership_not_found",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not instance.is_active and user_membership.role in ['viewer', 'editor']:
            logger.warning(
                "Viewer/editor attempted to access inactive workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.id,
                    "user_role": user_membership.role,
                    "action": "inactive_workspace_access_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You don't have permission to access this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = self.get_serializer(instance)
        
        response_data = serializer.data
        if request.is_admin_impersonation:
            response_data['admin_impersonation'] = {
                'target_user_id': target_user.id,
                'target_username': target_user.username,
                'requested_by_admin_id': request.user.id
            }
        
        return Response(response_data)
    
    def perform_create(self, serializer):
        """
        Create workspace with admin impersonation support.
        Admin can create workspace for target user.
        """
        target_user = self.request.target_user
        
        logger.info(
            "Workspace creation initiated",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "action": "workspace_creation_start",
                "component": "WorkspaceViewSet",
            },
        )
        
        workspace_data = serializer.validated_data
        if 'owner' not in workspace_data:
            instance = serializer.save(owner=target_user)
        else:
            instance = serializer.save()
        
        WorkspaceMembership.objects.create(
            workspace=instance,
            user=target_user,
            role='owner'
        )
        
        logger.info(
            "Workspace created successfully",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": instance.id,
                "workspace_name": instance.name,
                "action": "workspace_creation_success",
                "component": "WorkspaceViewSet",
            },
        )

    def perform_destroy(self, instance):
        """
        SOFT DELETE - set workspace as inactive (admin/owner only).
        Supports admin impersonation.
        """
        target_user = self.request.target_user
        
        logger.info(
            "Workspace soft deletion initiated",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "workspace_id": instance.id,
                "workspace_name": instance.name,
                "current_status": "active" if instance.is_active else "inactive",
                "action": "workspace_soft_deletion_start",
                "component": "WorkspaceViewSet",
            },
        )
        
        memberships = self._get_user_memberships(self.request)
        user_membership = memberships.get(instance.id)
        
        if not user_membership or user_membership.role not in ['admin', 'owner']:
            logger.warning(
                "Workspace soft deletion permission denied - insufficient role",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.id,
                    "user_role": user_membership.role if user_membership else None,
                    "required_roles": ['admin', 'owner'],
                    "action": "workspace_soft_deletion_permission_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError("Only workspace owners and admins can deactivate workspaces.")
        
        if not instance.is_active:
            logger.warning(
                "Attempt to deactivate already inactive workspace",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.id,
                    "action": "workspace_already_inactive",
                    "component": "WorkspaceViewSet",
                    "severity": "low",
                },
            )
            raise serializers.ValidationError("Workspace is already inactive.")
        
        instance.is_active = False
        instance.save()
        
        logger.info(
            "Workspace soft deleted successfully",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": instance.id,
                "previous_status": "active",
                "new_status": "inactive",
                "action": "workspace_soft_deletion_success",
                "component": "WorkspaceViewSet",
            },
        )

    @action(detail=True, methods=['delete'])
    @transaction.atomic
    def hard_delete(self, request, pk=None):
        """
        HARD DELETE - permanently remove workspace with comprehensive safety checks.
        Supports admin impersonation.
        """
        workspace = self.get_object()
        
        target_user = request.target_user
        
        logger.warning(
            "Workspace hard deletion initiated",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "workspace_owner_id": workspace.owner.id,
                "action": "workspace_hard_deletion_start",
                "component": "WorkspaceViewSet",
                "severity": "high",
            },
        )
        
        if workspace.owner != target_user:
            logger.error(
                "Workspace hard deletion permission denied - not owner",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "workspace_owner_id": workspace.owner.id,
                    "action": "workspace_hard_deletion_permission_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "high",
                },
            )
            return Response(
                {"error": "Only workspace owner can permanently delete the workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        other_members = workspace.members.exclude(id=target_user.id)
        if other_members.exists():
            member_count = other_members.count()
            logger.warning(
                "Workspace hard deletion blocked - other members exist",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "other_members_count": member_count,
                    "action": "workspace_hard_deletion_blocked_members",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {
                    "error": "Cannot delete workspace with other members.",
                    "detail": f"Workspace has {member_count} other member(s). Remove all members first.",
                    "member_count": member_count
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        confirmation = request.data.get('confirmation')
        workspace_name_confirmation = request.data.get('workspace_name')
        
        if not confirmation or confirmation != 'I understand this action is irreversible':
            return Response(
                {"error": "Confirmation required. Please confirm you understand this action is irreversible."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if workspace_name_confirmation != workspace.name:
            return Response(
                {"error": "Workspace name confirmation does not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        workspace_id = workspace.id
        workspace_name = workspace.name
        member_count = workspace.members.count()
        transaction_count = Transaction.objects.filter(workspace=workspace).count()
        
        try:
            workspace.delete()
            
            logger.critical(
                "Workspace hard deleted permanently",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "member_count": member_count,
                    "transaction_count": transaction_count,
                    "action": "workspace_hard_deletion_success",
                    "component": "WorkspaceViewSet",
                    "severity": "critical",
                },
            )
            
            return Response(
                {
                    "message": "Workspace permanently deleted.",
                    "details": {
                        "workspace_name": workspace_name,
                        "members_affected": member_count,
                        "transactions_deleted": transaction_count
                    }
                },
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(
                "Workspace hard deletion failed",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "workspace_hard_deletion_failure",
                    "component": "WorkspaceViewSet",
                    "severity": "critical",
                },
                exc_info=True,
            )
            return Response(
                {
                    "error": "Workspace deletion failed",
                    "detail": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """
        Activate an inactive workspace (admin/owner only).
        Supports admin impersonation.
        """
        workspace = self.get_object()
        
        target_user = request.target_user
        
        logger.info(
            "Workspace activation initiated",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "current_status": "active" if workspace.is_active else "inactive",
                "action": "workspace_activation_start",
                "component": "WorkspaceViewSet",
            },
        )
        
        memberships = self._get_user_memberships(request)
        user_membership = memberships.get(workspace.id)
        
        if not user_membership or user_membership.role not in ['admin', 'owner']:
            logger.warning(
                "Workspace activation permission denied",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "user_role": user_membership.role if user_membership else None,
                    "required_roles": ['admin', 'owner'],
                    "action": "workspace_activation_permission_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You don't have permission to activate this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if workspace.is_active:
            logger.warning(
                "Attempt to activate already active workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "action": "workspace_already_active",
                    "component": "WorkspaceViewSet",
                    "severity": "low",
                },
            )
            return Response(
                {"error": "Workspace is already active."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        workspace.is_active = True
        workspace.save()
        
        logger.info(
            "Workspace activated successfully",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": workspace.id,
                "previous_status": "inactive",
                "new_status": "active",
                "action": "workspace_activation_success",
                "component": "WorkspaceViewSet",
            },
        )
        
        response_data = {
            "message": "Workspace activated successfully.", 
            "is_active": True
        }
        
        if request.is_admin_impersonation:
            response_data['admin_impersonation'] = {
                'target_user_id': target_user.id,
                'target_username': target_user.username,
                'requested_by_admin_id': request.user.id
            }
        
        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'])
    def membership_info(self, request, pk=None):
        """
        Get detailed membership information for current user in this workspace.
        Supports admin impersonation.
        """
        workspace = self.get_object()
        
        target_user = request.target_user
        
        logger.debug(
            "Retrieving detailed membership info",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace.id,
                "action": "membership_info_retrieval",
                "component": "WorkspaceViewSet",
            },
        )
        
        memberships = self._get_user_memberships(request)
        user_membership = memberships.get(workspace.id)
        
        if not user_membership:
            logger.warning(
                "Membership not found for user in workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "action": "membership_not_found",
                    "component": "WorkspaceViewSet",
                    "severity": "low",
                },
            )
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if not workspace.is_active and user_membership.role in ['viewer', 'editor']:
            logger.warning(
                "Viewer/editor attempted to access membership info for inactive workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "user_role": user_membership.role,
                    "action": "inactive_workspace_membership_access_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You don't have permission to access this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = WorkspaceMembershipSerializer(
            user_membership, 
            context={'request': request}
        )
        
        response_data = {
            **serializer.data,
            'permissions': {
                'can_activate': user_membership.role in ['admin', 'owner'] and not workspace.is_active,
                'can_deactivate': user_membership.role in ['admin', 'owner'] and workspace.is_active,
                'can_hard_delete': workspace.owner == target_user,
                'can_invite': user_membership.role in ['admin', 'owner'] and workspace.is_active,
                'can_manage_members': user_membership.role in ['admin', 'owner'] and workspace.is_active,
                'can_view': workspace.is_active or user_membership.role in ['admin', 'owner'],
                'can_edit': user_membership.role in ['admin', 'owner'] and workspace.is_active,
                'can_see_inactive': user_membership.role in ['admin', 'owner'],
            }
        }
        
        if request.is_admin_impersonation:
            response_data['admin_impersonation'] = {
                'target_user_id': target_user.id,
                'target_username': target_user.username,
                'requested_by_admin_id': request.user.id
            }
        
        logger.debug(
            "Membership info retrieved successfully",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": workspace.id,
                "user_role": user_membership.role,
                "is_owner": workspace.owner == target_user,
                "workspace_active": workspace.is_active,
                "action": "membership_info_retrieved",
                "component": "WorkspaceViewSet",
            },
        )
        
        return Response(response_data)
        
    @action(detail=True, methods=['get'])
    def members(self, request, pk=None):
        """
        Get all members of this workspace with their roles.
        
        Returns serialized list of workspace members with membership details.
        Supports admin impersonation.
        """
        workspace = self.get_object()
        
        target_user = request.target_user
        
        logger.debug(
            "Retrieving workspace members",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace.id,
                "action": "workspace_members_retrieval",
                "component": "WorkspaceViewSet",
            },
        )
        
        memberships = self._get_user_memberships(request)
        user_membership = memberships.get(workspace.id)
        
        if not user_membership:
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not workspace.is_active and user_membership.role in ['viewer', 'editor']:
            logger.warning(
                "Viewer/editor attempted to access members of inactive workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "user_role": user_membership.role,
                    "action": "inactive_workspace_members_access_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You don't have permission to access this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        all_memberships = WorkspaceMembership.objects.filter(
            workspace=workspace
        ).select_related('user')
        
        members_data = []
        for membership in all_memberships:
            members_data.append({
                'user_id': membership.user.id,
                'username': membership.user.username,
                'email': membership.user.email,
                'role': membership.role,
                'joined_at': membership.joined_at,
                'is_owner': workspace.owner == membership.user
            })
        
        response_data = {
            'workspace_id': workspace.id,
            'workspace_name': workspace.name,
            'members': members_data,
            'total_members': len(members_data)
        }
        
        if request.is_admin_impersonation:
            response_data['admin_impersonation'] = {
                'target_user_id': target_user.id,
                'target_username': target_user.username,
                'requested_by_admin_id': request.user.id
            }
        
        logger.debug(
            "Workspace members retrieved successfully",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": workspace.id,
                "member_count": len(members_data),
                "action": "workspace_members_retrieved",
                "component": "WorkspaceViewSet",
            },
        )
        
        return Response(response_data)
    
    @action(detail=True, methods=['get'])
    def workspace_settings(self, request, pk=None):
        """
        Get workspace settings.
        
        Returns workspace settings with additional context.
        Supports admin impersonation.
        """
        workspace = self.get_object()
        
        target_user = request.target_user
        
        logger.debug(
            "Retrieving workspace settings",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace.id,
                "action": "workspace_settings_retrieval",
                "component": "WorkspaceViewSet",
            },
        )
        
        memberships = self._get_user_memberships(request)
        user_membership = memberships.get(workspace.id)
        
        if not user_membership:
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if not workspace.is_active and user_membership.role in ['viewer', 'editor']:
            logger.warning(
                "Viewer/editor attempted to access settings of inactive workspace",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id,
                    "user_role": user_membership.role,
                    "action": "inactive_workspace_settings_access_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": "You don't have permission to access this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        settings, created = WorkspaceSettings.objects.get_or_create(
            workspace=workspace,
            defaults={
                'domestic_currency': 'EUR',
                'fiscal_year_start': 1,
                'display_mode': 'month',
                'accounting_mode': False
            }
        )
        
        if created:
            logger.info(
                "Default workspace settings created",
                extra={
                    "workspace_id": workspace.id,
                    "action": "default_workspace_settings_created",
                    "component": "WorkspaceViewSet",
                },
            )
        
        settings_data = {
            'workspace_id': workspace.id,
            'domestic_currency': settings.domestic_currency,
            'fiscal_year_start': settings.fiscal_year_start,
            'display_mode': settings.display_mode,
            'accounting_mode': settings.accounting_mode,
            'available_currencies': ['EUR', 'USD', 'GBP', 'CHF', 'PLN', 'CZK'],
            'fiscal_year_start_options': [
                {'value': 1, 'label': 'January'},
                {'value': 2, 'label': 'February'},
                {'value': 3, 'label': 'March'},
                {'value': 4, 'label': 'April'},
                {'value': 5, 'label': 'May'},
                {'value': 6, 'label': 'June'},
                {'value': 7, 'label': 'July'},
                {'value': 8, 'label': 'August'},
                {'value': 9, 'label': 'September'},
                {'value': 10, 'label': 'October'},
                {'value': 11, 'label': 'November'},
                {'value': 12, 'label': 'December'},
            ],
            'display_mode_options': [
                {'value': 'month', 'label': 'Month only'},
                {'value': 'day', 'label': 'Full date'}
            ]
        }
        
        if request.is_admin_impersonation:
            settings_data['admin_impersonation'] = {
                'target_user_id': target_user.id,
                'target_username': target_user.username,
                'requested_by_admin_id': request.user.id
            }
        
        logger.debug(
            "Workspace settings retrieved successfully",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": workspace.id,
                "domestic_currency": settings.domestic_currency,
                "action": "workspace_settings_retrieved",
                "component": "WorkspaceViewSet",
            },
        )
        
        return Response(settings_data)
    
# -------------------------------------------------------------------
# WORKSPACE SETTINGS MANAGEMENT  
# -------------------------------------------------------------------
# Workspace configuration with atomic currency changes


class WorkspaceSettingsViewSet(WorkspaceMembershipMixin, mixins.RetrieveModelMixin,
                              mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    ViewSet for managing workspace-specific settings with atomic currency changes
    and admin impersonation support.
    """
    
    serializer_class = WorkspaceSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """
        Dynamically assign permissions based on action type.
        """
        if self.action in ['update', 'partial_update']:
            return [IsAuthenticated(), IsWorkspaceAdmin()]
        return [IsAuthenticated(), IsWorkspaceMember()]

    def get_queryset(self):
        """
        Get workspace settings queryset filtered by user membership with impersonation support.
        """
        target_user = self.request.target_user
        
        logger.debug(
            "Retrieving workspace settings queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "action": "workspace_queryset_retrieval", 
                "component": "WorkspaceSettingsViewSet",
            },
        )
        return WorkspaceSettings.objects.filter(workspace__members=target_user.id).select_related('workspace')

    def update(self, request, *args, **kwargs):
        """
        Update workspace settings with atomic currency change handling and impersonation support.
        """
        instance = self.get_object()
        
        target_user = request.target_user
        
        memberships = self._get_user_memberships(request)
        user_membership = memberships.get(instance.workspace.id)
        
        if not user_membership or user_membership.role not in ['admin', 'owner']:
            logger.warning(
                "Workspace settings update permission denied",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.workspace.id,
                    "user_role": user_membership.role if user_membership else None,
                    "required_roles": ['admin', 'owner'],
                    "action": "workspace_settings_update_permission_denied",
                    "component": "WorkspaceSettingsViewSet",
                    "severity": "medium",
                },
            )
            raise PermissionDenied("You don't have permission to update workspace settings")
        
        if 'domestic_currency' in request.data:
            return self._handle_currency_change(request, instance)
        
        response = super().update(request, *args, **kwargs)
        
        if request.is_admin_impersonation and response.status_code == status.HTTP_200_OK:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': target_user.id,
                    'target_username': target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response

    def partial_update(self, request, *args, **kwargs):
        """
        Partial update with atomic currency change handling and impersonation support.
        """
        instance = self.get_object()
        
        target_user = request.target_user
        
        memberships = self._get_user_memberships(request)
        user_membership = memberships.get(instance.workspace.id)
        
        if not user_membership or user_membership.role not in ['admin', 'owner']:
            logger.warning(
                "Workspace settings partial update permission denied",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.workspace.id,
                    "user_role": user_membership.role if user_membership else None,
                    "required_roles": ['admin', 'owner'],
                    "action": "workspace_settings_partial_update_permission_denied",
                    "component": "WorkspaceSettingsViewSet",
                    "severity": "medium",
                },
            )
            raise PermissionDenied("You don't have permission to update workspace settings")
        
        if 'domestic_currency' in request.data:
            return self._handle_currency_change(request, instance)
        
        response = super().partial_update(request, *args, **kwargs)
        
        if request.is_admin_impersonation and response.status_code == status.HTTP_200_OK:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': target_user.id,
                    'target_username': target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve workspace settings with impersonation support.
        """
        response = super().retrieve(request, *args, **kwargs)
        
        if request.is_admin_impersonation:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': request.target_user.id,
                    'target_username': request.target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response
    
    def _handle_currency_change(self, request, instance):
        """
        Handle currency change with atomic transaction recalculation and impersonation support.
        """
        new_currency = request.data['domestic_currency']
        
        target_user = request.target_user
        
        logger.info(
            "Currency change request received",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_settings_id": instance.id,
                "workspace_id": instance.workspace.id,
                "new_currency": new_currency,
                "current_currency": instance.domestic_currency,
                "action": "currency_change_request",
                "component": "WorkspaceSettingsViewSet",
            },
        )
        
        try:
            result = CurrencyService.change_workspace_currency(instance, new_currency)
            
            if result['changed']:
                logger.info(
                    "Currency change completed successfully via API",
                    extra={
                        "request_user_id": request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_settings_id": instance.id,
                        "transactions_updated": result['transactions_updated'],
                        "action": "currency_change_api_success",
                        "component": "WorkspaceSettingsViewSet",
                    },
                )
                
                serializer = self.get_serializer(instance)
                response_data = {
                    **serializer.data,
                    "recalculation_details": {
                        "transactions_updated": result['transactions_updated'],
                        "currency_changed": True
                    }
                }
                
                if request.is_admin_impersonation:
                    response_data['admin_impersonation'] = {
                        'target_user_id': target_user.id,
                        'target_username': target_user.username,
                        'requested_by_admin_id': request.user.id
                    }
                
                return Response(response_data)
                
            else:
                serializer = self.get_serializer(instance)
                response_data = serializer.data
                
                if request.is_admin_impersonation:
                    response_data['admin_impersonation'] = {
                        'target_user_id': target_user.id,
                        'target_username': target_user.username,
                        'requested_by_admin_id': request.user.id
                    }
                
                return Response(response_data)
                
        except Exception as e:
            logger.error(
                "Currency change API request failed",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "is_admin_impersonation": request.is_admin_impersonation,
                    "workspace_settings_id": instance.id,
                    "workspace_id": instance.workspace.id,
                    "new_currency": new_currency,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "currency_change_api_failure",
                    "component": "WorkspaceSettingsViewSet",
                    "severity": "high",
                },
                exc_info=True,
            )
            
            error_response = {
                "error": "Currency update failed",
                "code": "currency_change_failed",
                "detail": str(e)
            }
            
            if request.is_admin_impersonation:
                error_response['admin_impersonation'] = {
                    'target_user_id': target_user.id,
                    'target_username': target_user.username,
                    'requested_by_admin_id': request.user.id
                }
            
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)
        
# -------------------------------------------------------------------
# USER SETTINGS MANAGEMENT
# -------------------------------------------------------------------
# User preferences and personalization


class UserSettingsViewSet(mixins.RetrieveModelMixin,
                         mixins.UpdateModelMixin,
                         viewsets.GenericViewSet):
    """
    ViewSet for managing user-specific settings with admin impersonation support.
    
    Provides retrieve and update operations for user settings with field-level
    validation and security controls.
    """
    
    serializer_class = UserSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get user settings queryset filtered by target user (supports admin impersonation).
        """
        # Use target_user for all queries
        target_user = self.request.target_user
        
        logger.debug(
            "Retrieving user settings queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "action": "queryset_retrieval",
                "component": "UserSettingsViewSet",
            },
        )
        return UserSettings.objects.filter(user=target_user.id)

    def partial_update(self, request, *args, **kwargs):
        """
        Partially update user settings with field-level validation and impersonation support.
        
        Args:
            request: HTTP request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
            
        Returns:
            Response: DRF Response object with update result
            
        Raises:
            ValidationError: If unauthorized fields are attempted to be updated
        """
        # Use target_user for permission checks
        target_user = request.target_user
        
        allowed_fields = {'language'}
        invalid_fields = [key for key in request.data.keys() if key not in allowed_fields]
        
        if invalid_fields:
            logger.warning(
                "User settings update attempted with invalid fields",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "is_admin_impersonation": request.is_admin_impersonation,
                    "invalid_fields": invalid_fields,
                    "allowed_fields": list(allowed_fields),
                    "action": "settings_update_validation_failed",
                    "component": "UserSettingsViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {"error": f"Fields not allowed for update: {', '.join(invalid_fields)}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.info(
            "User settings update initiated",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "updated_fields": list(request.data.keys()),
                "action": "settings_update_start",
                "component": "UserSettingsViewSet",
            },
        )
        
        response = super().partial_update(request, *args, **kwargs)
        
        # Add admin impersonation info if applicable
        if request.is_admin_impersonation and response.status_code == status.HTTP_200_OK:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': target_user.id,
                    'target_username': target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve user settings with impersonation support.
        """
        response = super().retrieve(request, *args, **kwargs)
        
        # Add admin impersonation info if applicable
        if request.is_admin_impersonation:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': request.target_user.id,
                    'target_username': request.target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response
        
# -------------------------------------------------------------------
# EXPENSE CATEGORIES MANAGEMENT
# -------------------------------------------------------------------
# Read-only access to expense category hierarchies


class ExpenseCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving expense categories with admin impersonation support.
    
    Provides read-only access to expense categories from active workspace versions
    where the target user is a member.
    """
    
    serializer_class = ExpenseCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get expense categories from active workspace versions for target user.
        
        Returns:
            QuerySet: Filtered expense categories with prefetched properties
        """
        target_user = self.request.target_user
        
        logger.debug(
            "Retrieving expense categories queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "action": "expense_categories_retrieval",
                "component": "ExpenseCategoryViewSet",
            },
        )
        
        active_versions = ExpenseCategoryVersion.objects.filter(
            workspace__members=target_user.id,
            is_active=True
        ).select_related('workspace')
        
        categories = ExpenseCategory.objects.filter(version__in=active_versions)\
            .select_related('version')\
            .prefetch_related('property', 'children')
            
        logger.debug(
            "Expense categories queryset prepared",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "active_versions_count": active_versions.count(),
                "categories_count": categories.count(),
                "action": "expense_categories_queryset_prepared",
                "component": "ExpenseCategoryViewSet",
            },
        )
        
        return categories

    def list(self, request, *args, **kwargs):
        """
        List expense categories with impersonation support.
        """
        response = super().list(request, *args, **kwargs)
        
        if request.is_admin_impersonation:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': request.target_user.id,
                    'target_username': request.target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve expense category with impersonation support.
        """
        response = super().retrieve(request, *args, **kwargs)
        
        if request.is_admin_impersonation:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': request.target_user.id,
                    'target_username': request.target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response
    

# -------------------------------------------------------------------
# INCOME CATEGORIES MANAGEMENT  
# -------------------------------------------------------------------
# Read-only access to income category hierarchies


class IncomeCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving income categories with admin impersonation support.
    
    Provides read-only access to income categories from active workspace versions
    where the target user is a member.
    """
    
    serializer_class = IncomeCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get income categories from active workspace versions for target user.
        
        Returns:
            QuerySet: Filtered income categories with prefetched properties
        """
        target_user = self.request.target_user
        
        logger.debug(
            "Retrieving income categories queryset",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "action": "income_categories_retrieval",
                "component": "IncomeCategoryViewSet",
            },
        )
        
        active_versions = IncomeCategoryVersion.objects.filter(
            workspace__members=target_user.id,
            is_active=True
        ).select_related('workspace')
        
        categories = IncomeCategory.objects.filter(version__in=active_versions)\
            .select_related('version')\
            .prefetch_related('property', 'children')
            
        logger.debug(
            "Income categories queryset prepared",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "active_versions_count": active_versions.count(),
                "categories_count": categories.count(),
                "action": "income_categories_queryset_prepared",
                "component": "IncomeCategoryViewSet",
            },
        )
        
        return categories

    def list(self, request, *args, **kwargs):
        """
        List income categories with impersonation support.
        """
        response = super().list(request, *args, **kwargs)
        
        if request.is_admin_impersonation:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': request.target_user.id,
                    'target_username': request.target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve income category with impersonation support.
        """
        response = super().retrieve(request, *args, **kwargs)
        
        if request.is_admin_impersonation:
            response_data = response.data
            if isinstance(response_data, dict):
                response_data['admin_impersonation'] = {
                    'target_user_id': request.target_user.id,
                    'target_username': request.target_user.username,
                    'requested_by_admin_id': request.user.id
                }
                response.data = response_data
        
        return response
    
# -------------------------------------------------------------------
# TRANSACTION MANAGEMENT
# -------------------------------------------------------------------
# Financial transaction CRUD with filtering and bulk operations


class TransactionViewSet(WorkspaceMembershipMixin, viewsets.ModelViewSet):
    """
    ViewSet for managing financial transactions with role-based permissions.
    
    Permission rules:
    - Viewers: Read-only access (list, retrieve)
    - Editors/Admins/Owners: Full CRUD + bulk operations
    - All users must be workspace members
    
    Security features:
    - Automatic user assignment from request
    - Workspace membership validation
    - Category workspace validation
    - Atomic bulk operations
    - Automatic draft cleanup
    - Comprehensive logging
    
    Admin features:
    - Superusers can impersonate any user via user_id parameter
    - All operations are performed on behalf of the target user

    Features:
    - Lightweight mode for optimized list views (light=true parameter)
    - Full detail mode for complete transaction data

    """
    
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """
        Dynamically assign permissions based on action type.
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy', 'bulk_delete', 'bulk_sync']:
            return [IsAuthenticated(), IsWorkspaceEditor()]
        return [IsAuthenticated(), IsWorkspaceMember()]

    def get_serializer_class(self):
        """
        Dynamically select serializer based on light mode parameter.
        
        Returns:
            Serializer: TransactionListSerializer for lightweight list views,
                       TransactionSerializer for all other cases
        """
        light_mode = self.request.query_params.get('light') == 'true'
        
        if light_mode and self.action == 'list':
            logger.debug(
                "Selected TransactionListSerializer for lightweight list view",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": self.request.target_user.id,
                    "action": "lightweight_serializer_selected",
                    "component": "TransactionViewSet",
                },
            )
            return TransactionListSerializer
        
        logger.debug(
            "Selected TransactionSerializer for full detail view",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": self.request.target_user.id,
                "action_type": self.action,
                "light_mode": light_mode,
                "action": "full_serializer_selected",
                "component": "TransactionViewSet",
            },
        )
        return TransactionSerializer

    def get_queryset(self):
        """
        Get transactions queryset with advanced filtering, security, and optional lightweight optimization.
        
        Supports:
        - Lightweight mode for performance-optimized list views
        - Full detail mode for complete transaction data
        - Advanced filtering by type, date, workspace, and fiscal year
        - Admin impersonation support
        - Comprehensive security validation
        """
        logger.debug(
            "Retrieving transactions queryset with lightweight optimization",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": self.request.target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "query_params": dict(self.request.query_params),
                "action": "transactions_queryset_retrieval",
                "component": "TransactionViewSet",
            },
        )
        
        target_user = self.request.target_user
        
        # Base security-filtered queryset
        qs = Transaction.objects.for_user(
            user=target_user
        ).filter(
            workspace__members=target_user.id
        )

        # LIGHTWEIGHT OPTIMIZATION - Apply only for list views with light parameter
        light_mode = self.request.query_params.get('light') == 'true'
        
        if light_mode and self.action == 'list':
            # Lightweight mode - optimized for performance
            qs = qs.select_related('workspace').only(
                'id', 'type', 'amount_domestic', 'original_amount', 'original_currency',
                'date', 'description', 'tags', 'workspace_id',
                'expense_category_id', 'income_category_id'
            )
            
            logger.info(
                "Applied lightweight optimization to transactions queryset",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "optimization_type": "lightweight_mode",
                    "selected_fields_count": 11,
                    "join_count": 1,
                    "action": "lightweight_optimization_applied",
                    "component": "TransactionViewSet",
                },
            )
        else:
            # Full detail mode - complete relations for full functionality
            qs = qs.select_related(
                'workspace', 'workspace__settings', 'expense_category__version', 'income_category__version', 'user'
            ).prefetch_related('tags')
            
            logger.debug(
                "Applied full relations to transactions queryset",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "optimization_type": "full_detail_mode",
                    "join_count": 5,
                    "action": "full_relations_applied",
                    "component": "TransactionViewSet",
                },
            )

        # APPLY FILTERS (existing filtering logic preserved)
        tx_type = self.request.query_params.get('type')
        fiscal_year = self.request.query_params.get('fiscal_year')
        month = self.request.query_params.get('month')

        if tx_type in ['income', 'expense']:
            qs = qs.filter(type=tx_type)
            logger.debug(
                "Applied transaction type filter",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "transaction_type": tx_type,
                    "action": "transaction_type_filter_applied",
                    "component": "TransactionViewSet",
                },
            )

        workspace_id = self.request.query_params.get('workspace')
        if workspace_id:
            try:
                workspace_settings = WorkspaceSettings.objects.select_related('workspace').get(
                    workspace_id=workspace_id,
                    workspace__members=target_user.id
                )
                fiscal_start_month = workspace_settings.fiscal_year_start

                if fiscal_year:
                    fiscal_year = int(fiscal_year)
                    start_date = date(fiscal_year - 1, fiscal_start_month, 1) if fiscal_start_month > 1 else date(fiscal_year, 1, 1)
                    end_date = date(fiscal_year, fiscal_start_month, 1) if fiscal_start_month > 1 else date(fiscal_year, 12, 31)
                    qs = qs.filter(date__gte=start_date, date__lt=end_date)
                    
                    logger.debug(
                        "Applied fiscal year filter",
                        extra={
                            "request_user_id": self.request.user.id,
                            "target_user_id": target_user.id,
                            "workspace_id": workspace_id,
                            "fiscal_year": fiscal_year,
                            "fiscal_start_month": fiscal_start_month,
                            "action": "fiscal_year_filter_applied",
                            "component": "TransactionViewSet",
                        },
                    )

            except WorkspaceSettings.DoesNotExist:
                logger.warning(
                    "Workspace settings not found for fiscal year filtering",
                    extra={
                        "request_user_id": self.request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "action": "workspace_settings_not_found",
                        "component": "TransactionViewSet",
                        "severity": "low",
                    },
                )

        if month:
            month = int(month)
            qs = qs.filter(date__month=month)
            logger.debug(
                "Applied month filter",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "month": month,
                    "action": "month_filter_applied",
                    "component": "TransactionViewSet",
                },
            )

        logger.info(
            "Transactions queryset prepared with filters and optimization",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "final_queryset_count": qs.count(),
                "optimization_mode": "lightweight" if (light_mode and self.action == 'list') else "full",
                "filters_applied": {
                    "type": tx_type,
                    "fiscal_year": fiscal_year,
                    "month": month,
                    "workspace": workspace_id,
                },
                "action": "transactions_queryset_prepared",
                "component": "TransactionViewSet",
            },
        )
        
        return qs
    
    def perform_create(self, serializer):
        """
        Create a new transaction with comprehensive validation and security.
        Supports admin impersonation.
        """
        workspace = serializer.validated_data.get('workspace')
        target_user = self.request.target_user
        
        logger.info(
            "Transaction creation initiated",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "workspace_id": workspace.id if workspace else None,
                "action": "transaction_creation_start",
                "component": "TransactionViewSet",
            },
        )
        
        memberships = self._get_user_memberships(self.request)
        user_membership = memberships.get(workspace.id)
        
        if not user_membership or user_membership.role not in ['editor', 'admin', 'owner']:
            logger.warning(
                "Workspace editor permission denied for transaction creation",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id if workspace else None,
                    "user_role": user_membership.role if user_membership else None,
                    "action": "workspace_editor_permission_denied",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
            )
            raise PermissionDenied("You don't have permission to create transactions in this workspace")

        if workspace and workspace.members.filter(id=target_user.id).exists():
            expense_category = serializer.validated_data.get('expense_category')
            income_category = serializer.validated_data.get('income_category')
            
            if expense_category and expense_category.version.workspace != workspace:
                logger.warning(
                    "Expense category workspace validation failed",
                    extra={
                        "request_user_id": self.request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace.id,
                        "expense_category_id": expense_category.id,
                        "category_workspace_id": expense_category.version.workspace.id,
                        "action": "category_workspace_validation_failed",
                        "component": "TransactionViewSet",
                        "severity": "medium",
                    },
                )
                raise serializers.ValidationError("Expense category does not belong to this workspace")
                
            if income_category and income_category.version.workspace != workspace:
                logger.warning(
                    "Income category workspace validation failed",
                    extra={
                        "request_user_id": self.request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace.id,
                        "income_category_id": income_category.id,
                        "category_workspace_id": income_category.version.workspace.id,
                        "action": "category_workspace_validation_failed",
                        "component": "TransactionViewSet",
                        "severity": "medium",
                    },
                )
                raise serializers.ValidationError("Income category does not belong to this workspace")
            
            instance = serializer.save(user=target_user)
            
            if instance.date:
                instance.month = instance.date.replace(day=1)
                instance.save(update_fields=['month'])

            draft_type = instance.type
            deleted_count, _ = TransactionDraft.objects.filter(
                user=target_user,
                workspace=workspace,
                draft_type=draft_type
            ).delete()
            
            if deleted_count > 0:
                logger.info(
                    "Transaction draft deleted after successful save",
                    extra={
                        "request_user_id": self.request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace.id,
                        "transaction_type": draft_type,
                        "drafts_deleted": deleted_count,
                        "action": "draft_cleaned_after_save",
                        "component": "TransactionViewSet",
                    },
                )
                
            logger.info(
                "Transaction created successfully",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "transaction_id": instance.id,
                    "workspace_id": workspace.id,
                    "transaction_type": instance.type,
                    "original_amount": float(instance.original_amount) if instance.original_amount else None,
                    "action": "transaction_creation_success",
                    "component": "TransactionViewSet",
                },
            )
        else:
            logger.warning(
                "Workspace access denied for transaction creation",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace.id if workspace else None,
                    "action": "workspace_access_denied",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
            )
            raise serializers.ValidationError("You don't have access to this workspace")

    def perform_update(self, serializer):
        """
        Update an existing transaction with permission validation.
        Supports admin impersonation.
        """
        instance = serializer.instance
        target_user = self.request.target_user
        
        logger.info(
            "Transaction update initiated",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "transaction_id": instance.id,
                "action": "transaction_update_start",
                "component": "TransactionViewSet",
            },
        )
        
        memberships = self._get_user_memberships(self.request)
        user_membership = memberships.get(instance.workspace.id)
        
        if not user_membership or user_membership.role not in ['editor', 'admin', 'owner']:
            logger.warning(
                "Workspace editor permission denied for transaction update",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.workspace.id,
                    "transaction_id": instance.id,
                    "user_role": user_membership.role if user_membership else None,
                    "action": "workspace_editor_permission_denied",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
            )
            raise PermissionDenied("You don't have permission to update transactions in this workspace")

        instance = serializer.save()
        
        if instance.date:
            instance.month = instance.date.replace(day=1)
            instance.save(update_fields=['month'])

        draft_type = instance.type
        deleted_count, _ = TransactionDraft.objects.filter(
            user=target_user,
            workspace=instance.workspace,
            draft_type=draft_type
        ).delete()
        
        if deleted_count > 0:
            logger.info(
                "Transaction draft deleted after successful update",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.workspace.id,
                    "transaction_type": draft_type,
                    "drafts_deleted": deleted_count,
                    "action": "draft_cleaned_after_update",
                    "component": "TransactionViewSet",
                },
            )
            
        logger.info(
            "Transaction updated successfully",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "transaction_id": instance.id,
                "action": "transaction_update_success",
                "component": "TransactionViewSet",
            },
        )

    def perform_destroy(self, instance):
        """
        Delete a transaction with permission validation.
        Supports admin impersonation.
        """
        target_user = self.request.target_user
        
        memberships = self._get_user_memberships(self.request)
        user_membership = memberships.get(instance.workspace.id)
        
        if not user_membership or user_membership.role not in ['editor', 'admin', 'owner']:
            logger.warning(
                "Workspace editor permission denied for transaction deletion",
                extra={
                    "request_user_id": self.request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": instance.workspace.id,
                    "transaction_id": instance.id,
                    "user_role": user_membership.role if user_membership else None,
                    "action": "workspace_editor_permission_denied",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
            )
            raise PermissionDenied("You don't have permission to delete transactions in this workspace")
        
        logger.info(
            "Transaction deletion initiated",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": self.request.is_admin_impersonation,
                "transaction_id": instance.id,
                "workspace_id": instance.workspace.id,
                "action": "transaction_deletion_start",
                "component": "TransactionViewSet",
            },
        )
        
        instance.delete()
        
        logger.info(
            "Transaction deleted successfully",
            extra={
                "request_user_id": self.request.user.id,
                "target_user_id": target_user.id,
                "transaction_id": instance.id,
                "action": "transaction_deletion_success",
                "component": "TransactionViewSet",
            },
        )

    @action(detail=False, methods=['post'])
    @transaction.atomic
    def bulk_delete(self, request):
        """
        Atomically delete multiple transactions with permission validation.
        Supports admin impersonation.
        """
        transaction_ids = request.data.get('ids', [])
        target_user = request.target_user
        
        logger.info(
            "Bulk transaction delete initiated",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "transaction_count": len(transaction_ids),
                "transaction_ids": transaction_ids,
                "action": "bulk_delete_start",
                "component": "TransactionViewSet",
            },
        )
        
        try:
            transactions = Transaction.objects.filter(
                id__in=transaction_ids,
                user=target_user
            ).select_related('workspace')
            
            memberships = self._get_user_memberships(request)
            
            for transaction in transactions:
                user_membership = memberships.get(transaction.workspace.id)
                if not user_membership or user_membership.role not in ['editor', 'admin', 'owner']:
                    logger.warning(
                        "Workspace editor permission denied for bulk transaction deletion",
                        extra={
                            "request_user_id": request.user.id,
                            "target_user_id": target_user.id,
                            "workspace_id": transaction.workspace.id,
                            "transaction_id": transaction.id,
                            "user_role": user_membership.role if user_membership else None,
                            "action": "workspace_editor_permission_denied",
                            "component": "TransactionViewSet",
                            "severity": "high",
                        },
                    )
                    raise PermissionDenied(f"You don't have permission to delete transaction {transaction.id}")
            
            deleted_count, deletion_details = transactions.delete()
            
            response_data = {'deleted': deleted_count}
            
            if request.is_admin_impersonation:
                response_data['admin_impersonation'] = {
                    'target_user_id': target_user.id,
                    'target_username': target_user.username,
                    'requested_by_admin_id': request.user.id
                }
            
            logger.info(
                "Bulk transaction delete completed successfully",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "deleted_count": deleted_count,
                    "deletion_details": deletion_details,
                    "action": "bulk_delete_success",
                    "component": "TransactionViewSet",
                },
            )
            
            return Response(response_data)
            
        except PermissionDenied:
            raise
        except Exception as e:
            logger.error(
                "Bulk transaction delete failed",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "transaction_ids": transaction_ids,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "bulk_delete_failure",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
                exc_info=True,
            )
            return Response(
                {'error': 'Bulk delete operation failed'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['post'], url_path='workspaces/(?P<workspace_id>[^/.]+)/bulk-sync')
    def bulk_sync(self, request, workspace_id=None):
        """
        Bulk sync transactions for specific workspace with atomic safety.
        Supports admin impersonation.
        """
        target_user = request.target_user
        
        logger.info(
            "Bulk sync transaction viewset action called",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace_id,
                "action": "bulk_sync_viewset_called",
                "component": "TransactionViewSet",
            },
        )
        
        try:
            workspace = Workspace.objects.select_related('owner').get(id=workspace_id, members=target_user.id)
            
            memberships = self._get_user_memberships(request)
            user_membership = memberships.get(workspace.id)
            
            if not user_membership or user_membership.role not in ['editor', 'admin', 'owner']:
                logger.warning(
                    "Workspace editor permission denied for bulk sync",
                    extra={
                        "request_user_id": request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "user_role": user_membership.role if user_membership else None,
                        "action": "workspace_editor_permission_denied",
                        "component": "TransactionViewSet",
                        "severity": "high",
                    },
                )
                raise PermissionDenied("You don't have permission to sync transactions in this workspace")

            transactions_data = request.data
            
            results = TransactionService.bulk_sync_transactions(
                transactions_data, 
                workspace, 
                target_user
            )

            created_count = results.get('created', 0)
            updated_count = results.get('updated', 0)
            
            if created_count > 0 or updated_count > 0:
                transaction_types = set()
                for transaction in transactions_data:
                    if (isinstance(transaction, dict) and 
                        transaction.get('type') in ['income', 'expense']):
                        transaction_types.add(transaction['type'])
                
                for draft_type in transaction_types:
                    deleted_count, _ = TransactionDraft.objects.filter(
                        user=target_user,
                        workspace=workspace,
                        draft_type=draft_type
                    ).delete()
                    
                    if deleted_count > 0:
                        logger.info(
                            "Transaction draft deleted after bulk sync with creates/updates",
                            extra={
                                "request_user_id": request.user.id,
                                "target_user_id": target_user.id,
                                "workspace_id": workspace_id,
                                "transaction_type": draft_type,
                                "drafts_deleted": deleted_count,
                                "action": "draft_cleaned_after_bulk_sync",
                                "component": "TransactionViewSet",
                            },
                        )
            
            if request.is_admin_impersonation:
                results['admin_impersonation'] = {
                    'target_user_id': target_user.id,
                    'target_username': target_user.username,
                    'requested_by_admin_id': request.user.id
                }
            
            logger.info(
                "Bulk transaction sync completed successfully",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace_id,
                    "results": results,
                    "action": "bulk_sync_success",
                    "component": "TransactionViewSet",
                },
            )
            
            return Response(results)
            
        except PermissionDenied:
            raise
        except Workspace.DoesNotExist:
            logger.warning(
                "Workspace not found for bulk sync",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_not_found",
                    "component": "TransactionViewSet",
                    "severity": "medium",
                },
            )
            return Response(
                {'error': 'Workspace not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(
                "Bulk transaction sync failed",
                extra={
                    "request_user_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_id": workspace_id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "bulk_sync_failure",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
                exc_info=True,
            )
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )

# -------------------------------------------------------------------
# EXCHANGE RATES MANAGEMENT
# -------------------------------------------------------------------
# Currency exchange rate retrieval and filtering


class ExchangeRateViewSet(viewsets.GenericViewSet,
                          mixins.ListModelMixin,
                          mixins.RetrieveModelMixin):
    """
    ViewSet for retrieving exchange rate information.
    
    Provides read-only access to exchange rates with filtering by currencies
    and date ranges.
    """
    
    serializer_class = ExchangeRateSerializer
    permission_classes = [IsAuthenticated]
    queryset = ExchangeRate.objects.all()

    def get_queryset(self):
        """
        Get exchange rates queryset with currency and date filtering.
        
        Returns:
            QuerySet: Filtered exchange rates based on query parameters
        """
        logger.debug(
            "Retrieving exchange rates queryset",
            extra={
                "user_id": self.request.user.id,
                "query_params": dict(self.request.query_params),
                "action": "exchange_rates_queryset_retrieval",
                "component": "ExchangeRateViewSet",
            },
        )
        
        qs = super().get_queryset()
        currencies = self.request.query_params.get('currencies')
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')

        # Filter by specific currencies
        if currencies:
            currency_list = [c.strip().upper() for c in currencies.split(',')]
            qs = qs.filter(currency__in=currency_list)
            logger.debug(
                "Applied currency filter to exchange rates",
                extra={
                    "user_id": self.request.user.id,
                    "currencies": currency_list,
                    "action": "currency_filter_applied",
                    "component": "ExchangeRateViewSet",
                },
            )

        # Date range filtering
        if date_from:
            qs = qs.filter(date__gte=date_from)
            logger.debug(
                "Applied date_from filter to exchange rates",
                extra={
                    "user_id": self.request.user.id,
                    "date_from": date_from,
                    "action": "date_from_filter_applied",
                    "component": "ExchangeRateViewSet",
                },
            )
            
        if date_to:
            qs = qs.filter(date__lte=date_to)
            logger.debug(
                "Applied date_to filter to exchange rates",
                extra={
                    "user_id": self.request.user.id,
                    "date_to": date_to,
                    "action": "date_to_filter_applied",
                    "component": "ExchangeRateViewSet",
                },
            )

        logger.info(
            "Exchange rates queryset prepared with filters",
            extra={
                "user_id": self.request.user.id,
                "final_queryset_count": qs.count(),
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


@api_view(['POST'])
def sync_categories_api(request, workspace_id, category_type):
    """
    API endpoint for synchronizing category hierarchies.
    
    Handles bulk synchronization of expense or income category trees
    within a specific workspace.
    
    Args:
        request: HTTP request with category data
        workspace_id: ID of the workspace
        category_type: Type of categories ('expense' or 'income')
        
    Returns:
        Response: Results of category synchronization
    """
    logger.info(
        "Category synchronization initiated",
        extra={
            "user_id": request.user.id,
            "workspace_id": workspace_id,
            "category_type": category_type,
            "category_count": len(request.data) if isinstance(request.data, list) else 0,
            "action": "category_sync_start",
            "component": "sync_categories_api",
        },
    )
    
    try:
        workspace = get_object_or_404(Workspace.objects.select_related('owner'), id=workspace_id, members=request.user.id)
        
        if category_type == 'expense':
            version = get_object_or_404(
                ExpenseCategoryVersion.objects.select_related('workspace'), 
                workspace=workspace, 
                is_active=True
            )
            category_model = ExpenseCategory
        elif category_type == 'income':
            version = get_object_or_404(
                IncomeCategoryVersion.objects.select_related('workspace'), 
                workspace=workspace, 
                is_active=True
            )
            category_model = IncomeCategory
        else:
            logger.warning(
                "Invalid category type provided",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "category_type": category_type,
                    "action": "invalid_category_type",
                    "component": "sync_categories_api",
                    "severity": "medium",
                },
            )
            return Response(
                {'error': 'Invalid category type'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        results = sync_categories_tree(request.data, version, category_model)
        
        logger.info(
            "Category synchronization completed successfully",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_id,
                "category_type": category_type,
                "results": results,
                "action": "category_sync_success",
                "component": "sync_categories_api",
            },
        )
        
        return Response(results)
        
    except Exception as e:
        logger.error(
            "Category synchronization failed",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_id,
                "category_type": category_type,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "action": "category_sync_failure",
                "component": "sync_categories_api",
                "severity": "high",
            },
            exc_info=True,
        )
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_400_BAD_REQUEST
        )

# -------------------------------------------------------------------
# TRANSACTION DRAFTS MANAGEMENT  
# -------------------------------------------------------------------
# Single draft operations per workspace with atomic replacement


class TransactionDraftViewSet(viewsets.ModelViewSet):
    serializer_class = TransactionDraftSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        target_user = self.request.target_user
        return TransactionDraft.objects.for_user(
            user=target_user
        ).filter(
            workspace__members=target_user.id
        ).select_related('workspace', 'user')

    @action(detail=False, methods=['post'])
    @transaction.atomic
    def save_draft(self, request, workspace_pk=None):
        target_user = request.target_user
        workspace = get_object_or_404(
            Workspace.objects.select_related('owner'), 
            id=workspace_pk, 
            members=target_user.id
        )
        
        draft_type = request.data.get('draft_type')
        transactions_data = request.data.get('transactions_data', [])
        
        with transaction.atomic():
            TransactionDraft.objects.filter(
                user=target_user,
                workspace=workspace,
                draft_type=draft_type
            ).delete()
            
            draft = TransactionDraft.objects.create(
                user=target_user,
                workspace=workspace,
                draft_type=draft_type,
                transactions_data=transactions_data
            )
        
        logger.info(
            "Transaction draft saved atomically",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace.id,
                "draft_type": draft_type,
                "transaction_count": len(transactions_data),
                "action": "draft_saved_atomically",
                "component": "TransactionDraftViewSet",
            },
        )
        
        return Response(TransactionDraftSerializer(draft).data)

    @action(detail=False, methods=['get'])
    def get_workspace_draft(self, request, workspace_pk=None):
        target_user = request.target_user
        draft_type = request.query_params.get('type')
        
        try:
            draft = TransactionDraft.objects.select_related('workspace', 'user').get(
                user=target_user,
                workspace_id=workspace_pk,
                draft_type=draft_type
            )
            return Response(TransactionDraftSerializer(draft).data)
        except TransactionDraft.DoesNotExist:
            return Response({"transactions_data": []})

    @action(detail=True, methods=['delete'])
    def discard(self, request, workspace_pk=None, draft_type=None):
        target_user = request.target_user
        draft = self.get_object()
        draft_id = draft.id
        
        draft.delete()
        
        logger.info(
            "Transaction draft discarded",
            extra={
                "request_user_id": request.user.id,
                "target_user_id": target_user.id,
                "is_admin_impersonation": request.is_admin_impersonation,
                "workspace_id": workspace_pk,
                "draft_type": draft_type,
                "draft_id": draft_id,
                "action": "draft_discarded",
                "component": "TransactionDraftViewSet",
            },
        )
        
        return Response({"message": "Draft discarded successfully"})
