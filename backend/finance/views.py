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
    WorkspaceMembershipSerializer, WorkspaceSerializer, TransactionDraftSerializer 
)
from .services.transaction_service import TransactionService
from .services.currency_service import CurrencyService
from .utils.category_utils import sync_categories_tree

# Get structured logger for this module
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# WORKSPACE MANAGEMENT
# -------------------------------------------------------------------
# Workspace CRUD operations and membership management


class WorkspaceViewSet(viewsets.ModelViewSet):
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
    """
    
    serializer_class = WorkspaceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get workspaces based on user role:
        - Viewers/editors: only active workspaces
        - Admins/owners: all workspaces (active + inactive)
        """
        logger.debug(
            "Retrieving workspaces queryset with role-based filtering",
            extra={
                "user_id": self.request.user.id,
                "action": "role_based_workspaces_retrieval",
                "component": "WorkspaceViewSet",
            },
        )

        if not self.request.user.is_authenticated:
            return Workspace.objects.none()
        
        # Get all memberships for the current user
        user_memberships = WorkspaceMembership.objects.filter(
            user=self.request.user
        ).select_related('workspace')
        
        # Check if user has any admin/owner role in any workspace
        has_admin_owner_role = user_memberships.filter(
            role__in=['admin', 'owner']
        ).exists()
        
        if has_admin_owner_role:
            # Admin/owner can see ALL workspaces (active + inactive)
            workspaces = Workspace.objects.filter(
                members=self.request.user
            ).select_related('owner').prefetch_related('members')
            
            logger.debug(
                "Admin/owner workspace access - all workspaces",
                extra={
                    "user_id": self.request.user.id,
                    "total_workspaces_count": workspaces.count(),
                    "active_workspaces_count": workspaces.filter(is_active=True).count(),
                    "inactive_workspaces_count": workspaces.filter(is_active=False).count(),
                    "action": "admin_owner_workspaces_accessed",
                    "component": "WorkspaceViewSet",
                },
            )
        else:
            # Viewer/editor can only see ACTIVE workspaces
            workspaces = Workspace.objects.filter(
                members=self.request.user,
                is_active=True  # Only active workspaces for viewers/editors
            ).select_related('owner').prefetch_related('members')
            
            logger.debug(
                "Viewer/editor workspace access - active workspaces only",
                extra={
                    "user_id": self.request.user.id,
                    "active_workspaces_count": workspaces.count(),
                    "action": "viewer_editor_workspaces_accessed",
                    "component": "WorkspaceViewSet",
                },
            )
        
        return workspaces

    def get_serializer_context(self):
        """
        Add additional context to serializer for frontend needs.
        """
        context = super().get_serializer_context()
        
        # Add user's membership info for all workspaces
        if self.request.user.is_authenticated:
            user_memberships = WorkspaceMembership.objects.filter(
                user=self.request.user
            ).select_related('workspace')
            
            context['user_memberships'] = {
                membership.workspace_id: membership 
                for membership in user_memberships
            }
        
        return context

    def list(self, request, *args, **kwargs):
        """
        Custom list method to provide additional metadata about workspaces.
        """
        response = super().list(request, *args, **kwargs)
        
        # Add summary information for frontend
        workspaces = self.get_queryset()
        active_count = workspaces.filter(is_active=True).count()
        inactive_count = workspaces.filter(is_active=False).count()
        
        # Get user's roles across all workspaces
        user_memberships = WorkspaceMembership.objects.filter(
            user=request.user
        )
        role_counts = {}
        for membership in user_memberships:
            role_counts[membership.role] = role_counts.get(membership.role, 0) + 1
        
        # Determine user's overall access level
        has_admin_owner_access = user_memberships.filter(
            role__in=['admin', 'owner']
        ).exists()
        
        response.data = {
            'workspaces': response.data,
            'summary': {
                'total_workspaces': workspaces.count(),
                'active_workspaces': active_count,
                'inactive_workspaces': inactive_count if has_admin_owner_access else 0,
                'role_distribution': role_counts,
                'access_level': 'admin_owner' if has_admin_owner_access else 'viewer_editor'
            }
        }
        
        return response

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve single workspace with additional security checks.
        """
        instance = self.get_object()
        
        # Additional security check for viewers/editors - can't access inactive workspaces
        user_membership = WorkspaceMembership.objects.get(
            workspace=instance, 
            user=request.user
        )
        
        if not instance.is_active and user_membership.role in ['viewer', 'editor']:
            logger.warning(
                "Viewer/editor attempted to access inactive workspace",
                extra={
                    "user_id": request.user.id,
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
        return Response(serializer.data)

    def perform_destroy(self, instance):
        """
        SOFT DELETE - set workspace as inactive (admin/owner only).
        """
        logger.info(
            "Workspace soft deletion initiated",
            extra={
                "user_id": self.request.user.id,
                "workspace_id": instance.id,
                "workspace_name": instance.name,
                "current_status": "active" if instance.is_active else "inactive",
                "action": "workspace_soft_deletion_start",
                "component": "WorkspaceViewSet",
            },
        )
        
        # Check if user has permission to soft delete (admin/owner only)
        membership = WorkspaceMembership.objects.get(
            workspace=instance, 
            user=self.request.user
        )
        
        if membership.role not in ['admin', 'owner']:
            logger.warning(
                "Workspace soft deletion permission denied - insufficient role",
                extra={
                    "user_id": self.request.user.id,
                    "workspace_id": instance.id,
                    "user_role": membership.role,
                    "required_roles": ['admin', 'owner'],
                    "action": "workspace_soft_deletion_permission_denied",
                    "component": "WorkspaceViewSet",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError("Only workspace owners and admins can deactivate workspaces.")
        
        # Additional check: workspace must be active to be deactivated
        if not instance.is_active:
            logger.warning(
                "Attempt to deactivate already inactive workspace",
                extra={
                    "user_id": self.request.user.id,
                    "workspace_id": instance.id,
                    "action": "workspace_already_inactive",
                    "component": "WorkspaceViewSet",
                    "severity": "low",
                },
            )
            raise serializers.ValidationError("Workspace is already inactive.")
        
        # Soft delete - set to inactive
        instance.is_active = False
        instance.save()
        
        logger.info(
            "Workspace soft deleted successfully",
            extra={
                "user_id": self.request.user.id,
                "workspace_id": instance.id,
                "previous_status": "active",
                "new_status": "inactive",
                "action": "workspace_soft_deletion_success",
                "component": "WorkspaceViewSet",
            },
        )

    @action(detail=True, methods=['delete'])
    def hard_delete(self, request, pk=None):
        """
        HARD DELETE - permanently remove workspace and all related data.
        Only workspace owner can perform hard delete.
        """
        workspace = self.get_object()
        
        logger.warning(
            "Workspace hard deletion initiated",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "workspace_owner_id": workspace.owner.id,
                "action": "workspace_hard_deletion_start",
                "component": "WorkspaceViewSet",
                "severity": "high",
            },
        )
        
        # Check if user is the owner
        if workspace.owner != request.user:
            logger.error(
                "Workspace hard deletion permission denied - not owner",
                extra={
                    "user_id": request.user.id,
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
        
        # Confirm hard deletion with additional check
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
        
        # Store workspace info for logging before deletion
        workspace_id = workspace.id
        workspace_name = workspace.name
        member_count = workspace.members.count()
        
        # Perform hard delete
        workspace.delete()
        
        logger.critical(
            "Workspace hard deleted permanently",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_id,
                "workspace_name": workspace_name,
                "member_count": member_count,
                "action": "workspace_hard_deletion_success",
                "component": "WorkspaceViewSet",
                "severity": "critical",
            },
        )
        
        return Response(
            {"message": "Workspace permanently deleted."},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """
        Activate an inactive workspace (admin/owner only).
        """
        workspace = self.get_object()
        
        logger.info(
            "Workspace activation initiated",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "workspace_name": workspace.name,
                "current_status": "active" if workspace.is_active else "inactive",
                "action": "workspace_activation_start",
                "component": "WorkspaceViewSet",
            },
        )
        
        # Check if user has permission to activate (owner or admin only)
        membership = WorkspaceMembership.objects.get(
            workspace=workspace, 
            user=request.user
        )
        
        if membership.role not in ['admin', 'owner']:
            logger.warning(
                "Workspace activation permission denied",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace.id,
                    "user_role": membership.role,
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
        
        # Additional check: workspace must be inactive to be activated
        if workspace.is_active:
            logger.warning(
                "Attempt to activate already active workspace",
                extra={
                    "user_id": request.user.id,
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
        
        # Activate workspace
        workspace.is_active = True
        workspace.save()
        
        logger.info(
            "Workspace activated successfully",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "previous_status": "inactive",
                "new_status": "active",
                "action": "workspace_activation_success",
                "component": "WorkspaceViewSet",
            },
        )
        
        return Response(
            {"message": "Workspace activated successfully.", "is_active": True},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['get'])
    def membership_info(self, request, pk=None):
        """
        Get detailed membership information for current user in this workspace.
        """
        workspace = self.get_object()
        
        logger.debug(
            "Retrieving detailed membership info",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "action": "membership_info_retrieval",
                "component": "WorkspaceViewSet",
            },
        )
        
        try:
            membership = WorkspaceMembership.objects.get(
                workspace=workspace,
                user=request.user
            )
            
            # Security check: viewers/editors can't access membership info for inactive workspaces
            if not workspace.is_active and membership.role in ['viewer', 'editor']:
                logger.warning(
                    "Viewer/editor attempted to access membership info for inactive workspace",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace.id,
                        "user_role": membership.role,
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
                membership, 
                context={'request': request}
            )
            
            response_data = {
                **serializer.data,
                'permissions': {
                    'can_activate': membership.role in ['admin', 'owner'] and not workspace.is_active,
                    'can_deactivate': membership.role in ['admin', 'owner'] and workspace.is_active,
                    'can_hard_delete': workspace.owner == request.user,
                    'can_invite': membership.role in ['admin', 'owner'] and workspace.is_active,
                    'can_manage_members': membership.role in ['admin', 'owner'] and workspace.is_active,
                    'can_view': workspace.is_active or membership.role in ['admin', 'owner'],
                    'can_edit': membership.role in ['admin', 'owner'] and workspace.is_active,
                    'can_see_inactive': membership.role in ['admin', 'owner'],
                }
            }
            
            logger.debug(
                "Membership info retrieved successfully",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace.id,
                    "user_role": membership.role,
                    "is_owner": workspace.owner == request.user,
                    "workspace_active": workspace.is_active,
                    "action": "membership_info_retrieved",
                    "component": "WorkspaceViewSet",
                },
            )
            
            return Response(response_data)
            
        except WorkspaceMembership.DoesNotExist:
            logger.warning(
                "Membership not found for user in workspace",
                extra={
                    "user_id": request.user.id,
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

    @action(detail=True, methods=['get'])
    def members(self, request, pk=None):
        """
        Get all members of this workspace with their roles.
        
        Returns serialized list of workspace members with membership details.
        """
        workspace = self.get_object()
        
        logger.debug(
            "Retrieving workspace members",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "action": "workspace_members_retrieval",
                "component": "WorkspaceViewSet",
            },
        )
        
        # Check if user has permission to view members
        try:
            user_membership = WorkspaceMembership.objects.get(
                workspace=workspace,
                user=request.user
            )
            
            # Security check: viewers/editors can't access members for inactive workspaces
            if not workspace.is_active and user_membership.role in ['viewer', 'editor']:
                logger.warning(
                    "Viewer/editor attempted to access members of inactive workspace",
                    extra={
                        "user_id": request.user.id,
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
            
        except WorkspaceMembership.DoesNotExist:
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get all memberships for this workspace
        memberships = WorkspaceMembership.objects.filter(
            workspace=workspace
        ).select_related('user')
        
        # Serialize the data
        members_data = []
        for membership in memberships:
            members_data.append({
                'user_id': membership.user.id,
                'username': membership.user.username,
                'email': membership.user.email,
                'role': membership.role,
                'joined_at': membership.joined_at,
                'is_owner': workspace.owner == membership.user
            })
        
        logger.debug(
            "Workspace members retrieved successfully",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "member_count": len(members_data),
                "action": "workspace_members_retrieved",
                "component": "WorkspaceViewSet",
            },
        )
        
        return Response({
            'workspace_id': workspace.id,
            'workspace_name': workspace.name,
            'members': members_data,
            'total_members': len(members_data)
        })
    
    @action(detail=True, methods=['get'])
    def settings(self, request, pk=None):
        """
        Get workspace settings.
        
        Returns workspace settings with additional context.
        """
        workspace = self.get_object()
        
        logger.debug(
            "Retrieving workspace settings",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "action": "workspace_settings_retrieval",
                "component": "WorkspaceViewSet",
            },
        )
        
        # Check if user is member of this workspace
        try:
            user_membership = WorkspaceMembership.objects.get(
                workspace=workspace,
                user=request.user
            )
            
            # Security check: viewers/editors can't access settings for inactive workspaces
            if not workspace.is_active and user_membership.role in ['viewer', 'editor']:
                logger.warning(
                    "Viewer/editor attempted to access settings of inactive workspace",
                    extra={
                        "user_id": request.user.id,
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
            
        except WorkspaceMembership.DoesNotExist:
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get or create workspace settings
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
        
        # Serialize settings data
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
                # ... ostatné mesiace
            ],
            'display_mode_options': [
                {'value': 'month', 'label': 'Month only'},
                {'value': 'day', 'label': 'Full date'}
            ]
        }
        
        logger.debug(
            "Workspace settings retrieved successfully",
            extra={
                "user_id": request.user.id,
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


class WorkspaceSettingsViewSet(mixins.RetrieveModelMixin,
                              mixins.UpdateModelMixin,
                              viewsets.GenericViewSet):
    """
    ViewSet for managing workspace-specific settings with atomic currency changes.
    """
    
    serializer_class = WorkspaceSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get workspace settings queryset filtered by user membership.
        """
        logger.debug(
            "Retrieving workspace settings queryset",
            extra={
                "user_id": self.request.user.id,
                "action": "workspace_queryset_retrieval", 
                "component": "WorkspaceSettingsViewSet",
            },
        )
        return WorkspaceSettings.objects.filter(workspace__members=self.request.user)

    def update(self, request, *args, **kwargs):
        """
        Update workspace settings with atomic currency change handling.
        """
        instance = self.get_object()
        
        # Check if this is a currency change request
        if 'domestic_currency' in request.data:
            return self._handle_currency_change(request, instance)
        
        # For non-currency updates, use normal flow
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        """
        Partial update with atomic currency change handling.
        """
        instance = self.get_object()
        
        # Check if this is a currency change request
        if 'domestic_currency' in request.data:
            return self._handle_currency_change(request, instance)
        
        # For non-currency updates, use normal flow
        return super().partial_update(request, *args, **kwargs)
    
    def _handle_currency_change(self, request, instance):
        """
        Handle currency change with atomic transaction recalculation.
        
        Args:
            request: HTTP request object
            instance: WorkspaceSettings instance to update
            
        Returns:
            Response: DRF Response with operation result
        """
        new_currency = request.data['domestic_currency']
        
        logger.info(
            "Currency change request received",
            extra={
                "user_id": request.user.id,
                "workspace_settings_id": instance.id,
                "workspace_id": instance.workspace.id,
                "new_currency": new_currency,
                "current_currency": instance.domestic_currency,
                "action": "currency_change_request",
                "component": "WorkspaceSettingsViewSet",
            },
        )
        
        try:
            # Use atomic currency change service
            result = CurrencyService.change_workspace_currency(instance, new_currency)
            
            if result['changed']:
                logger.info(
                    "Currency change completed successfully via API",
                    extra={
                        "user_id": request.user.id,
                        "workspace_settings_id": instance.id,
                        "transactions_updated": result['transactions_updated'],
                        "action": "currency_change_api_success",
                        "component": "WorkspaceSettingsViewSet",
                    },
                )
                
                # Return updated settings
                serializer = self.get_serializer(instance)
                return Response({
                    **serializer.data,
                    "recalculation_details": {
                        "transactions_updated": result['transactions_updated'],
                        "currency_changed": True
                    }
                })
                
            else:
                # Currency didn't change, return current settings
                serializer = self.get_serializer(instance)
                return Response(serializer.data)
                
        except Exception as e:
            logger.error(
                "Currency change API request failed",
                extra={
                    "user_id": request.user.id,
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
            
            return Response(
                {
                    "error": "Currency update failed",
                    "code": "currency_change_failed",
                    "detail": str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )

# -------------------------------------------------------------------
# USER SETTINGS MANAGEMENT
# -------------------------------------------------------------------
# User preferences and personalization


class UserSettingsViewSet(mixins.RetrieveModelMixin,
                         mixins.UpdateModelMixin,
                         viewsets.GenericViewSet):
    """
    ViewSet for managing user-specific settings.
    
    Provides retrieve and update operations for user settings with field-level
    validation and security controls.
    """
    
    serializer_class = UserSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get user settings queryset filtered by current authenticated user.
        """
        logger.debug(
            "Retrieving user settings queryset",
            extra={
                "user_id": self.request.user.id,
                "action": "queryset_retrieval",
                "component": "UserSettingsViewSet",
            },
        )
        return UserSettings.objects.filter(user=self.request.user)

    def partial_update(self, request, *args, **kwargs):
        """
        Partially update user settings with field-level validation.
        
        Args:
            request: HTTP request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
            
        Returns:
            Response: DRF Response object with update result
            
        Raises:
            ValidationError: If unauthorized fields are attempted to be updated
        """
        allowed_fields = {'language'}
        invalid_fields = [key for key in request.data.keys() if key not in allowed_fields]
        
        if invalid_fields:
            logger.warning(
                "User settings update attempted with invalid fields",
                extra={
                    "user_id": request.user.id,
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
                "user_id": request.user.id,
                "updated_fields": list(request.data.keys()),
                "action": "settings_update_start",
                "component": "UserSettingsViewSet",
            },
        )
        
        return super().partial_update(request, *args, **kwargs)

# -------------------------------------------------------------------
# EXPENSE CATEGORIES MANAGEMENT
# -------------------------------------------------------------------
# Read-only access to expense category hierarchies


class ExpenseCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving expense categories.
    
    Provides read-only access to expense categories from active workspace versions
    where the current user is a member.
    """
    
    serializer_class = ExpenseCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get expense categories from active workspace versions.
        
        Returns:
            QuerySet: Filtered expense categories with prefetched properties
        """
        logger.debug(
            "Retrieving expense categories queryset",
            extra={
                "user_id": self.request.user.id,
                "action": "expense_categories_retrieval",
                "component": "ExpenseCategoryViewSet",
            },
        )
        
        # Get active versions for workspaces where user is a member
        active_versions = ExpenseCategoryVersion.objects.filter(
            workspace__members=self.request.user,
            is_active=True
        )
        
        categories = ExpenseCategory.objects.filter(version__in=active_versions)\
            .prefetch_related('property')  # Prefetch related properties for optimization
            
        logger.debug(
            "Expense categories queryset prepared",
            extra={
                "user_id": self.request.user.id,
                "active_versions_count": active_versions.count(),
                "categories_count": categories.count(),
                "action": "expense_categories_queryset_prepared",
                "component": "ExpenseCategoryViewSet",
            },
        )
        
        return categories

# -------------------------------------------------------------------
# INCOME CATEGORIES MANAGEMENT  
# -------------------------------------------------------------------
# Read-only access to income category hierarchies


class IncomeCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving income categories.
    
    Provides read-only access to income categories from active workspace versions
    where the current user is a member.
    """
    
    serializer_class = IncomeCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get income categories from active workspace versions.
        
        Returns:
            QuerySet: Filtered income categories with prefetched properties
        """
        logger.debug(
            "Retrieving income categories queryset",
            extra={
                "user_id": self.request.user.id,
                "action": "income_categories_retrieval",
                "component": "IncomeCategoryViewSet",
            },
        )
        
        # Get active versions for workspaces where user is a member
        active_versions = IncomeCategoryVersion.objects.filter(
            workspace__members=self.request.user,
            is_active=True
        )
        
        categories = IncomeCategory.objects.filter(version__in=active_versions)\
            .prefetch_related('property')  # Prefetch related properties for optimization
            
        logger.debug(
            "Income categories queryset prepared",
            extra={
                "user_id": self.request.user.id,
                "active_versions_count": active_versions.count(),
                "categories_count": categories.count(),
                "action": "income_categories_queryset_prepared",
                "component": "IncomeCategoryViewSet",
            },
        )
        
        return categories

# -------------------------------------------------------------------
# TRANSACTION MANAGEMENT
# -------------------------------------------------------------------
# Financial transaction CRUD with filtering and bulk operations


class TransactionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing financial transactions.
    
    Provides full CRUD operations for transactions with advanced filtering,
    workspace validation, and bulk operations.
    """
    
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Get transactions queryset with advanced filtering.
        
        Supports filtering by type, fiscal year, month, and workspace.
        
        Returns:
            QuerySet: Filtered transactions based on request parameters
        """
        logger.debug(
            "Retrieving transactions queryset",
            extra={
                "user_id": self.request.user.id,
                "query_params": dict(self.request.query_params),
                "action": "transactions_queryset_retrieval",
                "component": "TransactionViewSet",
            },
        )
        
        # Base queryset with user and workspace authorization
        qs = Transaction.objects.filter(
            user=self.request.user,
            workspace__members=self.request.user
        )
        
        tx_type = self.request.query_params.get('type')
        fiscal_year = self.request.query_params.get('fiscal_year')
        month = self.request.query_params.get('month')

        # Filter by transaction type
        if tx_type in ['income', 'expense']:
            qs = qs.filter(type=tx_type)
            logger.debug(
                "Applied transaction type filter",
                extra={
                    "user_id": self.request.user.id,
                    "transaction_type": tx_type,
                    "action": "transaction_type_filter_applied",
                    "component": "TransactionViewSet",
                },
            )

        # Fiscal year filtering based on workspace settings
        workspace_id = self.request.query_params.get('workspace')
        if workspace_id:
            try:
                workspace_settings = WorkspaceSettings.objects.get(
                    workspace_id=workspace_id,
                    workspace__members=self.request.user
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
                            "user_id": self.request.user.id,
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
                        "user_id": self.request.user.id,
                        "workspace_id": workspace_id,
                        "action": "workspace_settings_not_found",
                        "component": "TransactionViewSet",
                        "severity": "low",
                    },
                )

        # Month filtering
        if month:
            month = int(month)
            qs = qs.filter(date__month=month)
            logger.debug(
                "Applied month filter",
                extra={
                    "user_id": self.request.user.id,
                    "month": month,
                    "action": "month_filter_applied",
                    "component": "TransactionViewSet",
                },
            )

        logger.info(
            "Transactions queryset prepared with filters",
            extra={
                "user_id": self.request.user.id,
                "final_queryset_count": qs.count(),
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
        Create a new transaction with validation and workspace checks.
        
        Args:
            serializer: TransactionSerializer instance
            
        Raises:
            ValidationError: If workspace or category validation fails
        """
        workspace = serializer.validated_data.get('workspace')
        
        logger.info(
            "Transaction creation initiated",
            extra={
                "user_id": self.request.user.id,
                "workspace_id": workspace.id if workspace else None,
                "action": "transaction_creation_start",
                "component": "TransactionViewSet",
            },
        )
        
        if workspace and workspace.members.filter(id=self.request.user.id).exists():
            # Validate category workspace membership
            expense_category = serializer.validated_data.get('expense_category')
            income_category = serializer.validated_data.get('income_category')
            
            if expense_category and expense_category.version.workspace != workspace:
                logger.warning(
                    "Expense category workspace validation failed",
                    extra={
                        "user_id": self.request.user.id,
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
                        "user_id": self.request.user.id,
                        "workspace_id": workspace.id,
                        "income_category_id": income_category.id,
                        "category_workspace_id": income_category.version.workspace.id,
                        "action": "category_workspace_validation_failed",
                        "component": "TransactionViewSet",
                        "severity": "medium",
                    },
                )
                raise serializers.ValidationError("Income category does not belong to this workspace")
            
            # Save transaction instance
            instance = serializer.save(user=self.request.user)
            
            # Update month field based on transaction date
            if instance.date:
                instance.month = instance.date.replace(day=1)
                instance.save(update_fields=['month'])

             # DELETE DRAFT: Remove draft for this transaction type after successful save
            draft_type = instance.type  # 'income' or 'expense'
            deleted_count, _ = TransactionDraft.objects.filter(
                user=self.request.user,
                workspace=workspace,
                draft_type=draft_type
            ).delete()
            
            if deleted_count > 0:
                logger.info(
                    "Transaction draft deleted after successful save",
                    extra={
                        "user_id": self.request.user.id,
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
                    "user_id": self.request.user.id,
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
                    "user_id": self.request.user.id,
                    "workspace_id": workspace.id if workspace else None,
                    "action": "workspace_access_denied",
                    "component": "TransactionViewSet",
                    "severity": "high",
                },
            )
            raise serializers.ValidationError("You don't have access to this workspace")

    def perform_update(self, serializer):
        """
        Update an existing transaction and recalculate month field.
        
        Args:
            serializer: TransactionSerializer instance
        """
        instance = serializer.instance
        
        logger.info(
            "Transaction update initiated",
            extra={
                "user_id": self.request.user.id,
                "transaction_id": instance.id,
                "action": "transaction_update_start",
                "component": "TransactionViewSet",
            },
        )
        
        instance = serializer.save()
        
        # Update month field if date changed
        if instance.date:
            instance.month = instance.date.replace(day=1)
            instance.save(update_fields=['month'])

        # DELETE DRAFT: Remove draft for this transaction type after successful update
        draft_type = instance.type  # 'income' or 'expense'
        deleted_count, _ = TransactionDraft.objects.filter(
            user=self.request.user,
            workspace=instance.workspace,
            draft_type=draft_type
        ).delete()
        
        if deleted_count > 0:
            logger.info(
                "Transaction draft deleted after successful update",
                extra={
                    "user_id": self.request.user.id,
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
                "user_id": self.request.user.id,
                "transaction_id": instance.id,
                "action": "transaction_update_success",
                "component": "TransactionViewSet",
            },
        )

    @action(detail=False, methods=['post'])
    @transaction.atomic
    def bulk_delete(self, request):
        """
        Atomically delete multiple transactions in bulk.
        
        Args:
            request: HTTP request with transaction IDs in body
            
        Returns:
            Response: Result of bulk delete operation
        """
        transaction_ids = request.data.get('ids', [])
        
        logger.info(
            "Bulk transaction delete initiated",
            extra={
                "user_id": request.user.id,
                "transaction_count": len(transaction_ids),
                "transaction_ids": transaction_ids,
                "action": "bulk_delete_start",
                "component": "TransactionViewSet",
            },
        )
        
        try:
            transactions = Transaction.objects.filter(
                id__in=transaction_ids,
                user=request.user
            )
            
            deleted_count, deletion_details = transactions.delete()
            
            logger.info(
                "Bulk transaction delete completed successfully",
                extra={
                    "user_id": request.user.id,
                    "deleted_count": deleted_count,
                    "deletion_details": deletion_details,
                    "action": "bulk_delete_success",
                    "component": "TransactionViewSet",
                },
            )
            
            return Response({'deleted': deleted_count})
            
        except Exception as e:
            logger.error(
                "Bulk transaction delete failed",
                extra={
                    "user_id": request.user.id,
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
        Bulk sync transactions for specific workspace.
        """
        logger.info(
            "Bulk sync transaction viewset action called",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_id,
                "action": "bulk_sync_viewset_called",
                "component": "TransactionViewSet",
            },
        )
        
        try:
            workspace = Workspace.objects.get(id=workspace_id, members=request.user)
            transactions_data = request.data
            
            results = TransactionService.bulk_sync_transactions(
                transactions_data, 
                workspace, 
                request.user
            )

            # DELETE DRAFT: Remove draft if there were CREATE or UPDATE operations
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
                        user=request.user,
                        workspace=workspace,
                        draft_type=draft_type
                    ).delete()
                    
                    if deleted_count > 0:
                        logger.info(
                            "Transaction draft deleted after bulk sync with creates/updates",
                            extra={
                                "user_id": request.user.id,
                                "workspace_id": workspace_id,
                                "transaction_type": draft_type,
                                "drafts_deleted": deleted_count,
                                "action": "draft_cleaned_after_bulk_sync",
                                "component": "TransactionViewSet",
                            },
                        )
            
            logger.info(
                "Bulk transaction sync completed successfully",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "results": results,
                    "action": "bulk_sync_success",
                    "component": "TransactionViewSet",
                },
            )
            
            return Response(results)
            
        except Workspace.DoesNotExist:
            logger.warning(
                "Workspace not found for bulk sync",
                extra={
                    "user_id": request.user.id,
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
                    "user_id": request.user.id,
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
        workspace = get_object_or_404(Workspace, id=workspace_id, members=request.user)
        
        if category_type == 'expense':
            version = get_object_or_404(ExpenseCategoryVersion, workspace=workspace, is_active=True)
            category_model = ExpenseCategory
        elif category_type == 'income':
            version = get_object_or_404(IncomeCategoryVersion, workspace=workspace, is_active=True)
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
    """
    ViewSet for managing single transaction draft per workspace.
    """
    serializer_class = TransactionDraftSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Get drafts for current user's workspaces."""
        return TransactionDraft.objects.filter(
            user=self.request.user,
            workspace__members=self.request.user
        )

    def get_object(self):
        """Get specific draft or 404."""
        workspace_id = self.kwargs.get('workspace_pk')
        draft_type = self.kwargs.get('draft_type')  # 'income' or 'expense'
        
        return get_object_or_404(
            TransactionDraft,
            user=self.request.user,
            workspace_id=workspace_id,
            workspace__members=self.request.user,
            draft_type=draft_type
        )

    @action(detail=False, methods=['post'])
    def save_draft(self, request, workspace_pk=None):
        """
        Save or replace draft for workspace.
        
        Expected payload:
        {
            "draft_type": "income|expense",
            "transactions_data": [{...}, {...}]  # transaction objects
        }
        """
        workspace = get_object_or_404(Workspace, id=workspace_pk, members=request.user)
        
        draft_type = request.data.get('draft_type')
        transactions_data = request.data.get('transactions_data', [])
        
        # Create or replace draft
        draft, created = TransactionDraft.objects.update_or_create(
            user=request.user,
            workspace=workspace,
            draft_type=draft_type,
            defaults={'transactions_data': transactions_data}
        )
        
        action_type = "created" if created else "updated"
        logger.info(
            f"Transaction draft {action_type}",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace.id,
                "draft_type": draft_type,
                "transaction_count": len(transactions_data),
                "action": f"draft_{action_type}",
                "component": "TransactionDraftViewSet",
            },
        )
        
        return Response(TransactionDraftSerializer(draft).data)

    @action(detail=True, methods=['delete'])
    def discard(self, request, workspace_pk=None, draft_type=None):
        """
        Permanently delete draft.
        """
        draft = self.get_object()
        draft_id = draft.id
        
        draft.delete()
        
        logger.info(
            "Transaction draft discarded",
            extra={
                "user_id": request.user.id,
                "workspace_id": workspace_pk,
                "draft_type": draft_type,
                "draft_id": draft_id,
                "action": "draft_discarded",
                "component": "TransactionDraftViewSet",
            },
        )
        
        return Response({"message": "Draft discarded successfully"})

    @action(detail=False, methods=['get'])
    def get_workspace_draft(self, request, workspace_pk=None):
        """
        Get draft for specific workspace and type.
        """
        draft_type = request.query_params.get('type')  # 'income' or 'expense'
        
        try:
            draft = TransactionDraft.objects.get(
                user=request.user,
                workspace_id=workspace_pk,
                draft_type=draft_type
            )
            return Response(TransactionDraftSerializer(draft).data)
        except TransactionDraft.DoesNotExist:
            return Response({"transactions_data": []})  # Return empty draft