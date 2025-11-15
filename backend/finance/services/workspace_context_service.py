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

    def build_request_context(self, request):
        """
        Build complete request context with optimized queries and proper error propagation.
        
        Args:
            request: HTTP request object
            
        Raises:
            DatabaseError: On database connectivity issues
            Exception: On unexpected critical errors
        """
        try:
            self._initialize_request_defaults(request)
            
            if not request.user.is_authenticated:
                return

            user_id_param = self._get_user_id_param(request)
            workspace_id = self._get_validated_workspace_id(request)
            
            self._set_basic_permissions(request)
            
            if user_id_param:
                self._process_impersonation_context(request, user_id_param, workspace_id)
            elif workspace_id:
                self._process_workspace_context(request, workspace_id)
                
        except DatabaseError as e:
            logger.error(
                "Database error during context resolution",
                extra={
                    "user_id": getattr(request.user, 'id', 'anonymous'),
                    "error": str(e),
                    "action": "database_error",
                    "component": "WorkspaceContextService",
                    "severity": "high"
                }
            )
            self._reset_impersonation(request)
            raise
        except Exception as e:
            logger.error(
                "Unexpected error in context service",
                extra={
                    "user_id": getattr(request.user, 'id', 'anonymous'),
                    "error": str(e),
                    "action": "unexpected_service_error",
                    "component": "WorkspaceContextService", 
                    "severity": "critical"
                }
            )
            self._reset_impersonation(request)
            raise

    def _initialize_request_defaults(self, request):
        """Initialize secure request defaults."""
        request.target_user = getattr(request, 'user', None)
        request.is_admin_impersonation = False
        request.impersonation_type = None
        request.impersonation_workspace_ids = []
        request.workspace = None
        
        request.user_permissions = {
            'is_superuser': False,
            'is_workspace_admin': None,
            'workspace_role': None,
            'current_workspace_id': None,
            'workspace_exists': False,
        }

    def _get_user_id_param(self, request):
        """Extract and validate user_id parameter from request."""
        user_id = (request.GET.get('user_id') or 
                  getattr(request, 'data', {}).get('user_id'))
        
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
                        "component": "WorkspaceContextService"
                    }
                )
        return None

    def _get_validated_workspace_id(self, request):
        """Extract and validate workspace ID with existence check."""
        workspace_id = (getattr(request, 'kwargs', {}).get('workspace_pk') or
                       getattr(request, 'kwargs', {}).get('workspace_id') or
                       getattr(request, 'kwargs', {}).get('pk') or
                       request.GET.get('workspace_id') or
                       getattr(request, 'data', {}).get('workspace_id'))
        
        request.user_permissions['workspace_exists'] = False
        request.user_permissions['current_workspace_id'] = None
        request.workspace = None
        
        if not workspace_id:
            logger.debug(
                "No workspace ID provided in request",
                extra={
                    "user_id": request.user.id,
                    "action": "workspace_id_not_provided",
                    "component": "WorkspaceContextService"
                }
            )
            return None
            
        try:
            workspace_id = int(workspace_id)
            workspace_exists = Workspace.objects.filter(id=workspace_id).exists()
            request.user_permissions['workspace_exists'] = workspace_exists
            request.user_permissions['current_workspace_id'] = workspace_id
            
            if workspace_exists:
                request.workspace = Workspace.objects.get(id=workspace_id)
                logger.debug(
                    "Workspace validated successfully",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace_id,
                        "action": "workspace_validation_success",
                        "component": "WorkspaceContextService"
                    }
                )
            else:
                logger.warning(
                    "Access attempt to non-existent workspace",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace_id,
                        "action": "workspace_not_found",
                        "component": "WorkspaceContextService",
                        "severity": "medium"
                    }
                )
            
            return workspace_id if workspace_exists else None
                
        except (ValueError, TypeError):
            logger.warning(
                "Invalid workspace ID format",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "invalid_workspace_id",
                    "component": "WorkspaceContextService"
                }
            )
            request.user_permissions['workspace_exists'] = False
            return None

    def _set_basic_permissions(self, request):
        """Set basic user permissions without database queries."""
        request.user_permissions['is_superuser'] = request.user.is_superuser

    def _process_impersonation_context(self, request, user_id_param, workspace_id):
        """Process impersonation context with optimized service."""
        if not self.impersonation_service.check_rate_limit(request.user.id):
            logger.warning(
                "Impersonation rate limit exceeded",
                extra={
                    "admin_id": request.user.id,
                    "action": "impersonation_rate_limit_exceeded",
                    "component": "WorkspaceContextService",
                    "severity": "high"
                }
            )
            self._reset_impersonation(request)
            return

        target_user, granted, imp_type, workspace_ids = self.impersonation_service.process_impersonation(
            request.user, user_id_param, workspace_id
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
                    "component": "WorkspaceContextService"
                }
            )
        else:
            self._reset_impersonation(request)

    def _process_workspace_context(self, request, workspace_id):
        """Process workspace context with optimized data access."""
        if not request.user_permissions.get('workspace_exists'):
            logger.warning(
                "Workspace access attempt to non-existent workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_access_invalid",
                    "component": "WorkspaceContextService",
                    "severity": "medium"
                }
            )
            return

        role = self.membership_service.get_user_workspace_role(request.user.id, workspace_id)
        if role:
            request.user_permissions['workspace_role'] = role
            request.user_permissions['is_workspace_admin'] = self.membership_service.is_workspace_admin(
                request.user.id, workspace_id
            )
            
            logger.debug(
                "Workspace access permissions validated and set",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "role": role,
                    "is_workspace_admin": request.user_permissions['is_workspace_admin'],
                    "action": "workspace_permissions_set",
                    "component": "WorkspaceContextService"
                }
            )
        else:
            logger.warning(
                "User is not a member of the requested workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_access_denied",
                    "component": "WorkspaceContextService",
                    "severity": "medium"
                }
            )

    def _reset_impersonation(self, request):
        """Reset impersonation settings to secure defaults."""
        request.target_user = request.user
        request.is_admin_impersonation = False
        request.impersonation_type = None
        request.impersonation_workspace_ids = []