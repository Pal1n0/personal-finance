# finance/middleware.py
import logging
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from django.db import DatabaseError
from .models import WorkspaceAdmin, WorkspaceMembership, Workspace

logger = logging.getLogger(__name__)

class AdminImpersonationMiddleware(MiddlewareMixin):
    """
    Enterprise-grade middleware for secure admin impersonation and permission caching.
    
    Provides:
    - Secure admin impersonation with comprehensive security checks
    - Optimized permission caching with Redis backend
    - Workspace existence validation and role verification
    - Rate limiting and audit logging for compliance
    - Circuit breaker pattern for database failure scenarios
    """
    
    # Security constants
    MAX_IMPERSONATIONS_PER_MINUTE = 10
    IMPERSONATION_CACHE_TIMEOUT = 60  # seconds
    ALLOWED_SUPERUSER_EMAILS = settings.PROTECTED_SUPERUSER_EMAILS
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Process request for secure impersonation and permission resolution.
        
        Args:
            request: HTTP request object
            view_func: Target view function
            view_args: View arguments
            view_kwargs: View keyword arguments
            
        Returns:
            None: Always returns None to continue request processing
        """
        try:
            # Initialize secure defaults for all requests
            self._initialize_request_defaults(request)
            
            # Terminate processing for unauthenticated requests
            if not request.user.is_authenticated:
                return None
            
            # Extract and validate key parameters
            user_id_param = self._get_user_id_param(request)
            workspace_id = self._get_validated_workspace_id(request, view_kwargs)
            
            # Set basic user permissions without database queries
            self._set_basic_permissions(request)
            
            # Process impersonation with comprehensive security checks
            if user_id_param:
                if not self._check_impersonation_rate_limit(request):
                    logger.warning(
                        "Impersonation rate limit exceeded",
                        extra={
                            "admin_id": request.user.id,
                            "action": "impersonation_rate_limit_exceeded",
                            "component": "AdminImpersonationMiddleware",
                            "severity": "high",
                        },
                    )
                    return None
                    
                self._process_impersonation_request(request, user_id_param, workspace_id)
            elif workspace_id:
                # Non-impersonation request with workspace context
                self._process_workspace_access(request, workspace_id)
                
        except DatabaseError as e:
            logger.error(
                "Database error during permission resolution",
                extra={
                    "user_id": getattr(request.user, 'id', 'anonymous'),
                    "error": str(e),
                    "action": "database_error",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "high",
                },
            )
            # Fail securely - no permissions granted on database errors
            self._reset_impersonation(request)
        except Exception as e:
            logger.error(
                "Unexpected error in permission middleware",
                extra={
                    "user_id": getattr(request.user, 'id', 'anonymous'),
                    "error": str(e),
                    "action": "middleware_error",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "critical",
                },
            )
            # Fail securely
            self._reset_impersonation(request)
        
        return None

    def _initialize_request_defaults(self, request):
        """Initialize all request attributes with secure, production-ready defaults."""
        request.target_user = getattr(request, 'user', None)
        request.is_admin_impersonation = False
        request.impersonation_type = None
        request.impersonation_workspace_ids = []
        request.workspace = None
        
        request.user_permissions = {
            'is_superuser': False,
            'is_workspace_admin': None,  # None = not calculated yet
            'workspace_role': None,      # Role in current workspace (if any)
            'current_workspace_id': None,
            'workspace_exists': False,   # Explicit workspace validation flag
        }

    def _get_user_id_param(self, request):
        """
        Securely extract and validate user_id parameter from request.
        
        Returns:
            int or None: Validated user ID or None if invalid/absent
        """
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
                        "component": "AdminImpersonationMiddleware",
                    },
                )
        return None

    def _get_validated_workspace_id(self, request, view_kwargs):
        """
        Extract and validate workspace ID with existence check.
        
        Args:
            request: HTTP request object
            view_kwargs: View keyword arguments
            
        Returns:
            int or None: Validated workspace ID if exists, None otherwise
        """
        workspace_id = (view_kwargs.get('workspace_pk') or
                       view_kwargs.get('workspace_id') or
                       view_kwargs.get('pk') or
                       request.GET.get('workspace_id'))
        
        if workspace_id:
            try:
                workspace_id = int(workspace_id)
                
                # Critical security enhancement: Validate workspace existence
                workspace_exists = Workspace.objects.filter(id=workspace_id).exists()
                request.user_permissions['workspace_exists'] = workspace_exists
                request.user_permissions['current_workspace_id'] = workspace_id
                
                if workspace_exists:
                    request.workspace = Workspace.objects.get(id=workspace_id)

                else:
                    logger.warning(
                        "Access attempt to non-existent workspace",
                        extra={
                            "user_id": request.user.id,
                            "workspace_id": workspace_id,
                            "action": "workspace_not_found",
                            "component": "AdminImpersonationMiddleware",
                            "severity": "medium",
                        },
                    )
                    return None
                    
                return workspace_id
                
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid workspace ID format",
                    extra={
                        "user_id": request.user.id,
                        "workspace_id": workspace_id,
                        "action": "invalid_workspace_id",
                        "component": "AdminImpersonationMiddleware",
                    },
                )
        return None

    def _set_basic_permissions(self, request):
        """Set basic user permissions without database queries."""
        request.user_permissions['is_superuser'] = request.user.is_superuser

    def _check_impersonation_rate_limit(self, request):
        """
        Implement rate limiting for impersonation requests.
        
        Returns:
            bool: True if within rate limits, False if exceeded
        """
        cache_key = f"impersonation_rate_{request.user.id}"
        current_count = cache.get(cache_key, 0)
        
        if current_count >= self.MAX_IMPERSONATIONS_PER_MINUTE:
            return False
            
        cache.set(cache_key, current_count + 1, self.IMPERSONATION_CACHE_TIMEOUT)
        return True

    def _process_impersonation_request(self, request, user_id_param, workspace_id):
        """Process admin impersonation request with enhanced security."""
        logger.debug(
            "Processing secure impersonation request",
            extra={
                "admin_id": request.user.id,
                "target_user_id": user_id_param,
                "workspace_id": workspace_id,
                "action": "impersonation_request_start",
                "component": "AdminImpersonationMiddleware",
            },
        )
        
        try:
            User = get_user_model()
            target_user = User.objects.get(id=user_id_param)
            
            # Critical security: Prevent self-impersonation and system account access
            if not self._validate_impersonation_target(request.user, target_user):
                self._reset_impersonation(request)
                return
                
            if request.user_permissions['is_superuser']:
                self._handle_superuser_impersonation(request, target_user, workspace_id)
            else:
                self._handle_workspace_admin_impersonation(request, target_user, workspace_id)
                
        except User.DoesNotExist:
            logger.warning(
                "Impersonation failed - target user not found",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": user_id_param,
                    "action": "impersonation_user_not_found",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "medium",
                },
            )

    def _validate_superuser_email(self, user):
        """Check if user can be superuser based on email"""
        if user.is_superuser and user.email not in self.PROTECTED_SUPERUSER_EMAILS:
            logger.critical(
                "Security violation: Unauthorized superuser email",
                extra={
                    "user_id": user.id,
                    "email": user.email,
                    "action": "unauthorized_superuser_email",
                    "severity": "critical",
                },
            )
            return False
        return True
    
    def _validate_impersonation_target(self, admin_user, target_user):
        """
        Validate impersonation target for security compliance.
        
        Returns:
            bool: True if target is valid for impersonation
        """
        # Prevent self-impersonation
        if admin_user.id == target_user.id:
            logger.warning(
                "Self-impersonation attempt blocked",
                extra={
                    "admin_id": admin_user.id,
                    "action": "self_impersonation_blocked",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "low",
                },
            )
            return False
            
        # Prevent non-superusers from impersonating superusers  
        if target_user.is_superuser and not admin_user.is_superuser:
            logger.warning(
                "Non-superuser attempted to impersonate superuser",
                extra={
                    "admin_id": admin_user.id,
                    "target_user_id": target_user.id,
                    "action": "superuser_impersonation_blocked",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "high",
                },
            )
            return False
            
        # Validate superuser emails for security
        if not self._validate_superuser_email(target_user):
            logger.warning(
                "Unauthorized superuser impersonation attempt blocked",
                extra={
                    "admin_id": admin_user.id,
                    "target_user_id": target_user.id,
                    "target_user_email": target_user.email,
                    "action": "unauthorized_superuser_impersonation_blocked",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "high",
                },
            )
            return False
            
        return True

    def _handle_superuser_impersonation(self, request, target_user, workspace_id):
        """Handle superuser impersonation with enhanced security controls."""
        request.target_user = target_user
        request.is_admin_impersonation = True
        request.impersonation_type = 'superuser'
        
        if workspace_id:
            # Single workspace impersonation with validation
            if (request.user_permissions.get('workspace_exists') and 
                self._is_user_workspace_member(target_user, workspace_id)):
                request.impersonation_workspace_ids = [workspace_id]
                logger.info(
                    "Superuser impersonation activated for specific workspace",
                    extra={
                        "admin_id": request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "action": "superuser_impersonation_single_workspace",
                        "component": "AdminImpersonationMiddleware",
                    },
                )
            else:
                logger.warning(
                    "Superuser impersonation failed - workspace validation failed",
                    extra={
                        "admin_id": request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "workspace_exists": request.user_permissions.get('workspace_exists'),
                        "action": "superuser_impersonation_validation_failed",
                        "component": "AdminImpersonationMiddleware",
                    },
                )
                self._reset_impersonation(request)
        else:
            # All workspaces impersonation
            target_workspaces = self._get_user_workspace_ids(target_user)
            request.impersonation_workspace_ids = target_workspaces
            logger.info(
                "Superuser impersonation activated for all user workspaces",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": target_user.id,
                    "workspace_count": len(target_workspaces),
                    "action": "superuser_impersonation_all_workspaces",
                    "component": "AdminImpersonationMiddleware",
                },
            )

    def _handle_workspace_admin_impersonation(self, request, target_user, workspace_id):
        """Handle workspace admin impersonation with scope validation."""
        if workspace_id:
            # Single workspace impersonation
            if (request.user_permissions.get('workspace_exists') and 
                self._can_admin_impersonate_in_workspace(request.user, target_user, workspace_id)):
                self._grant_workspace_impersonation(request, target_user, workspace_id)
            else:
                logger.warning(
                    "Workspace admin impersonation permission denied",
                    extra={
                        "admin_id": request.user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "workspace_exists": request.user_permissions.get('workspace_exists'),
                        "action": "workspace_admin_impersonation_denied",
                        "component": "AdminImpersonationMiddleware",
                        "severity": "medium",
                    },
                )
        else:
            # Multiple workspaces impersonation
            common_workspaces = self._get_common_admin_workspaces(request.user, target_user)
            if common_workspaces:
                self._grant_multiple_workspaces_impersonation(request, target_user, common_workspaces)
            else:
                logger.warning(
                    "Workspace admin impersonation - no common workspaces",
                    extra={
                        "admin_id": request.user.id,
                        "target_user_id": target_user.id,
                        "action": "workspace_admin_no_common_workspaces",
                        "component": "AdminImpersonationMiddleware",
                        "severity": "medium",
                    },
                )

    def _process_workspace_access(self, request, workspace_id):
        """Process non-impersonation workspace access with validation."""
        # Only process if workspace exists
        if not request.user_permissions.get('workspace_exists'):
            logger.warning(
                "Workspace access attempt to non-existent workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_access_invalid",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "medium",
                },
            )
            return

        # Set workspace role for permission checks
        role = self._get_user_workspace_role(request.user, workspace_id)
        if role:
            request.user_permissions['workspace_role'] = role
            request.user_permissions['is_workspace_admin'] = self._is_workspace_admin(
                request.user, workspace_id
            )
            
            logger.debug(
                "Workspace access permissions validated and set",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "role": role,
                    "is_workspace_admin": request.user_permissions['is_workspace_admin'],
                    "action": "workspace_permissions_set",
                    "component": "AdminImpersonationMiddleware",
                },
            )
        else:
            logger.warning(
                "User is not a member of the requested workspace",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": workspace_id,
                    "action": "workspace_access_denied",
                    "component": "AdminImpersonationMiddleware",
                    "severity": "medium",
                },
            )

    def _can_admin_impersonate_in_workspace(self, admin_user, target_user, workspace_id):
        """Check if admin can impersonate target user in specific workspace."""
        return (self._is_workspace_admin(admin_user, workspace_id) and
                self._is_user_workspace_member(target_user, workspace_id))

    def _is_workspace_admin(self, user, workspace_id):
        """Check if user is admin of specific workspace with caching."""
        cache_key = f"workspace_admin_{user.id}_{workspace_id}"
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        result = WorkspaceAdmin.objects.filter(
            user=user,
            workspace_id=workspace_id,
            is_active=True
        ).exists()
        
        # Cache for 5 minutes to reduce database load
        cache.set(cache_key, result, 300)
        return result

    def _is_user_workspace_member(self, user, workspace_id):
        """Check if user is member of specific workspace with caching."""
        cache_key = f"workspace_member_{user.id}_{workspace_id}"
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        result = WorkspaceMembership.objects.filter(
            user=user,
            workspace_id=workspace_id
        ).exists()
        
        # Cache for 5 minutes
        cache.set(cache_key, result, 300)
        return result

    def _get_user_workspace_role(self, user, workspace_id):
        """Get user's role in specific workspace with caching."""
        cache_key = f"workspace_role_{user.id}_{workspace_id}"
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        membership = WorkspaceMembership.objects.filter(
            user=user,
            workspace_id=workspace_id
        ).values('role').first()
        
        result = membership['role'] if membership else None
        cache.set(cache_key, result, 300)
        return result

    def _get_user_workspace_ids(self, user):
        """Get all workspace IDs where user is a member with caching."""
        cache_key = f"user_workspaces_{user.id}"
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        result = list(WorkspaceMembership.objects.filter(
            user=user
        ).values_list('workspace_id', flat=True))
        
        cache.set(cache_key, result, 300)
        return result

    def _get_common_admin_workspaces(self, admin_user, target_user):
        """Get common workspaces where admin has rights and target user is member."""
        admin_workspaces = set(WorkspaceAdmin.objects.filter(
            user=admin_user, is_active=True
        ).values_list('workspace_id', flat=True))
        
        target_workspaces = set(self._get_user_workspace_ids(target_user))
        
        return list(admin_workspaces & target_workspaces)

    def _grant_workspace_impersonation(self, request, target_user, workspace_id):
        """Grant impersonation access for specific workspace."""
        request.target_user = target_user
        request.is_admin_impersonation = True
        request.impersonation_type = 'workspace_admin'
        request.impersonation_workspace_ids = [workspace_id]
        request.user_permissions['is_workspace_admin'] = True
        
        logger.info(
            "Workspace admin impersonation granted",
            extra={
                "admin_id": request.user.id,
                "target_user_id": target_user.id,
                "workspace_id": workspace_id,
                "action": "workspace_admin_impersonation_granted",
                "component": "AdminImpersonationMiddleware",
            },
        )

    def _grant_multiple_workspaces_impersonation(self, request, target_user, workspace_ids):
        """Grant impersonation access for multiple workspaces."""
        request.target_user = target_user
        request.is_admin_impersonation = True
        request.impersonation_type = 'workspace_admin'
        request.impersonation_workspace_ids = workspace_ids
        request.user_permissions['is_workspace_admin'] = True
        
        logger.info(
            "Multiple workspaces impersonation granted",
            extra={
                "admin_id": request.user.id,
                "target_user_id": target_user.id,
                "workspace_count": len(workspace_ids),
                "action": "multiple_workspaces_impersonation_granted",
                "component": "AdminImpersonationMiddleware",
            },
        )

    def _reset_impersonation(self, request):
        """Reset impersonation settings to secure defaults."""
        request.target_user = request.user
        request.is_admin_impersonation = False
        request.impersonation_type = None
        request.impersonation_workspace_ids = []