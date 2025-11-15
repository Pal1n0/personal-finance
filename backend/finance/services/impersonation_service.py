# finance/services/impersonation_service.py
"""
Production-grade impersonation service with comprehensive security validation.
Optimized for performance with cached data access and rate limiting.
"""

import logging
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth import get_user_model
from .membership_cache_service import MembershipCacheService

logger = logging.getLogger(__name__)


class ImpersonationService:
    """
    High-performance impersonation service with security validation.
    Uses cached data access to eliminate duplicate database queries.
    """

    MAX_IMPERSONATIONS_PER_MINUTE = 10
    IMPERSONATION_CACHE_TIMEOUT = 60
    ALLOWED_SUPERUSER_EMAILS = getattr(settings, 'PROTECTED_SUPERUSER_EMAILS', set())

    membership_service = MembershipCacheService()


    def check_rate_limit(self, admin_id):
        """
        Check impersonation rate limit with caching.
        
        Args:
            admin_id: Admin user ID
            
        Returns:
            bool: True if within rate limits
        """
        cache_key = f"impersonation_rate_{admin_id}"
        current_count = cache.get(cache_key, 0)
        
        if current_count >= self.MAX_IMPERSONATIONS_PER_MINUTE:
            logger.warning(
                "Impersonation rate limit exceeded",
                extra={
                    "admin_id": admin_id,
                    "current_count": current_count,
                    "limit": self.MAX_IMPERSONATIONS_PER_MINUTE,
                    "action": "impersonation_rate_limit_exceeded",
                    "component": "ImpersonationService"
                }
            )
            return False
            
        cache.set(cache_key, current_count + 1, self.IMPERSONATION_CACHE_TIMEOUT)
        return True

    def validate_impersonation_target(self, admin_user, target_user):
        """
        Comprehensive security validation for impersonation targets.
        
        Args:
            admin_user: Admin user instance
            target_user: Target user instance
            
        Returns:
            bool: True if target is valid for impersonation
        """
        if admin_user.id == target_user.id:
            logger.warning(
                "Self-impersonation attempt blocked",
                extra={
                    "admin_id": admin_user.id,
                    "action": "self_impersonation_blocked",
                    "component": "ImpersonationService",
                    "severity": "low"
                }
            )
            return False
            
        if target_user.is_superuser and not admin_user.is_superuser:
            logger.warning(
                "Non-superuser attempted to impersonate superuser",
                extra={
                    "admin_id": admin_user.id,
                    "target_user_id": target_user.id,
                    "action": "superuser_impersonation_blocked",
                    "component": "ImpersonationService", 
                    "severity": "high"
                }
            )
            return False
            
        if target_user.is_superuser and target_user.email not in self.ALLOWED_SUPERUSER_EMAILS:
            logger.critical(
                "Security violation: Unauthorized superuser email",
                extra={
                    "admin_id": admin_user.id,
                    "target_user_id": target_user.id,
                    "target_user_email": target_user.email,
                    "action": "unauthorized_superuser_email",
                    "component": "ImpersonationService",
                    "severity": "critical"
                }
            )
            return False
            
        return True

    def process_superuser_impersonation(self, admin_user, target_user, workspace_id):
        """
        Handle superuser impersonation with optimized data access.
        
        Args:
            admin_user: Admin user instance
            target_user: Target user instance  
            workspace_id: Optional workspace ID
            
        Returns:
            list: Workspace IDs for impersonation
        """
        if workspace_id:
            is_member = self.membership_service.is_user_workspace_member(target_user.id, workspace_id)
            if is_member:
                logger.info(
                    "Superuser impersonation for specific workspace",
                    extra={
                        "admin_id": admin_user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "action": "superuser_impersonation_single_workspace",
                        "component": "ImpersonationService"
                    }
                )
                return [workspace_id]
            else:
                logger.warning(
                    "Superuser impersonation failed - target not workspace member",
                    extra={
                        "admin_id": admin_user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "action": "superuser_impersonation_member_check_failed",
                        "component": "ImpersonationService"
                    }
                )
                return []
        else:
            user_data = self.membership_service.get_comprehensive_user_data(target_user.id)
            workspace_ids = user_data['all_workspace_ids']
            
            logger.info(
                "Superuser impersonation for all user workspaces",
                extra={
                    "admin_id": admin_user.id,
                    "target_user_id": target_user.id,
                    "workspace_count": len(workspace_ids),
                    "action": "superuser_impersonation_all_workspaces",
                    "component": "ImpersonationService"
                }
            )
            return workspace_ids

    def process_workspace_admin_impersonation(self, admin_user, target_user, workspace_id):
        """
        Handle workspace admin impersonation with optimized checks.
        
        Args:
            admin_user: Admin user instance
            target_user: Target user instance
            workspace_id: Optional workspace ID
            
        Returns:
            list: Workspace IDs for impersonation
        """
        if workspace_id:
            is_admin = self.membership_service.is_workspace_admin(admin_user.id, workspace_id)
            if is_admin:
                logger.info(
                    "Workspace admin impersonation for specific workspace",
                    extra={
                        "admin_id": admin_user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "action": "workspace_admin_impersonation_single_workspace",
                        "component": "ImpersonationService"
                    }
                )
                return [workspace_id]
            else:
                logger.warning(
                    "Workspace admin impersonation permission denied",
                    extra={
                        "admin_id": admin_user.id,
                        "target_user_id": target_user.id,
                        "workspace_id": workspace_id,
                        "action": "workspace_admin_impersonation_denied",
                        "component": "ImpersonationService",
                        "severity": "medium"
                    }
                )
                return []
        else:
            admin_data = self.membership_service.get_comprehensive_user_data(admin_user.id)
            target_data = self.membership_service.get_comprehensive_user_data(target_user.id)
            
            common_workspaces = admin_data['admin_workspaces'] & set(target_data['all_workspace_ids'])
            workspace_ids = list(common_workspaces)
            
            if workspace_ids:
                logger.info(
                    "Workspace admin impersonation for multiple workspaces",
                    extra={
                        "admin_id": admin_user.id,
                        "target_user_id": target_user.id,
                        "workspace_count": len(workspace_ids),
                        "action": "workspace_admin_impersonation_multiple_workspaces",
                        "component": "ImpersonationService"
                    }
                )
            else:
                logger.warning(
                    "Workspace admin impersonation - no common workspaces",
                    extra={
                        "admin_id": admin_user.id,
                        "target_user_id": target_user.id,
                        "action": "workspace_admin_no_common_workspaces",
                        "component": "ImpersonationService",
                        "severity": "medium"
                    }
                )
                
            return workspace_ids

    def process_impersonation(self, admin_user, target_user_id, workspace_id):
        """
        Main impersonation processing with optimized data flow.
        
        Args:
            admin_user: Admin user instance
            target_user_id: Target user ID
            workspace_id: Optional workspace ID
            
        Returns:
            tuple: (target_user, is_granted, impersonation_type, workspace_ids)
        """
        User = get_user_model()
        
        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            logger.warning(
                "Impersonation failed - target user not found",
                extra={
                    "admin_id": admin_user.id,
                    "target_user_id": target_user_id,
                    "action": "impersonation_user_not_found",
                    "component": "ImpersonationService",
                    "severity": "medium"
                }
            )
            return admin_user, False, None, []

        if not self.validate_impersonation_target(admin_user, target_user):
            return admin_user, False, None, []

        if admin_user.is_superuser:
            workspace_ids = self.process_superuser_impersonation(admin_user, target_user, workspace_id)
            return target_user, True, 'superuser', workspace_ids
        else:
            workspace_ids = self.process_workspace_admin_impersonation(admin_user, target_user, workspace_id)
            if workspace_ids:
                return target_user, True, 'workspace_admin', workspace_ids
            else:
                return admin_user, False, None, []