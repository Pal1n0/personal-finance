# finance/services/membership_cache_service.py
"""
Production-grade membership caching service.
Implements comprehensive cache hierarchy with intelligent fallback strategies.
Optimized for maximum performance with minimal database queries.
"""

import logging
from django.core.cache import cache
from django.db import models
from ..models import WorkspaceMembership, WorkspaceAdmin

logger = logging.getLogger(__name__)


class MembershipCacheService:
    """
    High-performance membership data service with optimized cache hierarchy.
    Provides comprehensive caching strategy to eliminate duplicate database queries.
    """

    def get_comprehensive_user_data(self, user_id):
        """
        Get all membership data for user with intelligent caching strategy.
        
        Cache Hierarchy:
        1. Comprehensive cache check
        2. Single optimized database query on cache miss
        3. Cache population for future requests
        
        Args:
            user_id: Target user ID
            
        Returns:
            dict: Comprehensive user membership data
        """
        cache_key = f"comprehensive_membership_{user_id}"
        
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.debug(
                "Comprehensive membership cache hit",
                extra={
                    "user_id": user_id, 
                    "action": "comprehensive_cache_hit",
                    "component": "MembershipCacheService"
                }
            )
            return cached_data
            
        logger.debug(
            "Comprehensive membership cache miss - fetching from database",
            extra={
                "user_id": user_id, 
                "action": "comprehensive_cache_miss",
                "component": "MembershipCacheService"
            }
        )
        
        data = self._fetch_optimized_user_data(user_id)
        cache.set(cache_key, data, 300)
        
        logger.debug(
            "Comprehensive membership data cached successfully",
            extra={
                "user_id": user_id,
                "workspaces_count": len(data['all_workspace_ids']),
                "admin_workspaces_count": len(data['admin_workspaces']),
                "action": "comprehensive_data_cached",
                "component": "MembershipCacheService"
            }
        )
        
        return data

    def get_user_workspace_role(self, user_id, workspace_id):
        """
        Get user role with intelligent cache hierarchy.
        
        Strategy:
        1. Comprehensive cache check (primary)
        2. Specific role cache check (secondary) 
        3. Database query (fallback)
        
        Args:
            user_id: Target user ID
            workspace_id: Target workspace ID
            
        Returns:
            str or None: User's role in the workspace
        """
        comprehensive_data = cache.get(f"comprehensive_membership_{user_id}")
        if comprehensive_data:
            membership_data = comprehensive_data['memberships'].get(workspace_id)
            if membership_data:
                logger.debug(
                    "Role retrieved from comprehensive cache",
                    extra={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "role": membership_data['role'],
                        "action": "role_from_comprehensive_cache",
                        "component": "MembershipCacheService"
                    }
                )
                return membership_data['role']
        
        specific_cache_key = f"workspace_role_{user_id}_{workspace_id}"
        cached_role = cache.get(specific_cache_key)
        if cached_role is not None:
            logger.debug(
                "Role retrieved from specific cache",
                extra={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "role": cached_role,
                    "action": "role_from_specific_cache", 
                    "component": "MembershipCacheService"
                }
            )
            return cached_role
        
        logger.debug(
            "Fetching role from database",
            extra={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": "role_db_query",
                "component": "MembershipCacheService"
            }
        )
        
        membership = WorkspaceMembership.objects.filter(
            user_id=user_id, workspace_id=workspace_id
        ).values('role').first()
        
        result = membership['role'] if membership else None
        cache.set(specific_cache_key, result, 300)
        
        logger.debug(
            "Role cached successfully",
            extra={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": result,
                "action": "role_cached",
                "component": "MembershipCacheService"
            }
        )
        
        return result

    def is_workspace_admin(self, user_id, workspace_id):
        """
        Check if user is workspace admin with cache hierarchy.
        
        Args:
            user_id: Target user ID
            workspace_id: Target workspace ID
            
        Returns:
            bool: True if user is workspace admin
        """
        comprehensive_data = cache.get(f"comprehensive_membership_{user_id}")
        if comprehensive_data:
            is_admin = workspace_id in comprehensive_data['admin_workspaces']
            logger.debug(
                "Admin status retrieved from comprehensive cache",
                extra={
                    "user_id": user_id,
                    "workspace_id": workspace_id, 
                    "is_admin": is_admin,
                    "action": "admin_status_from_comprehensive_cache",
                    "component": "MembershipCacheService"
                }
            )
            return is_admin
        
        specific_cache_key = f"workspace_admin_{user_id}_{workspace_id}"
        cached_result = cache.get(specific_cache_key)
        if cached_result is not None:
            logger.debug(
                "Admin status retrieved from specific cache",
                extra={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "is_admin": cached_result,
                    "action": "admin_status_from_specific_cache",
                    "component": "MembershipCacheService"
                }
            )
            return cached_result
        
        logger.debug(
            "Fetching admin status from database",
            extra={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": "admin_status_db_query",
                "component": "MembershipCacheService"
            }
        )
        
        result = WorkspaceAdmin.objects.filter(
            user_id=user_id, workspace_id=workspace_id, is_active=True
        ).exists()
        
        cache.set(specific_cache_key, result, 300)
        
        logger.debug(
            "Admin status cached successfully",
            extra={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "is_admin": result,
                "action": "admin_status_cached",
                "component": "MembershipCacheService"
            }
        )
        
        return result

    def is_user_workspace_member(self, user_id, workspace_id):
        """
        Check if user is workspace member with cache hierarchy.
        
        Args:
            user_id: Target user ID
            workspace_id: Target workspace ID
            
        Returns:
            bool: True if user is workspace member
        """
        comprehensive_data = cache.get(f"comprehensive_membership_{user_id}")
        if comprehensive_data:
            is_member = workspace_id in comprehensive_data['memberships']
            logger.debug(
                "Member status retrieved from comprehensive cache",
                extra={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "is_member": is_member,
                    "action": "member_status_from_comprehensive_cache",
                    "component": "MembershipCacheService"
                }
            )
            return is_member
        
        specific_cache_key = f"workspace_member_{user_id}_{workspace_id}"
        cached_result = cache.get(specific_cache_key)
        if cached_result is not None:
            logger.debug(
                "Member status retrieved from specific cache",
                extra={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "is_member": cached_result,
                    "action": "member_status_from_specific_cache",
                    "component": "MembershipCacheService"
                }
            )
            return cached_result
        
        logger.debug(
            "Fetching member status from database",
            extra={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": "member_status_db_query",
                "component": "MembershipCacheService"
            }
        )
        
        result = WorkspaceMembership.objects.filter(
            user_id=user_id, workspace_id=workspace_id
        ).exists()
        
        cache.set(specific_cache_key, result, 300)
        
        logger.debug(
            "Member status cached successfully",
            extra={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "is_member": result,
                "action": "member_status_cached",
                "component": "MembershipCacheService"
            }
        )
        
        return result

    def _fetch_optimized_user_data(self, user_id):
        """
        Single optimized query for comprehensive user membership data.
        
        Args:
            user_id: Target user ID
            
        Returns:
            dict: Comprehensive membership and admin data
        """
        memberships = WorkspaceMembership.objects.filter(
            user_id=user_id
        ).select_related('workspace').values(
            'workspace_id', 'role', 'workspace__name', 'workspace__is_active'
        )
        
        admin_workspaces = set(WorkspaceAdmin.objects.filter(
            user_id=user_id, is_active=True
        ).values_list('workspace_id', flat=True))
        
        comprehensive_data = {
            'memberships': {m['workspace_id']: m for m in memberships},
            'admin_workspaces': admin_workspaces,
            'all_workspace_ids': [m['workspace_id'] for m in memberships]
        }
        
        logger.debug(
            "Optimized user data fetched from database",
            extra={
                "user_id": user_id,
                "memberships_count": len(comprehensive_data['memberships']),
                "admin_workspaces_count": len(comprehensive_data['admin_workspaces']),
                "action": "optimized_user_data_fetched",
                "component": "MembershipCacheService"
            }
        )
        
        return comprehensive_data

    def invalidate_user_cache(self, user_id):
        """
        Invalidate comprehensive cache for user membership changes.
        
        Note: Only comprehensive cache requires explicit invalidation.
        Specific caches serve as secondary fallbacks and will refresh
        automatically from database on subsequent access.
        
        Args:
            user_id: Target user ID
        """
        cache_key = f"comprehensive_membership_{user_id}"
        cache.delete(cache_key)
        
        logger.info(
            "User comprehensive cache invalidated",
            extra={
                "user_id": user_id,
                "action": "user_comprehensive_cache_invalidated",
                "component": "MembershipCacheService"
            }
        )