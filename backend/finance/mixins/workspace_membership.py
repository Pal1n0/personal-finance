# finance/mixins/workspace_membership.py
"""
Production-grade mixin for cached workspace membership data access.
Eliminates duplicate database queries through optimized request-level caching.
"""

import logging

from ..services.membership_cache_service import MembershipCacheService

logger = logging.getLogger(__name__)


# Service instance for thread-safe access
MEMBERSHIP_SERVICE = MembershipCacheService()


class WorkspaceMembershipMixin:
    """
    Advanced mixin for cached workspace membership data access.
    Uses service layer for optimized data fetching.
    """

    # Class-level service instance for thread-safe access
    membership_service = MEMBERSHIP_SERVICE

    def _get_user_memberships(self, request):
        """
        Retrieve cached membership data from request context.

        Args:
            request: HTTP request object

        Returns:
            dict: Cached workspace memberships {workspace_id: role_string}
        """
        if not hasattr(request, "_cached_user_memberships"):
            target_user = getattr(request, "target_user", request.user)
            user_data = self.membership_service.get_comprehensive_user_data(
                target_user.id
            )

            request._cached_user_memberships = user_data["roles"]

            logger.debug(
                "Membership cache initialized from service",
                extra={
                    "user_id": target_user.id,
                    "cached_workspaces_count": len(request._cached_user_memberships),
                    "action": "membership_cache_initialized",
                    "component": "WorkspaceMembershipMixin",
                },
            )

        return request._cached_user_memberships

    def _get_membership_for_workspace(self, obj, request):
        """
        Get user role for specific workspace from optimized cache.

        Args:
            obj: Workspace instance
            request: HTTP request object

        Returns:
            str or None: User's role in the workspace
        """
        memberships = self._get_user_memberships(request)
        role = memberships.get(obj.id)

        if role:
            logger.debug(
                "Workspace role retrieved from cache",
                extra={
                    "user_id": request.user.id,
                    "workspace_id": obj.id,
                    "user_role": role,
                    "action": "workspace_role_cache_hit",
                    "component": "WorkspaceMembershipMixin",
                },
            )

        return role
