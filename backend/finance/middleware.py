# finance/middleware.py
import logging
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class AdminImpersonationMiddleware(MiddlewareMixin):
    """
    Middleware to handle admin impersonation globally.
    Processes user_id parameter and sets target_user on request.
    """
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Process admin impersonation after authentication middleware.
        """
        # Early return for non-impersonation cases
        user_id_param = request.GET.get('user_id') or getattr(request, 'data', {}).get('user_id')
        
        if not (request.user.is_authenticated and request.user.is_superuser and user_id_param):
            # Default values - no impersonation
            request.target_user = request.user
            request.is_admin_impersonation = False
            return None

        # Only process admin impersonation for authenticated superusers with user_id parameter
        logger.debug(
            "Processing admin impersonation",
            extra={
                "user_id_param": user_id_param,
                "admin_id": request.user.id,
                "path": request.path,
            },
        )
        
        try:
            User = get_user_model()
            target_user = User.objects.get(id=user_id_param)
            request.target_user = target_user
            request.is_admin_impersonation = True
            
            logger.info(
                "Admin impersonation activated via middleware",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": target_user.id,
                    "path": request.path,
                    "action": "admin_impersonation_middleware_activated",
                    "component": "AdminImpersonationMiddleware",
                },
            )
            
        except (User.DoesNotExist, ValueError):
            logger.warning(
                "Admin impersonation failed via middleware - target user not found",
                extra={
                    "admin_id": request.user.id,
                    "target_user_id": user_id_param,
                    "path": request.path,
                    "action": "admin_impersonation_middleware_failed", 
                    "component": "AdminImpersonationMiddleware",
                    "severity": "medium",
                },
            )
            # Fallback to default user
            request.target_user = request.user
            request.is_admin_impersonation = False
        
        return None