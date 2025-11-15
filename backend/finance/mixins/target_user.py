# finance/mixins/target_user.py
"""
Production-grade mixin for automatic user assignment from request context.
Supports secure admin impersonation with comprehensive audit logging.
"""

import logging

logger = logging.getLogger(__name__)


class TargetUserMixin:
    """
    Mixin for automatic user and workspace assignment from request context.
    """

    def validate(self, attrs):
        """
        Automatically assign user and workspace from request context.
        
        Args:
            attrs: Serializer attributes
            
        Returns:
            dict: Updated attributes with user and workspace assignment
        """
        attrs = super().validate(attrs)
        request = self.context.get('request')
        
        if request:
            if hasattr(request, 'target_user'):
                attrs['user'] = request.target_user
                logger.debug(
                    "User assignment from target_user completed",
                    extra={
                        "target_user_id": request.target_user.id,
                        "impersonation_active": getattr(request, 'is_admin_impersonation', False),
                        "action": "target_user_assignment",
                        "component": "TargetUserMixin",
                    },
                )
            
            if hasattr(request, 'workspace') and 'workspace' not in attrs:
                attrs['workspace'] = request.workspace
                logger.debug(
                    "Workspace assignment from request completed",
                    extra={
                        "workspace_id": request.workspace.id,
                        "action": "workspace_assignment", 
                        "component": "TargetUserMixin",
                    },
                )
        
        return attrs