# finance/mixins/workspace_context.py
"""
Production-grade workspace context mixin.
Thin wrapper around workspace context service with proper error propagation.
"""

import logging
from ..services.workspace_context_service import WorkspaceContextService

logger = logging.getLogger(__name__)


class WorkspaceContextMixin:
    """
    Optimized mixin for workspace context building.
    Delegates complex logic to services while maintaining proper request flow.
    """

    def initial(self, request, *args, **kwargs):
        """
        Initialize workspace context before any view processing.
        
        Args:
            request: HTTP request object
            *args: Additional arguments
            **kwargs: Additional keyword arguments
        """
        super().initial(request, *args, **kwargs)
        self._process_workspace_context(request)
    
    def _process_workspace_context(self, request):
        """
        Process workspace context using optimized service.
        
        Args:
            request: HTTP request object
            
        Note:
            Service exceptions are propagated to DRF for proper error handling.
        """
        context_service = WorkspaceContextService()
        context_service.build_request_context(request)