"""
URL configuration for financial management API.

This module defines all API endpoints for the financial management system,
including RESTful routes for resources and custom action endpoints.
"""

import logging
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

# Get structured logger for this module
logger = logging.getLogger(__name__)

# Initialize DefaultRouter for RESTful API endpoints
router = DefaultRouter()

# User settings endpoints
router.register(
    r'user-settings', 
    views.UserSettingsViewSet, 
    basename='user-settings'
)

# Workspace settings endpoints with atomic currency changes
router.register(
    r'workspace-settings', 
    views.WorkspaceSettingsViewSet, 
    basename='workspacesettings'
)

# Transaction management endpoints
router.register(
    r'transactions', 
    views.TransactionViewSet, 
    basename='transaction'
)

# Expense categories endpoints (read-only)
router.register(
    r'expense-categories', 
    views.ExpenseCategoryViewSet, 
    basename='expensecategory'
)

# Income categories endpoints (read-only)
router.register(
    r'income-categories', 
    views.IncomeCategoryViewSet, 
    basename='incomecategory'
)

# Exchange rates endpoints (read-only)
router.register(
    r'exchange-rates', 
    views.ExchangeRateViewSet, 
    basename='exchange-rate'
)

# Workspace management endpoints
router.register(
    r'workspaces', 
    views.WorkspaceViewSet, 
    basename='workspace'
)

# Transaction drafts management endpoints
router.register(
    r'transaction-drafts',
    views.TransactionDraftViewSet,
    basename='transactiondraft'
)

# Custom API endpoints for bulk operations and synchronization
urlpatterns = [
    # Include all router-generated URLs
    path('', include(router.urls)),
    
    # Category synchronization endpoint (JEDENKRÁT!)
    path(
        'workspaces/<int:workspace_id>/categories/<str:category_type>/sync/', 
        views.sync_categories_api, 
        name='sync-categories'
    ),
    
    # Workspace members endpoint
    path(
        'workspaces/<int:pk>/members/',
        views.WorkspaceViewSet.as_view({'get': 'members'}),
        name='workspace-members'
    ),
    
    # Workspace settings endpoint  
    path(
        'workspaces/<int:pk>/settings/',
        views.WorkspaceViewSet.as_view({'get': 'settings'}),
        name='workspace-settings'
    ),
    
    # Transaction bulk delete endpoint
    path(
        'transactions/bulk-delete/',
        views.TransactionViewSet.as_view({'post': 'bulk_delete'}),
        name='transaction-bulk-delete'
    ),
    
    # Bulk transaction synchronization endpoint (PRIBUDOL!)
    path(
    'workspaces/<int:workspace_id>/transactions/bulk-sync/',
    views.TransactionViewSet.as_view({'post': 'bulk_sync'}),
    name='bulk-sync-transactions'
),
]

# Log URL configuration on startup
custom_endpoints_count = len(urlpatterns) - 1  # Subtract the include route
logger.info(
    "Financial API URLs configured successfully",
    extra={
        "total_routes": len(router.urls) + custom_endpoints_count,
        "viewset_endpoints": len(router.registry),
        "custom_endpoints": custom_endpoints_count,  # SPRÁVNY POČET
        "action": "url_configuration_loaded",
        "component": "urls",
    },
)

# Log detailed route information in debug mode
logger.debug(
    "Detailed route configuration",
    extra={
        "registered_viewsets": [
            {
                "prefix": route[0],
                "viewset": route[1].__class__.__name__,
                "basename": route[2]
            }
            for route in router.registry
        ],
        "custom_routes": [
            {
                "pattern": pattern.pattern._route if hasattr(pattern.pattern, '_route') else str(pattern.pattern),
                "name": getattr(pattern, 'name', 'unnamed') 
            }
            for pattern in urlpatterns 
            if hasattr(pattern, 'pattern')
        ],
        "action": "route_detailed_log",
        "component": "urls",
    },
)