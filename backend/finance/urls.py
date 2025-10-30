from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'user-settings', views.UserSettingsViewSet, basename='user-settings')
router.register(r'workspace-settings', views.WorkspaceSettingsViewSet, basename='workspacesettings')
router.register(r'transactions', views.TransactionViewSet, basename='transaction')
router.register(r'expense-categories', views.ExpenseCategoryViewSet, basename='expensecategory')
router.register(r'income-categories', views.IncomeCategoryViewSet, basename='incomecategory')
router.register(r'exchange-rates', views.ExchangeRateViewSet, basename='exchange-rate')
router.register(r'category-properties', views.CategoryPropertyViewSet, basename='category-property')

urlpatterns = [
    path('', include(router.urls)),
    path('workspaces/<int:workspace_id>/categories/<str:category_type>/sync/', 
         views.sync_categories_api, name='sync-categories'),
    path('workspaces/<int:workspace_id>/transactions/bulk-sync/',
     views.bulk_sync_transactions, name='bulk-sync-transactions'),
]
