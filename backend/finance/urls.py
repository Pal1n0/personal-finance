from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'user-settings', views.UserSettingsViewSet, basename='user-settings')
router.register(r'transactions', views.TransactionViewSet, basename='transaction')
router.register(r'categories', views.CategoryViewSet, basename='category')
router.register(r'exchange-rates', views.ExchangeRateViewSet, basename='exchange-rate')
router.register(r'category-properties', views.CategoryPropertyViewSet, basename='category-property')

urlpatterns = [
    path('', include(router.urls)),
    path('workspaces/<int:workspace_id>/categories/<str:category_type>/sync/', 
         views.sync_categories_api, name='sync-categories'),
]
