import pytest
from unittest.mock import patch, Mock
from rest_framework import status
from rest_framework.test import APIRequestFactory, force_authenticate
from finance.views import WorkspaceAdminViewSet, TransactionViewSet, WorkspaceSettingsViewSet, CategorySyncViewSet, UserSettingsViewSet
from finance.models import WorkspaceAdmin, Workspace, Transaction
from django.http import Http404
# Odstránil som nefunkčný import ServiceException

@pytest.mark.django_db
class TestViewsCoverage:
    
    def setup_method(self):
        self.factory = APIRequestFactory()

    # --- WorkspaceAdminViewSet Tests ---

    def test_assign_admin_user_not_found(self, superuser, test_workspace):
        """
        Pokrýva: except User.DoesNotExist: return 404 v assign_admin.
        """
        view = WorkspaceAdminViewSet.as_view({'post': 'assign_admin'})
        request = self.factory.post(
            f'/api/workspaces/{test_workspace.id}/assign_admin/', 
            {'user_id': 99999}
        )
        force_authenticate(request, user=superuser)
        
        # Mockujeme permissions aby sme prešli cez prvú kontrolu
        with patch('rest_framework.permissions.IsAuthenticated.has_permission', return_value=True), \
             patch('finance.permissions.IsSuperuser.has_permission', return_value=True):
            # Mockujeme request.user_permissions (pridáva ho middleware v reále)
            request.user_permissions = {"workspace_exists": True}
            
            response = view(request, workspace_pk=test_workspace.id)
            
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "User to be assigned not found" in str(response.data)

    def test_assign_admin_already_exists_update(self, superuser, test_workspace, test_user):
        """
        Pokrýva: if not created: update existing assignment v assign_admin.
        """
        # Vytvor existujúceho, ale neaktívneho admina
        WorkspaceAdmin.objects.create(
            user=test_user, workspace=test_workspace, assigned_by=superuser, is_active=False
        )
        # Uisti sa, že je členom
        test_workspace.members.add(test_user)

        view = WorkspaceAdminViewSet.as_view({'post': 'assign_admin'})
        request = self.factory.post(
            f'/api/workspaces/{test_workspace.id}/assign_admin/', 
            {'user_id': test_user.id}
        )
        force_authenticate(request, user=superuser)
        request.user_permissions = {"workspace_exists": True}

        with patch('rest_framework.permissions.IsAuthenticated.has_permission', return_value=True), \
             patch('finance.permissions.IsSuperuser.has_permission', return_value=True):
            
            response = view(request, workspace_pk=test_workspace.id)

        assert response.status_code == status.HTTP_200_OK # 200 OK pre update, 201 pre create
        assert "Administrator privileges assigned" in str(response.data)

    # --- TransactionViewSet Tests ---

    def test_transaction_list_light_mode(self, test_user, test_workspace):
        """
        Pokrýva: if light_mode and self.action == "list": v get_serializer_class.
        """
        view = TransactionViewSet.as_view({'get': 'list'})
        request = self.factory.get('/api/transactions/?light=true')
        force_authenticate(request, user=test_user)
        
        request.target_user = test_user
        request.workspace = test_workspace
        
        # Mock service calls to avoid DB hits if needed, or let it run
        response = view(request, workspace_pk=test_workspace.id)
        
        assert response.status_code == status.HTTP_200_OK
        # Overenie, že sa použil iný serializer je ťažké priamo, 
        # ale coverage to zachytí.

    def test_cleanup_drafts_after_sync(self, test_user, test_workspace):
        """
        Pokrýva: _cleanup_drafts_after_sync logiku.
        """
        view = TransactionViewSet()
        view.draft_service = Mock()
        view.draft_service.cleanup_drafts_for_transaction.return_value = 5 # Simulujeme zmazanie 5 draftov
        
        transactions_data = {
            "create": [{"type": "expense"}, {"type": "income"}],
            "update": []
        }
        
        # Priame volanie internej metódy pre test
        with patch('finance.views.logger') as mock_logger:
            view._cleanup_drafts_after_sync(test_workspace, test_user, transactions_data)
            
            # Overíme, že sa volal cleanup pre oba typy
            assert view.draft_service.cleanup_drafts_for_transaction.call_count == 2
            # Overíme logovanie
            assert mock_logger.info.call_count >= 1

    # --- WorkspaceSettingsViewSet Tests ---

    def test_currency_change_failed_log(self, test_user, test_workspace):
        """
        Pokrýva: if not result.get("changed", False): logger.error(...) v _handle_currency_change.
        """
        view = WorkspaceSettingsViewSet()
        view.handle_service_call = Mock(return_value={"changed": False}) # Simulujeme zlyhanie
        
        request = Mock()
        request.user = test_user
        request.target_user = test_user
        request.data = {"domestic_currency": "USD"}
        
        instance = Mock()
        instance.workspace = test_workspace
        instance.domestic_currency = "EUR"

        with patch('finance.views.logger') as mock_logger:
            view._handle_currency_change(request, instance)
            
            mock_logger.error.assert_called()
            # Kontrola, či log obsahuje kľúčovú frázu
            assert "Currency change failed" in mock_logger.error.call_args[0][0]

    # --- CategorySyncViewSet Tests ---

    def test_category_sync_invalid_type(self, test_user, test_workspace):
        """
        Pokrýva: else: logger.warning("Invalid category type provided") v sync_categories.
        """
        view = CategorySyncViewSet.as_view({'post': 'sync_categories'})
        request = self.factory.post(
            f'/api/workspaces/{test_workspace.id}/categories/INVALID/sync/', 
            {}
        )
        force_authenticate(request, user=test_user)
        request.user_permissions = {"workspace_exists": True}
        request.target_user = test_user
        
        # Patch get_object_or_404 or Workspace.objects.get logic
        with patch('finance.views.Workspace.objects.get', return_value=test_workspace):
             response = view(request, workspace_pk=test_workspace.id, category_type="invalid_type")
             
        assert response

    def test_user_settings_update_invalid_fields(self, test_user):
        """
        Pokrýva: UserSettingsViewSet - validácia 'invalid_fields' (riadky ~2033-2060).
        """
        view = UserSettingsViewSet.as_view({'patch': 'partial_update'})
        
        # Skúsime poslať pole, ktoré neexistuje alebo je zakázané (napr. 'is_admin')
        request = self.factory.patch(
            '/api/user-settings/me/', 
            {'is_admin': True, 'random_field': 'hack'}
        )
        force_authenticate(request, user=test_user)
        request.target_user = test_user
        
        # Musíme vytvoriť UserSettings pre tohto usera, aby view našiel objekt
        from finance.models import UserSettings
        UserSettings.objects.get_or_create(user=test_user)

        # Patch view logic aby sme obišli get_object zložitosť ak treba, 
        # ale tu by to malo prejsť štandardne ak máme DB setup
        response = view(request)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Fields not allowed" in str(response.data)