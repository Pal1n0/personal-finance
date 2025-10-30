from rest_framework import viewsets, mixins
from rest_framework.decorators import api_view, action  
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Q
from django.db import transaction
from datetime import date
from django.shortcuts import get_object_or_404
from .services.transaction_service import TransactionService  # ✅ Import služby
from rest_framework import serializers



from .models import (
    Transaction, UserSettings, Workspace, WorkspaceSettings,
    ExpenseCategoryVersion, IncomeCategoryVersion, 
    ExpenseCategory, IncomeCategory, ExchangeRate
) 
from .serializers import (
    TransactionSerializer, UserSettingsSerializer, WorkspaceSettingsSerializer,
    ExchangeRateSerializer, ExpenseCategorySerializer, IncomeCategorySerializer
)
from .utils.currency_utils import recalculate_transactions_domestic_amount
from .utils.category_utils import sync_categories_tree

# -------------------------------
# User Settings
# -------------------------------
class UserSettingsViewSet(mixins.RetrieveModelMixin,
                         mixins.UpdateModelMixin,
                         viewsets.GenericViewSet):
    serializer_class = UserSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserSettings.objects.filter(user=self.request.user)

    def partial_update(self, request, *args, **kwargs):
        allowed_fields = {'language'}
        for key in request.data.keys():
            if key not in allowed_fields:
                return Response({"error": f"{key} cannot be updated"}, status=400)
        return super().partial_update(request, *args, **kwargs)

# -------------------------------
# Workspace Settings
# -------------------------------
class WorkspaceSettingsViewSet(mixins.RetrieveModelMixin,
                              mixins.UpdateModelMixin,
                              viewsets.GenericViewSet):
    serializer_class = WorkspaceSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return WorkspaceSettings.objects.filter(workspace__members=self.request.user)

    def partial_update(self, request, *args, **kwargs):
        allowed_fields = {
            'domestic_currency', 
            'fiscal_year_start', 
            'display_mode', 
            'accounting_mode'
        }
        for key in request.data.keys():
            if key not in allowed_fields:
                return Response({"error": f"{key} cannot be updated"}, status=400)
        return super().partial_update(request, *args, **kwargs)

# -------------------------------
# Expense Category
# -------------------------------
class ExpenseCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExpenseCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Aktívne verzie workspace, kde je user členom
        active_versions = ExpenseCategoryVersion.objects.filter(
            workspace__members=self.request.user,
            is_active=True
        )
        return ExpenseCategory.objects.filter(version__in=active_versions)\
            .prefetch_related('property')  # Tu pridáme prefetch pre property

# -------------------------------
# Income Category
# -------------------------------
class IncomeCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = IncomeCategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Aktívne verzie workspace, kde je user členom
        active_versions = IncomeCategoryVersion.objects.filter(
            workspace__members=self.request.user,
            is_active=True
        )
        return IncomeCategory.objects.filter(version__in=active_versions)\
            .prefetch_related('property')  # Tu pridáme prefetch pre property

# -------------------------------
# Transaction
# -------------------------------
class TransactionViewSet(viewsets.ModelViewSet):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # ✅ Pridané workspace filter
        qs = Transaction.objects.filter(
            user=self.request.user,
            workspace__members=self.request.user
        )
        
        tx_type = self.request.query_params.get('type')
        fiscal_year = self.request.query_params.get('fiscal_year')
        month = self.request.query_params.get('month')

        # Filter podľa typu
        if tx_type in ['income', 'expense']:
            qs = qs.filter(type=tx_type)

        # ✅ Zmenené na WorkspaceSettings
        workspace_id = self.request.query_params.get('workspace')
        if workspace_id:
            try:
                workspace_settings = WorkspaceSettings.objects.get(
                    workspace_id=workspace_id,
                    workspace__members=self.request.user
                )
                fiscal_start_month = workspace_settings.fiscal_year_start

                if fiscal_year:
                    fiscal_year = int(fiscal_year)
                    start_date = date(fiscal_year - 1, fiscal_start_month, 1) if fiscal_start_month > 1 else date(fiscal_year, 1, 1)
                    end_date = date(fiscal_year, fiscal_start_month, 1) if fiscal_start_month > 1 else date(fiscal_year, 12, 31)
                    qs = qs.filter(date__gte=start_date, date__lt=end_date)

            except WorkspaceSettings.DoesNotExist:
                pass

        # Filter podľa mesiaca
        if month:
            month = int(month)
            qs = qs.filter(date__month=month)

        return qs
    
    def perform_create(self, serializer):
        workspace = serializer.validated_data.get('workspace')
        if workspace and workspace.members.filter(id=self.request.user.id).exists():
            # ✅ Pridať workspace validation pre category
            expense_category = serializer.validated_data.get('expense_category')
            income_category = serializer.validated_data.get('income_category')
            
            if expense_category and expense_category.version.workspace != workspace:
                raise serializers.ValidationError("Expense category does not belong to this workspace")
                
            if income_category and income_category.version.workspace != workspace:
                raise serializers.ValidationError("Income category does not belong to this workspace")
            
            instance = serializer.save(user=self.request.user)
            if instance.date:
                instance.month = instance.date.replace(day=1)
                instance.save(update_fields=['month'])
        else:
            raise serializers.ValidationError("You don't have access to this workspace")

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.date:
            instance.month = instance.date.replace(day=1)
            instance.save(update_fields=['month'])

    @action(detail=False, methods=['post'])
    @transaction.atomic
    def bulk_delete(self, request):
        """Atomic bulk delete transakcií"""
        transaction_ids = request.data.get('ids', [])
        transactions = Transaction.objects.filter(
            id__in=transaction_ids,
            user=request.user
        )
        count, _ = transactions.delete()
        return Response({'deleted': count})


@api_view(['POST'])
@transaction.atomic
def bulk_sync_transactions(request, workspace_id):
    """Univerzálny atomic bulk sync transakcií"""
    try:
        workspace = Workspace.objects.get(id=workspace_id, members=request.user)
        transactions_data = request.data
        
        results = TransactionService.bulk_sync_transactions(
            transactions_data, 
            workspace, 
            request.user
        )
        
        return Response(results)
        
    except Workspace.DoesNotExist:
        return Response({'error': 'Workspace not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=400)

# -------------------------------
# Exchange Rate
# -------------------------------
class ExchangeRateViewSet(viewsets.GenericViewSet,
                          mixins.ListModelMixin,
                          mixins.RetrieveModelMixin):
    serializer_class = ExchangeRateSerializer
    permission_classes = [IsAuthenticated]
    queryset = ExchangeRate.objects.all()

    def get_queryset(self):
        qs = super().get_queryset()
        currencies = self.request.query_params.get('currencies')
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')

        if currencies:
            currency_list = [c.strip().upper() for c in currencies.split(',')]
            qs = qs.filter(currency__in=currency_list)

        if date_from:
            qs = qs.filter(date__gte=date_from)
        if date_to:
            qs = qs.filter(date__lte=date_to)

        return qs

# -------------------------------
# Sync Categories API
# -------------------------------
@api_view(['POST'])
def sync_categories_api(request, workspace_id, category_type):
    try:
        workspace = get_object_or_404(Workspace, id=workspace_id, members=request.user)
        
        if category_type == 'expense':
            version = get_object_or_404(ExpenseCategoryVersion, workspace=workspace, is_active=True)
            category_model = ExpenseCategory
        elif category_type == 'income':
            version = get_object_or_404(IncomeCategoryVersion, workspace=workspace, is_active=True)
            category_model = IncomeCategory
        else:
            return Response({'error': 'Invalid category type'}, status=400)
        
        results = sync_categories_tree(request.data, version, category_model)
        return Response(results)
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)