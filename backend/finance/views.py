from rest_framework import viewsets,mixins
from django.db import transaction
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
from datetime import date
from .models import Transaction, Category, CategoryProperty, ExchangeRate, UserSettings, CategoryVersion
from .serializers import (
    TransactionSerializer, CategorySerializer,
    CategoryPropertySerializer, ExchangeRateSerializer, UserSettingsSerializer
)
from .utils.currency_utils import recalculate_transactions_domestic_amount



# -------------------------------
# User settings
# -------------------------------
class UserSettingsViewSet(mixins.RetrieveModelMixin,
                          mixins.UpdateModelMixin,
                          viewsets.GenericViewSet):
    serializer_class = UserSettingsSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return UserSettings.objects.filter(user=self.request.user)

    # Optional: obmedziť update len na 4 polia
    def partial_update(self, request, *args, **kwargs):
        # tu sa dá ešte skontrolovať, že sa updatujú len povolené polia
        allowed_fields = {'domestic_currency', 'fiscal_year_start', 'display_mode', 'accounting_mode'}
        for key in request.data.keys():
            if key not in allowed_fields:
                return Response({"error": f"{key} cannot be updated"}, status=400)
        return super().partial_update(request, *args, **kwargs)

# -------------------------------
# Category
# -------------------------------
class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # len aktívne verzie používateľa
        active_versions = CategoryVersion.objects.filter(user=self.request.user, is_active=True)
        return Category.objects.filter(version__in=active_versions)

# -------------------------------
# Transaction
# -------------------------------
class TransactionViewSet(viewsets.ModelViewSet):
    """
    Full CRUD for Transaction:
    - GET: filter by type, fiscal_year, month
    - POST: create transaction
    - PUT/PATCH: update transaction
    - DELETE: delete transaction
    """
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = Transaction.objects.filter(user=self.request.user)
        tx_type = self.request.query_params.get('type')
        fiscal_year = self.request.query_params.get('fiscal_year')
        month = self.request.query_params.get('month')

        # Filter podľa typu
        if tx_type in ['income', 'expense']:
            qs = qs.filter(type=tx_type)

        # Filter podľa fiskálneho roka
        settings = UserSettings.objects.get(user=self.request.user)
        fiscal_start_month = settings.fiscal_year_start

        if fiscal_year:
            fiscal_year = int(fiscal_year)
            start_date = date(fiscal_year - 1, fiscal_start_month, 1) if fiscal_start_month > 1 else date(fiscal_year, 1, 1)
            end_date = date(fiscal_year, fiscal_start_month, 1) if fiscal_start_month > 1 else date(fiscal_year, 12, 31)
            qs = qs.filter(date__gte=start_date, date__lt=end_date)

        # Filter podľa mesiaca (voliteľné)
        if month:
            month = int(month)
            qs = qs.filter(date__month=month)

        return qs
    
    def perform_create(self, serializer):
        # Nastavíme používateľa a month z date
        instance = serializer.save(user=self.request.user)
        if instance.date:
            instance.month = instance.date.replace(day=1)
            instance.save(update_fields=['month'])

    def perform_update(self, serializer):
        instance = serializer.save()
        if instance.date:
            instance.month = instance.date.replace(day=1)
            instance.save(update_fields=['month'])

    def perform_destroy(self, instance):
        # Prípadné logovanie pred vymazaním
        instance.delete()


    # -------------------------------
    # Bulk operations
    # -------------------------------
    @action(detail=False, methods=['post'])
    def bulk_create(self, request):
        serializer = self.get_serializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)

        objs = []
        for item in serializer.validated_data:
            tx = Transaction(
                user=request.user,
                **item
            )
            if tx.date:
                tx.month = tx.date.replace(day=1)
            objs.append(tx)

        # 1x INSERT pre všetky transakcie
        with transaction.atomic():
            Transaction.objects.bulk_create(objs, ignore_conflicts=True)

        # vytvoríme serializer pre odpoveď
        out_serializer = self.get_serializer(objs, many=True)
        return Response(out_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'])
    def bulk_create(self, request):
        serializer = self.get_serializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)

        objs = []
        for item in serializer.validated_data:
            # Teraz item['category'] obsahuje Category objekt (nie ID!)
            # Pretože PrimaryKeyRelatedField automaticky načíta objekt z DB
            tx = Transaction(
                user=request.user,
                **item
            )
            if tx.date:
                tx.month = tx.date.replace(day=1)
            objs.append(tx)

        objs = recalculate_transactions_domestic_amount(objs, request.user)

        with transaction.atomic():
            Transaction.objects.bulk_create(objs)

        out_serializer = self.get_serializer(objs, many=True)
        return Response(out_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'])
    def bulk_update(self, request):
        data = request.data
        ids = [item.get("id") for item in data if item.get("id")]
        
        if not ids:
            return Response({"detail": "No IDs provided."}, status=400)
        
        # Načítame existujúce transakcie
        existing = {tx.id: tx for tx in Transaction.objects.filter(user=request.user, id__in=ids)}
        
        to_update = []
        needs_recalculation = []
        
        for item in data:
            obj_id = item.get("id")
            tx = existing.get(obj_id)
            if not tx:
                continue

            # Uložíme pôvodné hodnoty pre kontrolu zmien
            original_amount_old = tx.original_amount
            original_currency_old = tx.original_currency
            date_old = tx.date
            
            # Aktualizujeme polia
            for field, value in item.items():
                if field != "id" and hasattr(tx, field) and field != "category":
                    setattr(tx, field, value)
            
            # Špeciálne spracovanie pre category (ak používaš PrimaryKeyRelatedField)
            if 'category' in item:
                tx.category_id = item['category']
            
            # Nastavíme month
            if tx.date:
                tx.month = tx.date.replace(day=1)
            
            # Kontrola či treba prepočítavať
            if (original_amount_old != tx.original_amount or
                original_currency_old != tx.original_currency or
                date_old != tx.date):
                needs_recalculation.append(tx)
            
            to_update.append(tx)

        if not to_update:
            return Response({"detail": "No valid transactions to update."}, status=400)

        # Prepočítame domáce sumy
        if needs_recalculation:
            recalculate_transactions_domestic_amount(needs_recalculation, request.user)

        # Bulk update
        with transaction.atomic():
            Transaction.objects.bulk_update(
                to_update,
                fields=[
                    "type", "category", "original_amount", "original_currency",
                    "amount_domestic", "date", "month", "tags", 
                    "note_manual", "note_auto", "updated_at",
                ]
            )

        out_serializer = self.get_serializer(to_update, many=True)
        return Response(out_serializer.data, status=200)

    @action(detail=False, methods=['post'])
    def bulk_delete(self, request):
        ids = request.data.get("ids", [])
        qs = Transaction.objects.filter(user=request.user, id__in=ids)
        deleted_count = qs.count()
        qs.delete()
        return Response({"deleted": deleted_count}, status=204)

# -------------------------------
# CategoryProperty
# -------------------------------
class CategoryPropertyViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CategoryPropertySerializer
    permission_classes = [IsAuthenticated]
    queryset = CategoryProperty.objects.all()

# -------------------------------
# ExchangeRate
# -------------------------------

class ExchangeRateViewSet(viewsets.GenericViewSet,
                          mixins.ListModelMixin,
                          mixins.RetrieveModelMixin):
    """
    GET:
    - filter by one or multiple currencies (comma-separated, e.g., USD,EUR)
    - filter by date range: date_from / date_to
    """
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