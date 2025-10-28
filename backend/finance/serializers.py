from rest_framework import serializers
from .models import Transaction, Category, CategoryProperty, ExchangeRate, UserSettings, CategoryVersion, CURRENCY_CHOICES, FISCAL_YEAR_START_CHOICES, DISPLAY_MODE_CHOICES

class UserSettingsSerializer(serializers.ModelSerializer):
    domestic_currency = serializers.ChoiceField(choices=CURRENCY_CHOICES)
    fiscal_year_start = serializers.ChoiceField(choices=FISCAL_YEAR_START_CHOICES)
    display_mode = serializers.ChoiceField(choices=DISPLAY_MODE_CHOICES)

    class Meta:
        model = UserSettings
        fields = ['domestic_currency', 'fiscal_year_start', 'display_mode', 'accounting_mode']

class CategoryVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CategoryVersion
        fields = ['id', 'version', 'name', 'description', 'created_at', 'is_active']

class CategorySerializer(serializers.ModelSerializer):
    version = CategoryVersionSerializer(read_only=True)

    class Meta:
        model = Category
        fields = ['id', 'name', 'description', 'level', 'parent', 'version', 'is_active']

class TransactionSerializer(serializers.ModelSerializer):
    category = serializers.PrimaryKeyRelatedField(
    queryset=Category.objects.all(),
    required=False,
    allow_null=True
)

    class Meta:
        model = Transaction
        fields = [
            'id', 'type', 'category', 'original_amount', 'original_currency',
            'amount_domestic', 'date', 'month', 'tags', 'note_manual', 'note_auto'
        ]
        read_only_fields = ['amount_domestic', 'month']

class CategoryPropertySerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)

    class Meta:
        model = CategoryProperty
        fields = ['id', 'category', 'property_type']

class ExchangeRateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExchangeRate
        fields = ['id', 'currency', 'rate_to_eur', 'date']
