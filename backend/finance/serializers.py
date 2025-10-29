from rest_framework import serializers
from .models import (
    Transaction, ExchangeRate, UserSettings, WorkspaceSettings,
    ExpenseCategoryVersion, IncomeCategoryVersion, ExpenseCategory, IncomeCategory,
    ExpenseCategoryProperty, IncomeCategoryProperty
)

# -------------------------------
# User Settings
# -------------------------------
class UserSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSettings
        fields = ['id', 'user', 'language']
        read_only_fields = ['id', 'user']

# -------------------------------
# Workspace Settings
# -------------------------------
class WorkspaceSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkspaceSettings
        fields = [
            'id', 'workspace', 'domestic_currency', 'fiscal_year_start', 
            'display_mode', 'accounting_mode'
        ]
        read_only_fields = ['id', 'workspace']

# -------------------------------
# Category Serializers
# -------------------------------
class ExpenseCategoryVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseCategoryVersion
        fields = ['id', 'workspace', 'name', 'description', 'created_by', 'created_at', 'is_active']
        read_only_fields = ['id', 'created_by', 'created_at']

class IncomeCategoryVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = IncomeCategoryVersion
        fields = ['id', 'workspace', 'name', 'description', 'created_by', 'created_at', 'is_active']
        read_only_fields = ['id', 'created_by', 'created_at']

class ExpenseCategorySerializer(serializers.ModelSerializer):
    version = ExpenseCategoryVersionSerializer(read_only=True)
    children = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    
    class Meta:
        model = ExpenseCategory
        fields = [
            'id', 'name', 'description', 'level', 'version', 'children', 'is_active'
        ]

class IncomeCategorySerializer(serializers.ModelSerializer):
    version = IncomeCategoryVersionSerializer(read_only=True)
    children = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    
    class Meta:
        model = IncomeCategory
        fields = [
            'id', 'name', 'description', 'level', 'version', 'children', 'is_active'
        ]

# -------------------------------
# Transaction Serializer
# -------------------------------
class TransactionSerializer(serializers.ModelSerializer):
    expense_category = serializers.PrimaryKeyRelatedField(
        queryset=ExpenseCategory.objects.all(),
        required=False,
        allow_null=True
    )
    income_category = serializers.PrimaryKeyRelatedField(
        queryset=IncomeCategory.objects.all(),
        required=False, 
        allow_null=True
    )
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'user', 'workspace', 'type', 'expense_category', 'income_category',
            'original_amount', 'original_currency', 'amount_domestic', 'date', 
            'month', 'tags', 'note_manual', 'note_auto', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'workspace', 'amount_domestic', 'month', 
            'created_at', 'updated_at'
        ]

# -------------------------------
# Category Property Serializers
# -------------------------------
class ExpenseCategoryPropertySerializer(serializers.ModelSerializer):
    category = ExpenseCategorySerializer(read_only=True)
    
    class Meta:
        model = ExpenseCategoryProperty
        fields = ['id', 'category', 'property_type']

class IncomeCategoryPropertySerializer(serializers.ModelSerializer):
    category = IncomeCategorySerializer(read_only=True)
    
    class Meta:
        model = IncomeCategoryProperty
        fields = ['id', 'category', 'property_type']

# -------------------------------
# Exchange Rate Serializer
# -------------------------------
class ExchangeRateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExchangeRate
        fields = ['id', 'currency', 'rate_to_eur', 'date']
        