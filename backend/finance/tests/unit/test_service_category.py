# finance/tests/unit/test_service_category.py
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.exceptions import ValidationError
from django.db import DatabaseError
from rest_framework.exceptions import PermissionDenied

from finance.models import (ExpenseCategory, ExpenseCategoryVersion,
                            IncomeCategory, IncomeCategoryVersion, Transaction)
from finance.services.category_service import CategoryService


class TestCategoryServiceSyncTree:
    """Testy pre sync_categories_tree metódu"""

    @patch("finance.services.category_service.sync_categories_tree")
    def test_sync_categories_tree_success(
        self, mock_sync, test_workspace, expense_category_version
    ):
        """Test úspešnej synchronizácie stromu kategórií"""
        # Setup
        mock_sync.return_value = {"created": 5, "updated": 2, "deleted": 1}
        categories_data = [
            {"id": 1, "name": "Category 1", "level": 1},
            {"id": 2, "name": "Category 2", "level": 2, "parent_id": 1},
        ]

        service = CategoryService()
        results = service.sync_categories_tree(
            categories_data, expense_category_version, ExpenseCategory
        )

        assert results["created"] == 5
        assert results["updated"] == 2
        assert results["deleted"] == 1
        mock_sync.assert_called_once_with(
            categories_data, expense_category_version, ExpenseCategory
        )

    @patch("finance.services.category_service.sync_categories_tree")
    def test_sync_categories_tree_validation_error(
        self, mock_sync, test_workspace, expense_category_version
    ):
        """Test synchronizácie s validačnou chybou"""
        mock_sync.side_effect = ValidationError("Invalid category data")

        categories_data = [{"invalid": "data"}]
        service = CategoryService()

        with pytest.raises(ValidationError):
            service.sync_categories_tree(
                categories_data, expense_category_version, ExpenseCategory
            )

    @patch("finance.services.category_service.sync_categories_tree")
    def test_sync_categories_tree_database_error(
        self, mock_sync, test_workspace, expense_category_version
    ):
        """Test synchronizácie s databázovou chybou"""
        mock_sync.side_effect = DatabaseError("Database constraint failed")

        categories_data = [{"name": "Test Category", "level": 1}]
        service = CategoryService()

        with pytest.raises(DatabaseError):
            service.sync_categories_tree(
                categories_data, expense_category_version, ExpenseCategory
            )


class TestCategoryServiceValidateUsage:
    """Testy pre validate_category_usage metódu"""

    @patch("finance.services.category_service.check_category_usage")
    def test_validate_category_usage_unused_leaf(
        self, mock_check_usage, expense_leaf_category
    ):
        """Test validácie nepoužitej leaf kategórie"""
        mock_check_usage.return_value = False

        service = CategoryService()
        result = service.validate_category_usage(expense_leaf_category)

        assert result["category_id"] == expense_leaf_category.id
        assert result["category_name"] == expense_leaf_category.name
        assert result["level"] == expense_leaf_category.level
        assert result["is_used"] is False
        assert result["can_be_moved"] is True
        assert result["move_restrictions"]["transaction_count"] == 0

    @patch("finance.services.category_service.check_category_usage")
    def test_validate_category_usage_used_leaf(
        self, mock_check_usage, expense_leaf_category
    ):
        """Test validácie použitej leaf kategórie"""
        mock_check_usage.return_value = True

        with patch.object(
            CategoryService, "_get_category_transaction_count", return_value=5
        ):
            service = CategoryService()
            result = service.validate_category_usage(expense_leaf_category)

        assert result["is_used"] is True
        assert result["can_be_moved"] is False
        assert result["move_restrictions"]["reason"] == "Used in transactions"
        assert result["move_restrictions"]["transaction_count"] == 5

    @patch("finance.services.category_service.check_category_usage")
    def test_validate_category_usage_non_leaf(
        self, mock_check_usage, expense_root_category
    ):
        """Test validácie non-leaf kategórie"""
        mock_check_usage.return_value = False

        service = CategoryService()
        result = service.validate_category_usage(expense_root_category)

        assert result["level"] == 1
        assert result["can_be_moved"] is True
        assert result["move_restrictions"]["requires_confirmation"] is True


class TestCategoryServiceGetCategories:
    """Testy pre get_categories_for_workspace metódu"""

    def test_get_categories_for_workspace_expense(
        self, test_workspace, expense_category_version, expense_root_category
    ):
        """Test získania expense kategórií pre workspace"""
        service = CategoryService()
        categories = service.get_categories_for_workspace(test_workspace, "expense")

        assert categories.count() >= 1
        assert categories.first().version == expense_category_version

    def test_get_categories_for_workspace_income(
        self, test_workspace, income_category_version, income_root_category
    ):
        """Test získania income kategórií pre workspace"""
        service = CategoryService()
        categories = service.get_categories_for_workspace(test_workspace, "income")

        assert categories.count() >= 1
        assert categories.first().version == income_category_version

    def test_get_categories_for_workspace_invalid_type(self, test_workspace):
        """Test získania kategórií s neplatným typom"""
        service = CategoryService()

        with pytest.raises(ValidationError) as exc_info:
            service.get_categories_for_workspace(test_workspace, "invalid_type")

        assert 'Must be "expense" or "income"' in str(exc_info.value)

    def test_get_categories_for_workspace_no_active_version(self, test_workspace):
        """Test získania kategórií bez aktívnej verzie"""
        # Deaktivuj všetky existujúce verzie
        ExpenseCategoryVersion.objects.filter(workspace=test_workspace).update(
            is_active=False
        )
        IncomeCategoryVersion.objects.filter(workspace=test_workspace).update(
            is_active=False
        )

        service = CategoryService()

        # Expense categories - malo by vrátiť prázdny queryset
        expense_categories = service.get_categories_for_workspace(
            test_workspace, "expense"
        )
        assert expense_categories.count() == 0

        # Income categories - malo by vrátiť prázdny queryset
        income_categories = service.get_categories_for_workspace(
            test_workspace, "income"
        )
        assert income_categories.count() == 0


class TestCategoryServiceTreeStructure:
    """Testy pre get_category_tree_structure metódu"""

    def test_get_category_tree_structure_expense(
        self, test_workspace, expense_root_category, expense_child_category
    ):
        """Test vytvorenia expense category tree štruktúry"""
        service = CategoryService()
        tree_structure = service.get_category_tree_structure(test_workspace, "expense")

        assert len(tree_structure) >= 1
        root_category = tree_structure[0]
        assert root_category["id"] == expense_root_category.id
        assert root_category["name"] == expense_root_category.name
        assert root_category["level"] == expense_root_category.level
        assert root_category["is_root"] is True

    def test_get_category_tree_structure_income(
        self, test_workspace, income_root_category, income_child_category
    ):
        """Test vytvorenia income category tree štruktúry"""
        service = CategoryService()
        tree_structure = service.get_category_tree_structure(test_workspace, "income")

        assert len(tree_structure) >= 1
        root_category = tree_structure[0]
        assert root_category["id"] == income_root_category.id
        assert root_category["name"] == income_root_category.name
        assert root_category["level"] == income_root_category.level

    def test_get_category_tree_structure_empty(self, test_workspace):
        """Test vytvorenia tree štruktúry pre prázdny workspace"""
        # Odstráň všetky kategórie
        ExpenseCategory.objects.all().delete()
        IncomeCategory.objects.all().delete()

        service = CategoryService()

        expense_tree = service.get_category_tree_structure(test_workspace, "expense")
        income_tree = service.get_category_tree_structure(test_workspace, "income")

        assert expense_tree == []
        assert income_tree == []

    def test_get_category_tree_structure_hierarchy(
        self, test_workspace, expense_category_hierarchy
    ):
        """Test vytvorenia komplexnej hierarchie"""
        service = CategoryService()
        tree_structure = service.get_category_tree_structure(test_workspace, "expense")

        assert len(tree_structure) == 1
        root = tree_structure[0]
        assert root["name"] == "Level 1 Root"
        assert len(root["children"]) == 1

        level2_child = root["children"][0]
        assert level2_child["name"] == "Level 2 Child"
        assert len(level2_child["children"]) == 1

        level3_leaf = level2_child["children"][0]
        assert level3_leaf["name"] == "Level 3 Leaf"
        assert level3_leaf["children"] == []


class TestCategoryServiceValidateOperations:
    """Testy pre validate_category_operations metódu"""

    @patch("finance.services.category_service.validate_category_hierarchy")
    @patch("finance.services.category_service.check_category_usage")
    def test_validate_operations_success(
        self,
        mock_check_usage,
        mock_validate_hierarchy,
        test_workspace,
        expense_root_category,
    ):
        """Test úspešnej validácie operácií"""
        mock_check_usage.return_value = False

        operations_data = {
            "create": [{"name": "New Category", "level": 1}],
            "update": [{"id": expense_root_category.id, "name": "Updated Category"}],
            "delete": [expense_root_category.id],
        }

        service = CategoryService()
        results = service.validate_category_operations(
            test_workspace, "expense", operations_data
        )

        assert results["is_valid"] is True
        assert results["errors"] == []
        mock_validate_hierarchy.assert_called_once()

    @patch("finance.services.category_service.validate_category_hierarchy")
    @patch("finance.services.category_service.check_category_usage")
    def test_validate_operations_with_warnings(
        self,
        mock_check_usage,
        mock_validate_hierarchy,
        test_workspace,
        expense_leaf_category,
    ):
        """Test validácie s varovaniami"""
        mock_check_usage.return_value = True

        operations_data = {"delete": [expense_leaf_category.id]}

        service = CategoryService()
        results = service.validate_category_operations(
            test_workspace, "expense", operations_data
        )

        assert results["is_valid"] is True
        assert len(results["warnings"]) == 1
        assert "Deleting categories used in transactions" in results["warnings"][0]

    @patch("finance.services.category_service.validate_category_hierarchy")
    def test_validate_operations_validation_error(
        self, mock_validate_hierarchy, test_workspace
    ):
        """Test validácie s chybami validácie"""
        mock_validate_hierarchy.side_effect = ValidationError(
            "Hierarchy validation failed"
        )

        operations_data = {"create": [{"invalid": "data"}]}

        service = CategoryService()
        results = service.validate_category_operations(
            test_workspace, "expense", operations_data
        )

        assert results["is_valid"] is False
        assert len(results["errors"]) == 1
        assert "Hierarchy validation failed" in results["errors"][0]

    def test_validate_operations_no_active_version(self, test_workspace):
        """Test validácie bez aktívnej verzie"""
        # Deaktivuj všetky verzie
        ExpenseCategoryVersion.objects.filter(workspace=test_workspace).update(
            is_active=False
        )

        operations_data = {"create": [{"name": "Test", "level": 1}]}
        service = CategoryService()

        results = service.validate_category_operations(
            test_workspace, "expense", operations_data
        )

        assert results["is_valid"] is False
        assert "No active expense category version" in results["errors"][0]


class TestCategoryServiceEdgeCases:
    """Testy pre edge cases a error handling"""

    @patch("finance.services.category_service.sync_categories_tree")
    def test_sync_categories_tree_logging(
        self, mock_sync, test_workspace, expense_category_version
    ):
        """Test logovania počas synchronizácie"""
        mock_sync.return_value = {"created": 3, "updated": 1, "deleted": 0}

        with patch("finance.services.category_service.logger") as mock_logger:
            service = CategoryService()
            categories_data = [{"name": "Test Category", "level": 1}]

            service.sync_categories_tree(
                categories_data, expense_category_version, ExpenseCategory
            )

            # Skontroluj že sa volal info logger na začiatku a na konci
            assert mock_logger.info.call_count >= 2

    @patch("finance.services.category_service.check_category_usage")
    def test_validate_usage_exception_handling(
        self, mock_check_usage, expense_root_category
    ):
        """Test handlingu výnimiek pri validácii použitia"""
        mock_check_usage.side_effect = Exception("Unexpected error")

        service = CategoryService()

        with pytest.raises(Exception):
            service.validate_category_usage(expense_root_category)

    def test_get_category_transaction_count_expense(
        self, expense_leaf_category, expense_transaction
    ):
        """Test počítania transakcií pre expense kategóriu"""
        service = CategoryService()
        count = service._get_category_transaction_count(expense_leaf_category)

        assert count >= 1

    def test_get_category_transaction_count_income(
        self, income_root_category, income_transaction
    ):
        """Test počítania transakcií pre income kategóriu"""
        service = CategoryService()
        count = service._get_category_transaction_count(income_root_category)

        assert count >= 1

    def test_get_category_transaction_count_no_transactions(
        self, expense_root_category
    ):
        """Test počítania transakcií pre kategóriu bez transakcií"""
        # Odstráň všetky transakcie pre túto kategóriu
        Transaction.objects.filter(expense_category=expense_root_category).delete()

        service = CategoryService()
        count = service._get_category_transaction_count(expense_root_category)

        assert count == 0


class TestCategoryServiceIntegration:
    """Integračné testy pre CategoryService"""

    def test_complete_category_workflow(self, test_workspace, expense_category_version):
        """Test kompletného workflow s kategóriami"""
        service = CategoryService()

        # 1. Získanie kategórií
        categories = service.get_categories_for_workspace(test_workspace, "expense")
        initial_count = categories.count()

        # 2. Validácia operácií
        operations_data = {
            "create": [
                {"name": "New Root Category", "level": 1},
                {"name": "New Child Category", "level": 2, "parent_id": 1},
            ]
        }

        validation_results = service.validate_category_operations(
            test_workspace, "expense", operations_data
        )
        assert validation_results["is_valid"] is True

        # 3. Synchronizácia stromu (mocknutá)
        with patch(
            "finance.services.category_service.sync_categories_tree"
        ) as mock_sync:
            mock_sync.return_value = {"created": 2, "updated": 0, "deleted": 0}

            sync_results = service.sync_categories_tree(
                operations_data["create"], expense_category_version, ExpenseCategory
            )

            assert sync_results["created"] == 2

        # 4. Vytvorenie tree štruktúry
        tree_structure = service.get_category_tree_structure(test_workspace, "expense")
        assert len(tree_structure) >= 1

    def test_category_usage_workflow(
        self, test_workspace, expense_leaf_category, expense_transaction
    ):
        """Test workflowu validácie použitia kategórie"""
        service = CategoryService()

        # Overenie použitia kategórie
        with patch(
            "finance.services.category_service.check_category_usage"
        ) as mock_check_usage:
            mock_check_usage.return_value = True

            usage_info = service.validate_category_usage(expense_leaf_category)

            assert usage_info["is_used"] is True
            assert usage_info["can_be_moved"] is False
            assert usage_info["move_restrictions"]["transaction_count"] > 0

        # Validácia operácií s použitou kategóriou
        operations_data = {"delete": [expense_leaf_category.id]}

        validation_results = service.validate_category_operations(
            test_workspace, "expense", operations_data
        )

        assert validation_results["is_valid"] is True
        assert len(validation_results["warnings"]) == 1
        assert (
            "Deleting categories used in transactions"
            in validation_results["warnings"][0]
        )


class TestCategoryServiceErrorScenarios:
    """Testy pre chybové scenáre"""

    def test_sync_categories_tree_with_invalid_data(
        self, test_workspace, expense_category_version
    ):
        """Test synchronizácie s neplatnými dátami"""
        service = CategoryService()

        invalid_categories_data = [
            {"name": "", "level": 1},  # Prázdny názov
            {"name": "A" * 256, "level": 1},  # Príliš dlhý názov
        ]

        with patch(
            "finance.services.category_service.sync_categories_tree"
        ) as mock_sync:
            mock_sync.side_effect = ValidationError("Invalid category data")

            with pytest.raises(ValidationError):
                service.sync_categories_tree(
                    invalid_categories_data, expense_category_version, ExpenseCategory
                )

    def test_get_categories_database_error(self, test_workspace):
        """Test získania kategórií s databázovou chybou"""
        service = CategoryService()

        with patch.object(ExpenseCategoryVersion.objects, "filter") as mock_filter:
            mock_filter.side_effect = DatabaseError("Connection failed")

            with pytest.raises(DatabaseError):
                service.get_categories_for_workspace(test_workspace, "expense")

    def test_validate_operations_invalid_category_type(self, test_workspace):
        """Test validácie operácií s neplatným typom kategórie"""
        service = CategoryService()

        with pytest.raises(ValidationError):
            service.validate_category_operations(test_workspace, "invalid_type", {})

    @patch("finance.services.category_service.validate_category_hierarchy")
    def test_validate_operations_missing_category(
        self, mock_validate_hierarchy, test_workspace, expense_root_category
    ):
        """Test validácie operácií s chýbajúcou kategóriou"""
        operations_data = {
            "update": [
                {"id": 99999, "name": "Non-existent Category"}
            ],  # Neexistujúce ID
            "delete": [88888],  # Neexistujúce ID
        }

        service = CategoryService()
        results = service.validate_category_operations(
            test_workspace, "expense", operations_data
        )

        # Validácia by mala prejsť, kým sú dátové štruktúry platné
        # Skutočná validácia existencie kategórií sa deje v sync_categories_tree
        assert results["is_valid"] is True


class TestCategoryServicePerformance:
    """Testy výkonu pre CategoryService"""

    def test_get_categories_for_workspace_performance(
        self, test_workspace, expense_category_version
    ):
        """Test výkonu získavania kategórií"""
        import time

        service = CategoryService()

        start_time = time.time()
        categories = service.get_categories_for_workspace(test_workspace, "expense")
        end_time = time.time()

        # Získanie kategórií by malo byť rýchle (< 100ms)
        execution_time = end_time - start_time
        assert execution_time < 0.1  # 100ms
        assert categories.count() >= 0

    def test_get_category_tree_structure_performance(
        self, test_workspace, expense_category_hierarchy
    ):
        """Test výkonu vytvárania tree štruktúry"""
        import time

        service = CategoryService()

        start_time = time.time()
        tree_structure = service.get_category_tree_structure(test_workspace, "expense")
        end_time = time.time()

        # Vytvorenie tree štruktúry by malo byť rýchle
        execution_time = end_time - start_time
        assert execution_time < 0.2  # 200ms
        assert len(tree_structure) == 1
