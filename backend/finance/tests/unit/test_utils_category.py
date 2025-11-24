# finance/tests/unit/test_utils_category.py
from datetime import date
from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError

from finance.models import ExpenseCategory
from finance.utils.category_utils import (
    CategorySyncError,
    check_category_usage,
    sync_categories_tree,
    validate_category_hierarchy,
)


class TestCategorySyncError:
    """Testy pre CategorySyncError exception"""

    def test_category_sync_error_creation(self):
        """Test vytvorenia CategorySyncError"""
        error = CategorySyncError(
            message="Test error", category_id=123, category_name="Test Category"
        )
        assert error.message == "Test error"
        assert error.category_id == 123
        assert error.category_name == "Test Category"
        assert str(error) == "Test error"


class TestValidateCategoryHierarchy:
    """Testy pre validate_category_hierarchy funkciu"""

    def test_validate_empty_data(self, expense_category_version):
        """Test validácie prázdnych dát"""

        data = {}
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)

    def test_validate_basic_create_operations(self, expense_category_version):
        """Test validácie základných create operácií"""
        from finance.models import ExpenseCategory

        data = {
            "create": [
                {"temp_id": 1, "name": "Test Category 1", "level": 1},
                {
                    "temp_id": 2,
                    "name": "Test Category 2",
                    "level": 2,
                    "parent_temp_id": 1,
                },
            ]
        }
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)

    def test_validate_invalid_create_missing_name(self, expense_category_version):
        """Test validácie create operácií s chýbajúcim menom"""

        data = {"create": [{"temp_id": 1, "name": "", "level": 1}]}  # Prázdne meno
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert "Category name must be at least 2 characters long" in str(exc_info.value)

    def test_validate_invalid_create_missing_temp_id(self, expense_category_version):
        """Test validácie create operácií s chýbajúcim temp_id"""

        data = {
            "create": [
                {
                    "name": "Test Category",
                    "level": 1,
                    # Chýba temp_id
                }
            ]
        }
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert "Missing temp_id" in str(exc_info.value)

    def test_validate_invalid_level(self, expense_category_version):
        """Test validácie neplatnej úrovne"""
        from finance.models import ExpenseCategory

        data = {
            "create": [
                {"temp_id": 1, "name": "Test Category", "level": 6}  # Neplatná úroveň
            ]
        }
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert "Invalid category level" in str(exc_info.value)

    def test_validate_update_operations(
        self, expense_category_version, expense_root_category
    ):
        """Test validácie update operácií"""
        from finance.models import ExpenseCategory

        data = {
            "update": [
                {"id": expense_root_category.id, "name": "Updated Name", "level": 1}
            ]
        }
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)

    def test_validate_delete_operations(
        self, expense_category_version, expense_root_category
    ):
        """Test validácie delete operácií"""

        data = {"delete": [expense_root_category.id]}
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)

    def test_validate_invalid_delete_ids(self, expense_category_version):
        """Test validácie neplatných delete ID"""
        from finance.models import ExpenseCategory

        data = {"delete": ["not_an_integer"]}  # Neplatné ID
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert "All delete IDs must be integers" in str(exc_info.value)


class TestSyncCategoriesTree:
    """Testy pre sync_categories_tree funkciu"""

    def test_sync_basic_create(self, expense_category_version):
        """Test základnej synchronizácie s create operáciami"""

        data = {
            "create": [
                {
                    "temp_id": 1,
                    "name": "New Root Category",
                    "level": 1,
                    "description": "Test description",
                }
            ]
        }

        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["created"]) == 1
        assert len(result["errors"]) == 0
        assert result["created"][0]["name"] == "New Root Category"
        assert result["created"][0]["level"] == 1

        # Over že kategória bola skutočne vytvorená
        category = ExpenseCategory.objects.get(id=result["created"][0]["id"])
        assert category.name == "New Root Category"
        assert category.version == expense_category_version

    def test_sync_create_with_parent_child(self, expense_category_version):
        """Test synchronizácie s parent-child vzťahmi"""

        data = {
            "create": [
                {"temp_id": 1, "name": "Parent Category", "level": 1},
                {
                    "temp_id": 2,
                    "name": "Child Category",
                    "level": 2,
                    "parent_temp_id": 1,
                },
            ]
        }

        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["created"]) == 2
        assert len(result["errors"]) == 0

        # Nájdeme vytvorené kategórie
        parent_id = next(
            item["id"] for item in result["created"] if item["temp_id"] == 1
        )
        child_id = next(
            item["id"] for item in result["created"] if item["temp_id"] == 2
        )

        parent = ExpenseCategory.objects.get(id=parent_id)
        child = ExpenseCategory.objects.get(id=child_id)

        # Over parent-child vzťah
        assert child in parent.children.all()
        assert parent in child.parents.all()

    def test_sync_update_operation(
        self, expense_category_version, expense_root_category, expense_child_category
    ):
        """Test synchronizácie s update operáciou"""
        # expense_root_category už má expense_child_category ako dieťa

        original_name = expense_root_category.name

        data = {
            "update": [
                {
                    "id": expense_root_category.id,
                    "name": "Updated Category Name",
                    "level": 1,
                    "description": "Updated description",
                }
            ]
        }

        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["updated"]) == 1
        assert len(result["errors"]) == 0
        assert result["updated"][0] == expense_root_category.id

        # Over že kategória bola aktualizovaná
        expense_root_category.refresh_from_db()
        assert expense_root_category.name == "Updated Category Name"
        assert expense_root_category.description == "Updated description"

    def test_sync_delete_operation(
        self, expense_category_version, expense_root_category
    ):
        """Test synchronizácie s delete operáciou"""

        category_id = expense_root_category.id

        data = {"delete": [category_id]}

        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["deleted"]) == 1
        assert len(result["errors"]) == 0
        assert result["deleted"][0] == category_id

        # Over že kategória bola skutočne vymazaná
        assert not ExpenseCategory.objects.filter(id=category_id).exists()

    def test_sync_complex_operations(
        self, expense_category_version, expense_root_category, expense_child_category
    ):
        """Test komplexnej synchronizácie s viacerými operáciami"""
        # expense_root_category už má expense_child_category ako dieťa

        # Pôvodná kategória na update
        update_id = expense_root_category.id

        data = {
            "create": [
                {"temp_id": 1, "name": "New Category 1", "level": 1},
                {
                    "temp_id": 2,
                    "name": "New Category 2",
                    "level": 2,
                    "parent_temp_id": 1,
                },
            ],
            "update": [{"id": update_id, "name": "Updated Root", "level": 1}],
            "delete": [],  # Žiadne mazanie
        }

        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["created"]) == 2
        assert len(result["updated"]) == 1
        assert len(result["deleted"]) == 0
        assert len(result["errors"]) == 0

        # Over všetky operácie
        expense_root_category.refresh_from_db()
        assert expense_root_category.name == "Updated Root"

        # Over nové kategórie
        new_categories = ExpenseCategory.objects.filter(
            version=expense_category_version,
            name__in=["New Category 1", "New Category 2"],
        )
        assert new_categories.count() == 2

    def test_sync_invalid_category_for_update(
        self, expense_category_version, workspace_settings
    ):
        """Test synchronizácie s neplatnou kategóriou pre update"""

        data = {
            "update": [
                {"id": 99999, "name": "Updated Name", "level": 1}  # Neexistujúce ID
            ]
        }

        with pytest.raises(CategorySyncError) as exc_info:
            sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert "Category not found for update" in str(exc_info.value)

    def test_sync_validation_error(self, expense_category_version, workspace_settings):
        """Test synchronizácie s validačnou chybou"""

        data = {
            "create": [{"temp_id": 1, "name": "A", "level": 1}]  # Príliš krátke meno
        }

        with pytest.raises(ValidationError) as exc_info:
            sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert "Category name must be at least 2 characters long" in str(exc_info.value)


class TestCategoryHierarchyScenarios:
    """Testy pre rôzne scenáre hierarchie kategórií"""

    def test_flat_structure_only_level5(self, expense_category_version):
        """Test plochej štruktúry - len level 5 kategórie"""

        data = {
            "create": [
                {"temp_id": 1, "name": "Flat Category 1", "level": 5},
                {"temp_id": 2, "name": "Flat Category 2", "level": 5},
            ]
        }

        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["created"]) == 2
        assert len(result["errors"]) == 0

    def test_mixed_structure(self, expense_category_version):
        """Test zmiešanej štruktúry - hierarchia aj ploché kategórie"""

        data = {
            "create": [
                # Hierarchia
                {"temp_id": 1, "name": "Root Category", "level": 1},
                {
                    "temp_id": 2,
                    "name": "Child Category",
                    "level": 2,
                    "parent_temp_id": 1,
                },
                # Ploché kategórie
                {"temp_id": 3, "name": "Flat Category", "level": 5},
            ]
        }

        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["created"]) == 3
        assert len(result["errors"]) == 0

    def test_circular_reference_detection(self, expense_category_version):
        """Test detekcie cyklických referencií"""

        # Vytvoríme kategórie ktoré budú mať cyklickú referenciu
        data = {
            "create": [
                {"temp_id": 1, "name": "Category A", "level": 1},
                {"temp_id": 2, "name": "Category B", "level": 2, "parent_temp_id": 1},
                {"temp_id": 3, "name": "Category C", "level": 3, "parent_temp_id": 2},
            ]
        }

        # Najprv vytvoríme normálnu hierarchiu
        sync_categories_tree(data, expense_category_version, ExpenseCategory)

        # Potom skúsime vytvoriť cyklickú referenciu
        update_data = {
            "update": [
                {
                    "id": next(
                        cat.id
                        for cat in ExpenseCategory.objects.filter(name="Category A")
                    ),
                    "parent_id": next(
                        cat.id
                        for cat in ExpenseCategory.objects.filter(name="Category C")
                    ),
                    "name": "Category A",
                    "level": 1,
                }
            ]
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(
                update_data, expense_category_version, ExpenseCategory
            )
        assert "circular" in str(exc_info.value).lower()

    def test_sync_cannot_move_used_leaf_category(
        self,
        expense_category_version,
        expense_leaf_category,
        transaction_with_expense,
        workspace_settings,
    ):
        """Test že leaf kategória s transakciami sa nedá presunúť"""

        data = {
            "update": [
                {
                    "id": expense_leaf_category.id,
                    "name": expense_leaf_category.name,
                    "level": expense_leaf_category.level,
                    "parent_id": None,  # Pokus o presun
                }
            ]
        }

        with pytest.raises(ValidationError) as exc_info:
            sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert "used in transactions" in str(exc_info.value).lower()

    def test_sync_can_move_unused_leaf_category(
        self, expense_category_version, expense_leaf_category
    ):
        """Test že leaf kategória bez transakcií sa dá presunúť"""

        # Vytvor rodičovskú kategóriu
        parent = ExpenseCategory.objects.create(
            name="Parent Category", level=4, version=expense_category_version
        )

        data = {
            "update": [
                {
                    "id": expense_leaf_category.id,
                    "name": expense_leaf_category.name,
                    "level": expense_leaf_category.level,
                    "parent_id": parent.id,
                }
            ]
        }

        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["errors"]) == 0
        assert len(result["updated"]) == 1

        # Over že vzťah bol vytvorený
        expense_leaf_category.refresh_from_db()
        assert parent in expense_leaf_category.parents.all()

    def test_sync_can_move_non_leaf_category(
        self, expense_category_version, expense_child_category
    ):
        """Test že non-leaf kategórie (nie level 1) sa môžu presúvať"""

        # Vytvor dieťa pre child category (level 3)
        grandchild = ExpenseCategory.objects.create(
            name="Jablká", level=3, version=expense_category_version
        )
        expense_child_category.children.add(grandchild)

        # Vytvor nového rodiča (level 1 pre level 2 child)
        new_parent = ExpenseCategory.objects.create(
            name="New Parent",
            level=1,  # Level 1 pre level 2 child
            version=expense_category_version,
        )

        data = {
            "update": [
                {
                    "id": expense_child_category.id,
                    "name": expense_child_category.name,
                    "level": expense_child_category.level,
                    "parent_id": new_parent.id,
                }
            ]
        }

        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)

        assert len(result["errors"]) == 0

    def test_sync_cannot_move_level1_to_parent(
        self, expense_category_version, expense_root_category, expense_child_category
    ):
        """Test že level 1 kategórie nemôžu mať rodiča"""

        # Použime existujúcu child kategóriu ako rodiča
        data = {
            "update": [
                {
                    "id": expense_root_category.id,
                    "name": expense_root_category.name,
                    "level": 1,
                    "parent_id": expense_child_category.id,  # Level 2 kategória ako rodič
                }
            ]
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)

        # Overíme že dostaneme správnu chybu
        error_msg = str(exc_info.value)
        assert (
            "level 1" in error_msg.lower() or "cannot have parent" in error_msg.lower()
        )

    def test_check_category_usage_function(
        self, expense_leaf_category, transaction_with_expense
    ):
        """Test helper funkcie pre kontrolu používania"""

        # Test s používanou kategóriou
        is_used = check_category_usage(expense_leaf_category.id, ExpenseCategory)
        assert is_used

        # Test s nepoužívanou kategóriou
        unused_category = ExpenseCategory.objects.create(
            name="Unused Category", level=5, version=expense_leaf_category.version
        )
        is_used = check_category_usage(unused_category.id, ExpenseCategory)
        assert not is_used

    @pytest.mark.django_db
    def test_sync_cannot_move_non_leaf_with_used_l5_descendant(
        self, test_user, test_workspace, expense_category_version, workspace_settings
    ):
        """
        Test že non-leaf kategória sa nedá presunúť, ak má používanú L5 podkategóriu.
        Pokrýva riadky 405-442 v sync_categories_tree.
        """
        from finance.models import Transaction

        # 1. Vytvoríme hierarchiu: L1 -> L2 -> L3 -> L4 -> L5 (Leaf)
        l1_root = ExpenseCategory.objects.create(
            version=expense_category_version, name="Root L1", level=1
        )
        l2_child = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child L2", level=2
        )
        l3_grandchild = ExpenseCategory.objects.create(
            version=expense_category_version, name="Grandchild L3", level=3
        )
        l4_great_grandchild = ExpenseCategory.objects.create(
            version=expense_category_version, name="GreatGrandchild L4", level=4
        )
        l5_leaf = ExpenseCategory.objects.create(
            version=expense_category_version, name="Leaf L5 (Used)", level=5
        )

        l1_root.children.add(l2_child)
        l2_child.children.add(l3_grandchild)
        l3_grandchild.children.add(l4_great_grandchild)
        l4_great_grandchild.children.add(l5_leaf)

        # 2. Vytvoríme transakciu používajúcu L5 kategóriu
        Transaction.objects.create(
            user=test_user,
            workspace=test_workspace,
            type="expense",
            expense_category=l5_leaf,
            original_amount=Decimal("100.00"),
            original_currency="EUR",
            date=date(2025, 1, 1),
            month=date(2025, 1, 1),
        )

        # 3. Pokúsime sa presunúť L1 kategóriu (s jej podstromom) pod nového rodiča
        new_root = ExpenseCategory.objects.create(
            version=expense_category_version, name="New Root", level=1
        )  # Nový rodič, pod ktorého chceme presunúť L1_root

        update_data = {
            "update": [
                {
                    "id": l2_child.id,  # Changing to l2_child
                    "name": l2_child.name,
                    "level": 2,  # level of l2_child
                    "parent_id": new_root.id,  # Skúška presunu
                }
            ]
        }

        with pytest.raises(ValidationError) as exc_info:
            sync_categories_tree(update_data, expense_category_version, ExpenseCategory)

        assert (
            "Cannot move category 'Child L2' because subcategory 'Leaf L5 (Used)' is used in transactions."
            in str(exc_info.value)
        )

    @pytest.mark.xfail(
        reason="Hierarchy validation for childless non-leaf categories after delete is not yet implemented."
    )
    @pytest.mark.django_db
    def test_sync_non_leaf_category_becomes_childless_after_delete(
        self, expense_category_version, test_user, test_workspace, workspace_settings
    ):
        """
        Test že non-leaf kategória nemôže ostať bez detí po operácii delete.
        Pokrýva riadky 665-680 v sync_categories_tree (final validation).
        """
        from finance.models import ExpenseCategory

        # 1. Vytvoríme hierarchiu: Grandparent L3 -> Parent L4 -> Child L5
        grandparent_l3 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Grandparent L3", level=3
        )
        parent_l4 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Parent L4", level=4
        )
        child_l5 = ExpenseCategory.objects.create(
            version=expense_category_version, name="Child L5", level=5
        )
        grandparent_l3.children.add(parent_l4)
        parent_l4.children.add(child_l5)

        # 2. Pokúsime sa zmazať Child L5, čím Parent L4 zostane bez detí
        delete_data = {"delete": [child_l5.id]}

        with pytest.raises(ValidationError) as exc_info:
            sync_categories_tree(delete_data, expense_category_version, ExpenseCategory)

        # Očakávame chybu, že Parent L4 (non-leaf) musí mať aspoň jedno dieťa
        # Check if the specific error message is contained within the raised ValidationError's messages
        error_messages = str(exc_info.value)
        assert (
            "Category 'Parent L4' (level 4) must have at least one child"
            in error_messages
        )
