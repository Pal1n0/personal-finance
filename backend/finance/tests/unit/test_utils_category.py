# finance/tests/unit/test_utils_category.py
import pytest
from django.core.exceptions import ValidationError
from finance.models import ExpenseCategory
from finance.utils.category_utils import (
    validate_category_hierarchy, 
    sync_categories_tree,
    CategorySyncError,
    check_category_usage
)


class TestCategorySyncError:
    """Testy pre CategorySyncError exception"""
    
    def test_category_sync_error_creation(self):
        """Test vytvorenia CategorySyncError"""
        error = CategorySyncError(
            message="Test error",
            category_id=123,
            category_name="Test Category"
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
            'create': [
                {
                    'temp_id': 1,
                    'name': 'Test Category 1',
                    'level': 1
                },
                {
                    'temp_id': 2, 
                    'name': 'Test Category 2',
                    'level': 2,
                    'parent_temp_id': 1
                }
            ]
        }
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
    
    def test_validate_invalid_create_missing_name(self, expense_category_version):
        """Test validácie create operácií s chýbajúcim menom"""
        
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': '',  # Prázdne meno
                    'level': 1
                }
            ]
        }
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert 'Category name must be at least 2 characters long' in str(exc_info.value)
    
    def test_validate_invalid_create_missing_temp_id(self, expense_category_version):
        """Test validácie create operácií s chýbajúcim temp_id"""
        
        data = {
            'create': [
                {
                    'name': 'Test Category',
                    'level': 1
                    # Chýba temp_id
                }
            ]
        }
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert 'Missing temp_id' in str(exc_info.value)
    
    def test_validate_invalid_level(self, expense_category_version):
        """Test validácie neplatnej úrovne"""
        from finance.models import ExpenseCategory
        
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': 'Test Category',
                    'level': 6  # Neplatná úroveň
                }
            ]
        }
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert 'Invalid category level' in str(exc_info.value)
    
    def test_validate_update_operations(self, expense_category_version, expense_root_category):
        """Test validácie update operácií"""
        from finance.models import ExpenseCategory
        
        data = {
            'update': [
                {
                    'id': expense_root_category.id,
                    'name': 'Updated Name',
                    'level': 1
                }
            ]
        }
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
    
    def test_validate_delete_operations(self, expense_category_version, expense_root_category):
        """Test validácie delete operácií"""
        
        data = {
            'delete': [expense_root_category.id]
        }
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
    
    def test_validate_invalid_delete_ids(self, expense_category_version):
        """Test validácie neplatných delete ID"""
        from finance.models import ExpenseCategory
        
        data = {
            'delete': ['not_an_integer']  # Neplatné ID
        }
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert 'All delete IDs must be integers' in str(exc_info.value)


class TestSyncCategoriesTree:
    """Testy pre sync_categories_tree funkciu"""
    
    def test_sync_basic_create(self, expense_category_version):
        """Test základnej synchronizácie s create operáciami"""
        
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': 'New Root Category',
                    'level': 1,
                    'description': 'Test description'
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['created']) == 1
        assert len(result['errors']) == 0
        assert result['created'][0]['name'] == 'New Root Category'
        assert result['created'][0]['level'] == 1
        
        # Over že kategória bola skutočne vytvorená
        category = ExpenseCategory.objects.get(id=result['created'][0]['id'])
        assert category.name == 'New Root Category'
        assert category.version == expense_category_version
    
    def test_sync_create_with_parent_child(self, expense_category_version):
        """Test synchronizácie s parent-child vzťahmi"""
        
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': 'Parent Category',
                    'level': 1
                },
                {
                    'temp_id': 2,
                    'name': 'Child Category', 
                    'level': 2,
                    'parent_temp_id': 1
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['created']) == 2
        assert len(result['errors']) == 0
        
        # Nájdeme vytvorené kategórie
        parent_id = next(item['id'] for item in result['created'] if item['temp_id'] == 1)
        child_id = next(item['id'] for item in result['created'] if item['temp_id'] == 2)
        
        parent = ExpenseCategory.objects.get(id=parent_id)
        child = ExpenseCategory.objects.get(id=child_id)
        
        # Over parent-child vzťah
        assert child in parent.children.all()
        assert parent in child.parents.all()
    
    def test_sync_update_operation(self, expense_category_version, expense_root_category):
        """Test synchronizácie s update operáciou"""
        
        original_name = expense_root_category.name
        
        data = {
            'update': [
                {
                    'id': expense_root_category.id,
                    'name': 'Updated Category Name',
                    'level': 1,
                    'description': 'Updated description'
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['updated']) == 1
        assert len(result['errors']) == 0
        assert result['updated'][0] == expense_root_category.id
        
        # Over že kategória bola aktualizovaná
        expense_root_category.refresh_from_db()
        assert expense_root_category.name == 'Updated Category Name'
        assert expense_root_category.description == 'Updated description'
    
    def test_sync_delete_operation(self, expense_category_version, expense_root_category):
        """Test synchronizácie s delete operáciou"""
        
        category_id = expense_root_category.id
        
        data = {
            'delete': [category_id]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['deleted']) == 1
        assert len(result['errors']) == 0
        assert result['deleted'][0] == category_id
        
        # Over že kategória bola skutočne vymazaná
        assert not ExpenseCategory.objects.filter(id=category_id).exists()
    
    def test_sync_complex_operations(self, expense_category_version, expense_root_category):
        """Test komplexnej synchronizácie s viacerými operáciami"""
        
        # Pôvodná kategória na update
        update_id = expense_root_category.id
        
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': 'New Category 1',
                    'level': 1
                },
                {
                    'temp_id': 2,
                    'name': 'New Category 2',
                    'level': 2,
                    'parent_temp_id': 1
                }
            ],
            'update': [
                {
                    'id': update_id,
                    'name': 'Updated Root',
                    'level': 1
                }
            ],
            'delete': []  # Žiadne mazanie
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['created']) == 2
        assert len(result['updated']) == 1
        assert len(result['deleted']) == 0
        assert len(result['errors']) == 0
        
        # Over všetky operácie
        expense_root_category.refresh_from_db()
        assert expense_root_category.name == 'Updated Root'
        
        # Over nové kategórie
        new_categories = ExpenseCategory.objects.filter(
            version=expense_category_version,
            name__in=['New Category 1', 'New Category 2']
        )
        assert new_categories.count() == 2
    
    def test_sync_invalid_category_for_update(self, expense_category_version):
        """Test synchronizácie s neplatnou kategóriou pre update"""
        
        data = {
            'update': [
                {
                    'id': 99999,  # Neexistujúce ID
                    'name': 'Updated Name',
                    'level': 1
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['errors']) > 0
        assert 'not found' in result['errors'][0].lower()
    
    def test_sync_validation_error(self, expense_category_version):
        """Test synchronizácie s validačnou chybou"""
        
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': 'A',  # Príliš krátke meno
                    'level': 1
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['errors']) > 0
        assert '2 characters' in result['errors'][0]


class TestCategoryHierarchyScenarios:
    """Testy pre rôzne scenáre hierarchie kategórií"""
    
    def test_flat_structure_only_level5(self, expense_category_version):
        """Test plochej štruktúry - len level 5 kategórie"""
        
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': 'Flat Category 1',
                    'level': 5
                },
                {
                    'temp_id': 2,
                    'name': 'Flat Category 2',
                    'level': 5
                }
            ]
        }
        
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['created']) == 2
        assert len(result['errors']) == 0
    
    def test_mixed_structure(self, expense_category_version):
        """Test zmiešanej štruktúry - hierarchia aj ploché kategórie"""
        
        data = {
            'create': [
                # Hierarchia
                {
                    'temp_id': 1,
                    'name': 'Root Category',
                    'level': 1
                },
                {
                    'temp_id': 2,
                    'name': 'Child Category',
                    'level': 2,
                    'parent_temp_id': 1
                },
                # Ploché kategórie
                {
                    'temp_id': 3,
                    'name': 'Flat Category',
                    'level': 5
                }
            ]
        }
        
        validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['created']) == 3
        assert len(result['errors']) == 0
    
    def test_circular_reference_detection(self, expense_category_version):
        """Test detekcie cyklických referencií"""
        
        # Vytvoríme kategórie ktoré budú mať cyklickú referenciu
        data = {
            'create': [
                {
                    'temp_id': 1,
                    'name': 'Category A',
                    'level': 1
                },
                {
                    'temp_id': 2,
                    'name': 'Category B',
                    'level': 2,
                    'parent_temp_id': 1
                },
                {
                    'temp_id': 3, 
                    'name': 'Category C',
                    'level': 3,
                    'parent_temp_id': 2
                }
            ]
        }
        
        # Najprv vytvoríme normálnu hierarchiu
        sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        # Potom skúsime vytvoriť cyklickú referenciu
        update_data = {
            'update': [
                {
                    'id': next(cat.id for cat in ExpenseCategory.objects.filter(name='Category A')),
                    'parent_id': next(cat.id for cat in ExpenseCategory.objects.filter(name='Category C')),
                    'name': 'Category A',
                    'level': 1
                }
            ]
        }
        
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(update_data, expense_category_version, ExpenseCategory)
        assert 'circular' in str(exc_info.value).lower()

    def test_sync_cannot_move_used_leaf_category(self, expense_category_version, expense_leaf_category, transaction_with_expense):
        """Test že leaf kategória s transakciami sa nedá presunúť"""
        
        data = {
            'update': [
                {
                    'id': expense_leaf_category.id,
                    'name': expense_leaf_category.name,
                    'level': expense_leaf_category.level,
                    'parent_id': None  # Pokus o presun
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['errors']) > 0
        assert 'used in transactions' in result['errors'][0].lower()

    def test_sync_can_move_unused_leaf_category(self, expense_category_version, expense_leaf_category):
        """Test že leaf kategória bez transakcií sa dá presunúť"""
        
        # Vytvor rodičovskú kategóriu
        parent = ExpenseCategory.objects.create(
            name="Parent Category",
            level=4,
            version=expense_category_version
        )
        
        data = {
            'update': [
                {
                    'id': expense_leaf_category.id,
                    'name': expense_leaf_category.name,
                    'level': expense_leaf_category.level,
                    'parent_id': parent.id
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['errors']) == 0
        assert len(result['updated']) == 1
        
        # Over že vzťah bol vytvorený
        expense_leaf_category.refresh_from_db()
        assert parent in expense_leaf_category.parents.all()

    def test_sync_can_move_non_leaf_category(self, expense_category_version, expense_root_category):
        """Test že non-leaf kategórie sa môžu presúvať"""
        
        # Vytvor nového rodiča
        new_parent = ExpenseCategory.objects.create(
            name="New Parent",
            level=1, 
            version=expense_category_version
        )
        
        data = {
            'update': [
                {
                    'id': expense_root_category.id,
                    'name': expense_root_category.name,
                    'level': expense_root_category.level,
                    'parent_id': new_parent.id
                }
            ]
        }
        
        result = sync_categories_tree(data, expense_category_version, ExpenseCategory)
        
        assert len(result['errors']) == 0
        assert len(result['updated']) == 1

    def test_sync_cannot_move_level1_to_parent(self, expense_category_version, expense_root_category):
        """Test že level 1 kategórie nemôžu mať rodiča"""
        
        # Pokus dať level 1 kategórii rodiča (čo by malo zlyhať v validácii)
        fake_parent_id = 9999
        
        data = {
            'update': [
                {
                    'id': expense_root_category.id,
                    'name': expense_root_category.name,
                    'level': 1,
                    'parent_id': fake_parent_id
                }
            ]
        }
        
        with pytest.raises(ValidationError) as exc_info:
            validate_category_hierarchy(data, expense_category_version, ExpenseCategory)
        assert 'level 1' in str(exc_info.value).lower()

    def test_check_category_usage_function(self, expense_leaf_category, transaction_with_expense):
        """Test helper funkcie pre kontrolu používania"""
        
        # Test s používanou kategóriou
        is_used = check_category_usage(expense_leaf_category.id, ExpenseCategory)
        assert is_used == True
        
        # Test s nepoužívanou kategóriou  
        unused_category = ExpenseCategory.objects.create(
            name="Unused Category",
            level=5,
            version=expense_leaf_category.version
        )
        is_used = check_category_usage(unused_category.id, ExpenseCategory)
        assert is_used == False
