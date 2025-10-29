from django.db import transaction
from django.core.exceptions import ValidationError

def validate_category_hierarchy(categories_data):
    """Validácia že leafy sú na spodku a rooty na vrchu"""
    # Toto je ZLOŽITÉ - musel by si analyzovať celú požiadavku aplikovat do funckie nizsie 
    pass

def sync_categories_tree(categories_data, version, category_model):
    """
    Synchronizuje celý strom kategórií z frontendu
    """
    results = {
        'created': [],
        'updated': [], 
        'deleted': [],
        'errors': []
    }
    
    try:
        with transaction.atomic():  # ✅ Všetko alebo nič
            # 1. VYMAŽ KATEGÓRIE
            if categories_data.get('delete'):
                # Skontroluj či kategórie existujú a patria do verzie
                existing_ids = category_model.objects.filter(
                    id__in=categories_data['delete'],
                    version=version
                ).values_list('id', flat=True)
                
                invalid_ids = set(categories_data['delete']) - set(existing_ids)
                if invalid_ids:
                    raise ValidationError(f"Neplatné ID pre zmazanie: {invalid_ids}")
                
                category_model.objects.filter(id__in=existing_ids).delete()
                results['deleted'] = list(existing_ids)
            
            # 2. VYTVOR NOVÉ KATEGÓRIE
            temp_id_map = {}
            if categories_data.get('create'):
                new_categories = []
                for item in categories_data['create']:
                    category = category_model(
                        name=item['name'],
                        level=item['level'],
                        version=version
                    )
                    new_categories.append(category)
                
                category_model.objects.bulk_create(new_categories)
                
                # Mapovanie temp_id → db_id
                for i, item in enumerate(categories_data['create']):
                    temp_id_map[item['temp_id']] = new_categories[i].id
                    results['created'].append({
                        'temp_id': item['temp_id'],
                        'id': new_categories[i].id,
                        'name': new_categories[i].name
                    })
            
            # 3. AKTUALIZUJ EXISTUJÚCE KATEGÓRIE
            if categories_data.get('update'):
                updates = []
                for item in categories_data['update']:
                    category = category_model.objects.get(id=item['id'], version=version)
                    category.name = item['name']
                    category.level = item['level']
                    updates.append(category)
                
                category_model.objects.bulk_update(updates, ['name', 'level'])
                results['updated'] = [item['id'] for item in categories_data['update']]
            
            # 4. NASTAV VZŤAHY PRE NOVÉ KATEGÓRIE
            if categories_data.get('create'):
                for item in categories_data['create']:
                    if item.get('parent_temp_id'):
                        child_id = temp_id_map[item['temp_id']]
                        parent_id = temp_id_map.get(item['parent_temp_id'])
                        
                        if parent_id:
                            child = category_model.objects.get(id=child_id)
                            parent = category_model.objects.get(id=parent_id)
                            parent.children.add(child)
            
            # 5. NASTAV VZŤAHY PRE UPRAVENÉ KATEGÓRIE  
            if categories_data.get('update'):
                for item in categories_data['update']:
                    if 'parent_id' in item:
                        category = category_model.objects.get(id=item['id'], version=version)
                        
                        # Zruš staré vzťahy
                        category.parents.clear()
                        
                        # Pridaj nového parenta
                        if item['parent_id']:
                            parent = category_model.objects.get(id=item['parent_id'], version=version)
                            parent.children.add(category)
            
            return results
            
    except ValidationError as e:
        results['errors'] = [str(e)]
        return results
    except Exception as e:
        results['errors'] = [f"Neočakávaná chyba: {str(e)}"]
        return results