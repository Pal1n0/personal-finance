import os

# --- KONFIGURÁCIA ---
PROJECT_ROOT = '.'

# Zložky, ktoré ignorujeme
IGNORE_DIRS = {
    'venv', 'env', '.git', '__pycache__', 'node_modules', 
    'migrations', 'dist', 'build', '.idea', '.vscode', 
    'coverage', 'htmlcov', '__pycache__'
}

# Názvy tvojich hlavných zložiek (ak sa volajú inak, prepíš to tu)
BACKEND_NAMES = {'Backend', 'backend'}
FRONTEND_NAMES = {'Frontend', 'frontend'}

# Prípony súborov, ktoré chceme rátať
EXTENSIONS = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.jsx': 'React (JSX)',
    '.ts': 'TypeScript',
    '.tsx': 'React (TSX)',
    '.html': 'HTML',
    '.css': 'CSS',
    '.scss': 'SASS/SCSS',
    '.json': 'JSON',
    '.md': 'Markdown',
    '.yml': 'YAML',
    '.yaml': 'YAML'
}

def count_lines_detailed():
    # Inicializácia počítadiel
    stats = {
        'Backend': 0,
        'Frontend': 0,
        'Root/Other': 0,
        'Total': 0
    }
    
    file_counts = {
        'Backend': 0,
        'Frontend': 0,
        'Root/Other': 0
    }

    print(f"🔍 Analyzujem projekt v: {os.path.abspath(PROJECT_ROOT)}...\n")

    for root, dirs, files in os.walk(PROJECT_ROOT):
        # 1. Odfiltrovanie ignorovaných zložiek (in-place úprava zoznamu dirs)
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            
            if ext in EXTENSIONS:
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines_count = len(f.readlines())
                        
                        # 2. Zistenie, do ktorej kategórie súbor patrí
                        # Získame relatívnu cestu (napr. "Backend/finance/models.py")
                        rel_path = os.path.relpath(root, PROJECT_ROOT)
                        # Vezmeme prvú časť cesty (napr. "Backend")
                        top_folder = rel_path.split(os.sep)[0]

                        category = 'Root/Other'
                        if top_folder in BACKEND_NAMES:
                            category = 'Backend'
                        elif top_folder in FRONTEND_NAMES:
                            category = 'Frontend'
                        
                        # 3. Pripočítanie
                        stats[category] += lines_count
                        stats['Total'] += lines_count
                        file_counts[category] += 1
                        
                except Exception as e:
                    # Tiché ignorovanie chýb pri čítaní (napr. locknuté súbory)
                    pass

    # --- VÝPIS VÝSLEDKOV ---
    print(f"{'KATEGÓRIA':<15} | {'SÚBORY':<10} | {'RIADKY KÓDU':<15}")
    print("-" * 45)
    
    print(f"{'Backend':<15} | {file_counts['Backend']:<10} | {stats['Backend']:<15}")
    print(f"{'Frontend':<15} | {file_counts['Frontend']:<10} | {stats['Frontend']:<15}")
    print(f"{'Root/Config':<15} | {file_counts['Root/Other']:<10} | {stats['Root/Other']:<15}")
    
    print("-" * 45)
    print(f"{'SPOLU':<15} | {sum(file_counts.values()):<10} | {stats['Total']:<15}")
    print("=" * 45)

if __name__ == "__main__":
    count_lines_detailed()