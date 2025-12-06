// --- 1. User & Workspace Types ---

export interface User {
  pk: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
}

export interface UserSettings {
  id: number;
  user: number;
  language: string;
  preferred_currency: string;
  date_format: string;
  options: {
    language: [string, string][];
    preferred_currency: [string, string][];
    date_format: [string, string][];
  };
}

export interface Workspace {
  id: number;
  name: string;
  description: string | null;
  owner: number;
  owner_username: string;
  owner_email: string;
  user_role: 'owner' | 'editor' | 'viewer';
  member_count: number;
  is_owner: boolean;
  user_permissions: any; // You might want to define a more specific type for this
  created_at: string;
  is_active: boolean;
}

export interface WorkspaceMembership {
  id: number;
  workspace: number;
  workspace_name: string;
  user: number;
  user_username: string;
  user_email: string;
  role: 'owner' | 'editor' | 'viewer';
  is_workspace_owner: boolean;
  joined_at: string;
}

export interface WorkspaceSettings {
  id: number;
  workspace: number;
  domestic_currency: string;
  fiscal_year_start: number;
  display_mode: string;
  accounting_mode: boolean;
}

// --- 2. Categories & Tags ---

export interface Category {
  id: number;
  name: string;
  description: string | null;
  level: number;
  is_active: boolean;
  children: Category[];
  version: CategoryVersion;
}

export interface CategoryVersion {
  id: number;
  name: string;
  description: string | null;
  levels_count: number;
  is_active: boolean;
  workspace: number;
  created_by: number;
  created_at: string;
}

export interface Tag {
  id: number;
  name: string;
  workspace: number;
}

// --- 3. Transactions ---

export interface Transaction {
  id: number;
  user: number;
  workspace: number;
  type: 'income' | 'expense';
  expense_category: number | null;
  income_category: number | null;
  original_amount: string;
  original_currency: string;
  amount_domestic: string;
  date: string;
  month: string;
  tag_list: string[];
  note_manual: string;
  note_auto: string;
  created_at: string;
  updated_at: string;
}

export interface TransactionDraft {
  id: number;
  user: number;
  workspace: number;
  draft_type: 'income' | 'expense';
  transactions_data: Partial<Transaction>[];
  transactions_count: number;
  last_modified: string;
  created_at: string;
}

// --- 4. Other ---

export interface ExchangeRate {
  id: number;
  currency: string;
  rate_to_eur: string;
  date: string;
}
