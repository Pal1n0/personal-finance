// src/types/index.ts

// --- 1. Workspace & Auth ---

export interface User {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
}

export interface Workspace {
  id: number;
  name: string;
  currency: string; // 'EUR', 'USD', 'CZK'...
  role: 'owner' | 'admin' | 'editor' | 'viewer';
}

// --- 2. Categories & Tags ---

export interface Tag {
  id: number;
  name: string;
  color?: string; // hex kód pre farbu tagu v UI
}

export interface Category {
  id: number;
  name: string;
  parentId: number | null; // null ak je to hlavná kategória
  type: 'income' | 'expense';
  // Pre stromovú štruktúru v selectoch
  children?: Category[]; 
}

// --- 3. Transactions (Jadro) ---

export interface Transaction {
  id: number;
  date: string; // ISO String '2025-11-27'
  
  // Pozor: Peniaze z Djanga chodia ako string kvôli presnosti!
  // Na frontende ich pre výpočty musíme previesť na number, 
  // ale v type ich držíme ako string, aby sme nerobili chyby pri prenose.
  amount: string; 
  currency: string;
  
  // Ak je mena iná ako mena workspace-u
  amountDomestic?: string; 
  
  type: 'income' | 'expense';
  category: number; // ID kategórie
  tags: number[];   // Pole ID tagov
  
  noteManual?: string;
  noteAuto?: string; // Import info
}

// --- 4. Dashboard Widgety (Pre tvoj skladací dashboard) ---

export type ChartType = 'bar' | 'pie' | 'line' | 'area';
export type AggregationType = 'sum' | 'count' | 'avg';

export interface DashboardWidget {
  id: string; // Unikátne ID widgetu pre react-grid-layout
  title: string;
  type: 'chart' | 'table' | 'stat-card';
  
  // Konfigurácia pre pivot funkciu
  config: {
    chartType?: ChartType;
    groupBy: 'category' | 'tag' | 'month' | 'day';
    operation: AggregationType;
    filterType?: 'income' | 'expense' | 'all';
  };

  // Pozícia na mriežke (x, y, width, height)
  layout: {
    i: string;
    x: number;
    y: number;
    w: number;
    h: number;
  };
}