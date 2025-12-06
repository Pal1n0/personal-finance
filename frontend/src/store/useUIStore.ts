// src/store/useUIStore.ts
import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

interface UIState {
  // States from the original useUIStore
  isSidebarOpen: boolean;
  isDarkMode: boolean;

  // States from the old uiStore
  dateFormat: string | null;
  language: string | null;
  pageTitle: string | null;
  
  // New error state
  error: string | null;

  // Actions from both
  toggleSidebar: () => void;
  toggleDarkMode: () => void;
  setUi: (settings: { dateFormat?: string; language?: string }) => void;
  setPageTitle: (title: string) => void;
  setError: (error: string | null) => void;
  reset: () => void;
}

const initialState = {
  isSidebarOpen: true,
  isDarkMode: false,
  dateFormat: null,
  language: localStorage.getItem('i18nextLng') || null, // Initialize language from localStorage
  pageTitle: null,
  error: null,
};

const useUIStore = create<UIState>()(devtools((set) => ({
  ...initialState,

  // Actions from original useUIStore
  toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),
  toggleDarkMode: () => set((state) => ({ isDarkMode: !state.isDarkMode })),
  setPageTitle: (title) => set({ pageTitle: title }),

  // Actions from old uiStore and new error handling
  setUi: (settings) => set((state) => ({ ...state, ...settings })),
  setError: (error) => set({ error }),
  reset: () => set(initialState),
}), { name: 'UIStore' }));

export default useUIStore;