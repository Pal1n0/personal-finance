// src/store/uiStore.ts
import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

interface UiState {
  dateFormat: string | null;
  language: string | null;
  error: string | null;
  setUi: (settings: { dateFormat?: string; language?: string }) => void;
  setError: (error: string | null) => void;
  reset: () => void;
}

const initialState = {
  dateFormat: null,
  language: null,
  error: null,
};

const useUiStore = create<UiState>()(devtools((set) => ({
  ...initialState,
  setUi: (settings) =>
    set((state) => ({
      ...state,
      ...settings,
    })),
  setError: (error) => set({ error }),
  reset: () => set(initialState),
}), { name: 'UiStore' }));

export default useUiStore;