
import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import type { User } from '../types';

interface UserState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  dateFormat: string | null;
  language: string | null;
  setCredentials: (user: User, token: string) => void;
  logout: () => void;
  setUserSettings: (settings: { dateFormat?: string; language?: string }) => void;
}

const useUserStore = create<UserState>()(devtools((set) => ({
  user: null,
  token: localStorage.getItem('token'),
  isAuthenticated: !!localStorage.getItem('token'),
  dateFormat: null,
  language: null,
  setCredentials: (user, token) => {
    set({ user, token, isAuthenticated: true });
    localStorage.setItem('token', token);
  },
  logout: () => {
    set({ user: null, token: null, isAuthenticated: false });
    localStorage.removeItem('token');
  },
  setUserSettings: (settings) =>
    set((state) => ({
      ...state,
      ...settings,
    })),
}), { name: 'UserStore' }));

export default useUserStore;
