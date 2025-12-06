import { Outlet, useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { LayoutDashboard, Wallet, Settings, LogOut, AlertTriangle, Tags, Landmark } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Header } from '@/components/layout/Header';
import { useTranslation } from 'react-i18next';
import apiClient from '@/services/apiClient';
import useUserStore from '@/store/useUserStore';
import useUIStore from '@/store/useUIStore';
import { CollapsibleNav } from '@/components/layout/CollapsibleNav';

export function DashboardLayout() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();

  const isAuthenticated = useUserStore((state) => state.isAuthenticated);
  const logout = useUserStore((state) => state.logout);
  const setUserSettings = useUserStore((state) => state.setUserSettings);
  const setUi = useUIStore((state) => state.setUi);


  const { data: userSettings, isLoading: isInitLoading, isError: loadError } = useQuery({
    queryKey: ['user-settings'],
    queryFn: () => apiClient.get('api/v1/finance/user-settings/').then(res => res.data),
    enabled: isAuthenticated,
    retry: false,
  });

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    if (userSettings) {
      const localStorageLang = localStorage.getItem('i18nextLng');

      // Initialize language from user settings only if no language is set in localStorage
      // This means the user hasn't explicitly chosen a language yet via the LanguageSwitcher
      if (!localStorageLang && userSettings.language) {
        i18n.changeLanguage(userSettings.language);
        localStorage.setItem('i18nextLng', userSettings.language);
        setUi({ language: userSettings.language });
      } else if (localStorageLang && localStorageLang !== i18n.language) {
        // If there's a language in localStorage but it's different from current i18n language,
        // it means i18n hasn't picked it up yet or it's a fresh load.
        // Ensure i18n is set to localStorage's value.
        i18n.changeLanguage(localStorageLang);
        setUi({ language: localStorageLang });
      }

      // Always keep userStore's settings in sync with backend's userSettings
      // Also update UI store dateFormat as it's not subject to the same "free choice" as language
      if (userSettings.language) {
          setUserSettings({ language: userSettings.language });
      }
      if (userSettings.date_format) {
          setUserSettings({ dateFormat: userSettings.date_format });
          setUi({ dateFormat: userSettings.date_format }); 
      }
    }
  }, [userSettings, i18n, setUi, setUserSettings]);

  const navItems = [
    { href: '/dashboard', icon: LayoutDashboard, label: t('nav.dashboard') },
    {
      icon: Wallet,
      label: t('nav.transactions'),
      subItems: [
        { href: '/transactions/expenses', label: t('nav.expenses') },
        { href: '/transactions/incomes', label: t('nav.incomes') },
      ],
    },
    {
      icon: Landmark,
      label: t('nav.categories'),
      subItems: [
        { href: '/categories/expenses', label: t('nav.expenseCategories') },
        { href: '/categories/incomes', label: t('nav.incomeCategories') },
      ],
    },
    {
      icon: Settings,
      label: t('nav.settings'),
      subItems: [
        { href: '/settings/user', label: t('nav.userSettings') },
        { href: '/settings/workspaces', label: t('nav.workspaceSettings') },
        { href: '/settings/tags', label: t('nav.tagManagement') },
      ],
    },
  ];

  const handleLogout = () => {
    logout();
  };

  if (!isAuthenticated) {
    return null;
  }

  if (isInitLoading) {
    return <div className="flex h-screen w-full items-center justify-center">Loading...</div>;
  }

  return (
    <div className="flex h-screen bg-zinc-50 dark:bg-zinc-900">
      {/* --- SIDEBAR --- */}
      <aside className="w-64 bg-white dark:bg-zinc-950 border-r border-zinc-200 dark:border-zinc-800 hidden md:flex flex-col">
        <div className="p-6">
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-50">
            {t('app.title')}<span className="text-primary">App</span>
          </h1>
        </div>

        <nav className="flex-1 px-4 py-2 space-y-1">
          {navItems.map((item) => (
            <CollapsibleNav key={item.label} item={item} />
          ))}
        </nav>

        <div className="p-4 mt-auto">
          <Button variant="ghost" className="w-full justify-start" onClick={handleLogout}>
            <LogOut className="w-5 h-5 mr-3" />
            <span>{t('nav.logout')}</span>
          </Button>
        </div>
      </aside>

      {/* --- MAIN CONTENT --- */}
      <main className="flex-1 flex flex-col overflow-y-auto">
        <Header />
        <div className="p-4 md:p-8 flex-1">
          {loadError && (
            <div className="bg-destructive/10 border border-destructive/50 text-destructive p-4 rounded-md mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                <h3 className="font-semibold">Application Error</h3>
              </div>
              <p className="text-sm mt-2">Failed to load critical user data. Some features may not work as expected.</p>
            </div>
          )}
          <Outlet />
        </div>
      </main>
    </div>
  );
}