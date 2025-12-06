import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Settings } from 'lucide-react';
import LanguageSwitcher from '@/components/ui/LanguageSwitcher';
import { Button } from '@/components/ui/button';
import { WorkspaceSwitcher } from '@/components/ui/WorkspaceSwitcher';
import useUIStore from '@/store/useUIStore';

export function Header() {
  const { t } = useTranslation();
  const pageTitle = useUIStore((state) => state.pageTitle);

  return (
    <header className="flex items-center justify-between h-16 px-4 md:px-8 border-b bg-white dark:bg-zinc-950">
      <div>
        {/* Placeholder for a mobile menu icon or breadcrumbs in the future */}
        <h1 className="text-lg font-semibold text-zinc-900 dark:text-zinc-50 truncate">{pageTitle ? t(pageTitle) : ''}</h1>
      </div>
      <div className="flex items-center space-x-2">
        <WorkspaceSwitcher />
        <LanguageSwitcher />
        <Link to="/settings/user">
          <Button variant="ghost" size="icon">
            <Settings className="h-5 w-5" />
            <span className="sr-only">{t('nav.settings')}</span>
          </Button>
        </Link>
        {/* Other header items like user profile can go here */}
      </div>
    </header>
  );
}
