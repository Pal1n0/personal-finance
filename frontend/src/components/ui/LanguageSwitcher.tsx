import { Languages } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import useUIStore from '@/store/useUIStore';

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

// Export this array so SettingsPage can use it
export const LANGUAGES_AVAILABLE = [
  { code: 'en', name: 'English' },
  { code: 'sk', name: 'Slovensky' },
  { code: 'cs', name: 'Česky' },
];

export default function LanguageSwitcher() {
  const { i18n } = useTranslation(); // Removed 't'
  const uiLanguage = useUIStore((state) => state.language);
  const setUi = useUIStore((state) => state.setUi);

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
    localStorage.setItem('i18nextLng', lng); // Explicitly set localStorage
    setUi({ language: lng }); // Update local UI store for responsiveness
  };

  const currentLanguage = uiLanguage || i18n.language;

  return (
    <Select onValueChange={changeLanguage} value={currentLanguage}>
      <SelectTrigger className="w-auto flex items-center gap-2 border-none">
        <SelectValue asChild>
          <span className="flex items-center gap-2">
            <Languages className="h-5 w-5 text-muted-foreground" />
            <span className="hidden md:inline">
              {LANGUAGES_AVAILABLE.find((l) => l.code === currentLanguage)?.name} {/* Use native name */}
            </span>
          </span>
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {LANGUAGES_AVAILABLE.map((language) => (
          <SelectItem key={language.code} value={language.code}>
            {language.name} {/* Use native name */}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}