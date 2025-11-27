import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import Backend from 'i18next-http-backend';

i18n
  // Načíta preklady zo súborov (napr. /public/locales/sk/translation.json)
  .use(Backend)
  // Zistí jazyk užívateľa (sk, cz, en)
  .use(LanguageDetector)
  // Prepojí s Reactom
  .use(initReactI18next)
  .init({
    fallbackLng: 'en', // Ak jazyk nenájde, použije angličtinu
    debug: true, // Pri vývoji uvidíš v konzole, čo sa deje
    
    interpolation: {
      escapeValue: false, // React už chráni pred XSS, netreba to tu
    },
    
    // Kde má hľadať preklady (predvolené nastavenie Backend pluginu)
    backend: {
      loadPath: '/locales/{{lng}}/{{ns}}.json',
    }
  });

export default i18n;