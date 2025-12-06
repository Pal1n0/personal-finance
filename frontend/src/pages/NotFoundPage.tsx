import { useTranslation } from 'react-i18next';

const NotFoundPage = () => {
  const { t } = useTranslation();
  return (
    <div className="flex justify-center items-center h-screen">
      {t('placeholder.page_not_found')}
    </div>
  );
};

export default NotFoundPage;
