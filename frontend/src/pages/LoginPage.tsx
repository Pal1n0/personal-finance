// src/pages/LoginPage.tsx
import React from 'react';
import { useTranslation } from 'react-i18next';

const LoginPage = () => {
  const { t } = useTranslation();

  return (
    <div className="flex items-center justify-center h-screen bg-gray-100">
      <div className="p-8 bg-white rounded shadow-md w-96">
        <h1 className="text-2xl font-bold mb-4">{t('login.title')}</h1>
        <p>{t('login.form_placeholder')}</p>
      </div>
    </div>
  );
};

export default LoginPage;
