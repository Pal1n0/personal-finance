// src/pages/SettingsPage.tsx
import { useForm, Controller } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import apiClient from '@/services/apiClient';
import useUIStore from '@/store/useUIStore';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { UserSettings } from '@/types';
import { LANGUAGES_AVAILABLE } from '@/components/ui/LanguageSwitcher'; // Import LANGUAGES_AVAILABLE

// Zod schema for validation
const settingsSchema = z.object({
  language: z.string(),
  preferred_currency: z.string(),
  date_format: z.string(),
});

type SettingsFormData = z.infer<typeof settingsSchema>;

// Form component that is rendered only when settings are loaded
const SettingsForm = ({ settings }: { settings: UserSettings }) => {
  const { t, i18n } = useTranslation();
  const setUi = useUIStore((state) => state.setUi);
  const queryClient = useQueryClient();

  const { control, handleSubmit, formState: { isDirty }, reset } = useForm<SettingsFormData>({
    resolver: zodResolver(settingsSchema),
    defaultValues: {
      language: settings.language,
      preferred_currency: settings.preferred_currency,
      date_format: settings.date_format,
    },
    mode: 'onChange',
  });

  const mutation = useMutation({
    mutationFn: (data: SettingsFormData) => apiClient.patch('api/v1/finance/user-settings/', data),
    onSuccess: (response, variables) => {
        const updatedSettings = response.data;
        
        const uiPayload: { dateFormat: string; language?: string } = {
          dateFormat: updatedSettings.date_format,
        };

        // Check if the language was explicitly changed in the form
        if (variables.language !== settings.language) {
            // If it was changed, then update i18n and localStorage to the new submitted language
            if (variables.language !== i18n.language) { // Prevent redundant i18n change
                i18n.changeLanguage(variables.language);
                localStorage.setItem('i18nextLng', variables.language);
            }
            uiPayload.language = variables.language; // Update UI store with the newly submitted language
        } else {
            // If the language was NOT explicitly changed in the form,
            // ensure uiPayload.language matches the current i18n.language.
            // This prevents reverting the UI language if it was set by the LanguageSwitcher.
            uiPayload.language = i18n.language;
        }
        
        setUi(uiPayload);
        
        reset(updatedSettings);
        queryClient.invalidateQueries({ queryKey: ['user-settings'] });
        
        console.log('Settings updated successfully!');
      },
      onError: (error) => {
        console.error('Failed to update settings:', error);
      }
  });

  console.log("isDirty:", isDirty, "mutation.isPending:", mutation.isPending);

  const onSubmit = (data: SettingsFormData) => {
    mutation.mutate(data);
  };

  return (
    <Card className="max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle>{t('settings.title')}</CardTitle>
        <CardDescription>{t('settings.description')}</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          {/* Language Setting */}
          <div className="space-y-2">
            <Label htmlFor="language">{t('settings.language.label')}</Label>
            <Controller
              name="language"
              control={control}
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger>
                    <SelectValue placeholder={t('settings.language.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {settings.options?.language.map(([value]) => (
                      <SelectItem key={value} value={value}>
                        {LANGUAGES_AVAILABLE.find(lang => lang.code === value)?.name || value} {/* Use native name from LANGUAGES_AVAILABLE */}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          {/* Preferred Currency Setting */}
          <div className="space-y-2">
            <Label htmlFor="preferred_currency">{t('settings.currency.label')}</Label>
            <Controller
              name="preferred_currency"
              control={control}
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger>
                    <SelectValue placeholder={t('settings.currency.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {settings.options?.preferred_currency.map(([value]) => (
                      <SelectItem key={value} value={value}>
                        {t(`currencies.${value}`)} {/* Translate using the currency code */}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          {/* Date Format Setting */}
          <div className="space-y-2">
            <Label htmlFor="date_format">{t('settings.dateFormat.label')}</Label>
            <Controller
              name="date_format"
              control={control}
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger>
                    <SelectValue placeholder={t('settings.dateFormat.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    {settings.options?.date_format.map(([value, label]) => (
                      <SelectItem key={value} value={value}>{label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          <Button type="submit" disabled={!isDirty || mutation.isPending}>
            {mutation.isPending ? t('settings.saving') : t('settings.saveButton')}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
};

export function SettingsPage() {
  const { t } = useTranslation();
  const setPageTitle = useUIStore((state) => state.setPageTitle);
  const { data: settings, isPending, isError } = useQuery({
    queryKey: ['user-settings'],
    queryFn: () => apiClient.get('api/v1/finance/user-settings/').then(res => res.data),
    retry: false,
  });

  useEffect(() => {
    setPageTitle('settings.title');
  }, [setPageTitle]);

  if (isPending) {
    return <div>{t('settings.loading')}</div>;
  }


  if (isError || !settings) {
    return <div>{t('settings.error')}</div>;
  }

  return (
    <div>
      <Link to="/settings/workspaces" className="text-blue-500 hover:underline">
        {t("workspaces.manage")}
      </Link>
      <SettingsForm settings={settings} />
    </div>
  );
}
