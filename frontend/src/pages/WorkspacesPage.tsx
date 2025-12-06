import { useState, useEffect } from 'react';
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Link } from "react-router-dom";
import type { Workspace } from "@/types";
import { CreateWorkspaceModal } from '@/features/workspaces/CreateWorkspaceModal';
import { useWorkspaces } from '@/hooks/useWorkspaces';
import useUIStore from '@/store/useUIStore';

export function WorkspacesPage() {
  const { t } = useTranslation();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const { data: workspaces, isLoading, isError } = useWorkspaces();
  const setPageTitle = useUIStore((state) => state.setPageTitle);

  useEffect(() => {
    setPageTitle('workspaces.manage');
  }, [setPageTitle]);

  if (isLoading) {
    return <div>{t('workspaces.loading')}</div>;
  }

  if (isError || !workspaces) {
    return <div>{t('workspaces.error')}</div>;
  }

  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">
          {t("workspaces.manage")}
        </h2>
        <Button onClick={() => setIsModalOpen(true)}>{t("workspaces.create.button")}</Button>
      </div>
      <div className="space-y-4">
        {workspaces.map((workspace) => (
          <Card key={workspace.id}>
            <CardHeader>
              <CardTitle>{workspace.name}</CardTitle>
              <CardDescription>{workspace.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <Link to={`/settings/workspaces/${workspace.id}`}>
                <Button variant="outline">{t("workspaces.view")}</Button>
              </Link>
            </CardContent>
          </Card>
        ))}
      </div>
      <CreateWorkspaceModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </div>
  );
}