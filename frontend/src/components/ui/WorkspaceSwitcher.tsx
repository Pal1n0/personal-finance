import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWorkspaces } from '@/hooks/useWorkspaces';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from './dropdown-menu';
import { Button } from '@/components/ui/button';
import { buttonVariants } from './button';
import useWorkspaceStore, { type Workspace } from '../../store/useWorkspaceStore';
import { Check, ChevronsUpDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTranslation } from 'react-i18next'; // Import useTranslation
import { CreateWorkspaceModal } from '@/features/workspaces/CreateWorkspaceModal';

export function WorkspaceSwitcher() {
  const navigate = useNavigate();
  const { t } = useTranslation(); // Initialize useTranslation
  const { data: workspaces, isLoading } = useWorkspaces();
  const [isCreateWorkspaceModalOpen, setIsCreateWorkspaceModalOpen] = useState(false);

  const activeWorkspace = useWorkspaceStore((state) => state.activeWorkspace);
  const setActiveWorkspace = useWorkspaceStore((state) => state.setActiveWorkspace);

  useEffect(() => {
    if (workspaces && workspaces.length > 0 && !activeWorkspace) {
      setActiveWorkspace(workspaces[0]);
    } else if (workspaces && workspaces.length === 0 && activeWorkspace) {
      setActiveWorkspace(null);
    }
  }, [workspaces, activeWorkspace, setActiveWorkspace]);

  if (isLoading) {
    return (
      <button
        disabled
        className={cn(
          buttonVariants({ variant: "outline" }),
          "w-[200px] justify-between opacity-50"
        )}
      >
        {t('workspaces.loading')}
        <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
      </button>
    );
  }

  if (!workspaces || workspaces.length === 0) {
    return (
      <>
        <Button
          variant="default"
          className="w-[200px] justify-center"
          onClick={() => setIsCreateWorkspaceModalOpen(true)}
        >
          {t('workspaces.create.button')}
        </Button>
        <CreateWorkspaceModal
          isOpen={isCreateWorkspaceModalOpen}
          onClose={() => setIsCreateWorkspaceModalOpen(false)}
        />
      </>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cn(
          buttonVariants({ variant: "outline" }),
          "w-[200px] justify-between"
        )}
        role="combobox"
      >
        <span className="truncate">
            {activeWorkspace ? activeWorkspace.name : t('workspaces.select')}
        </span>
        <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-[200px]">
        {workspaces?.map((workspace) => (
          <DropdownMenuItem
            key={workspace.id}
            onSelect={() => setActiveWorkspace(workspace)}
            className="cursor-pointer"
          >
            {workspace.name}
            <Check className={`ml-auto h-4 w-4 ${activeWorkspace?.id === workspace.id ? 'opacity-100' : 'opacity-0'}`} />
          </DropdownMenuItem>
        ))}
        <DropdownMenuItem onSelect={() => setIsCreateWorkspaceModalOpen(true)} className="cursor-pointer text-blue-600">
          {t('workspaces.create.new')}
        </DropdownMenuItem>
      </DropdownMenuContent>
      <CreateWorkspaceModal
        isOpen={isCreateWorkspaceModalOpen}
        onClose={() => setIsCreateWorkspaceModalOpen(false)}
      />
    </DropdownMenu>
  );
}