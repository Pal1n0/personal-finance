import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { createWorkspace } from '../../services/workspaceService';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';

interface CreateWorkspaceModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function CreateWorkspaceModal({ isOpen, onClose }: CreateWorkspaceModalProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const queryClient = useQueryClient();
  const { mutateAsync: submitWorkspaceCreation, isLoading } = useMutation({
    mutationFn: createWorkspace,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['workspaces'] });
    },
  });
  const [nameError, setNameError] = useState<string | null>(null);

  const handleCreate = async () => {
    console.log('handleCreate called');
    console.log('Name:', name, 'Description:', description);
    setNameError(null); // Reset previous error

    if (!name.trim()) {
      setNameError(t('workspaces.create.nameRequired'));
      console.log('Validation failed: name required');
      return;
    }
    if (name.trim().length < 2) {
      setNameError(t('workspaces.create.nameMinLength'));
      console.log('Validation failed: name too short');
      return;
    }

    try {
      console.log('Attempting to create workspace...');
      const newWorkspace = await submitWorkspaceCreation({ name, description });
      toast.success(t('workspaces.create.success', { name: newWorkspace.name }));
      onClose();
      // Redirect to the new workspace's settings page
      navigate(`/settings/workspaces/${newWorkspace.id}`);
      console.log('Workspace created successfully:', newWorkspace);
    } catch (err: any) {
      const errorMessage = err.data?.detail || t('workspaces.create.error');
      toast.error(errorMessage);
      console.error('Failed to create workspace:', err);
    }
  };

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      setName('');
      setDescription('');
      setNameError(null);
      onClose();
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>{t('workspaces.create.title')}</DialogTitle>
          <DialogDescription>
            {t('workspaces.create.description')}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="name" className="text-right">
              {t('workspaces.create.form.name')}
            </Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                if (nameError) setNameError(null); // Clear error on change
              }}
              className="col-span-3"
            />
            {nameError && (
              <p className="col-start-2 col-span-3 text-sm text-red-500">
                {nameError}
              </p>
            )}
          </div>
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="description" className="text-right">
              {t('workspaces.create.form.description')}
            </Label>
            <Textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="col-span-3 resize-none"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isLoading}>
            {t('workspaces.create.form.cancel')}
          </Button>
          <Button onClick={handleCreate} disabled={isLoading}>
            {isLoading ? t('workspaces.create.form.creating') : t('workspaces.create.form.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
