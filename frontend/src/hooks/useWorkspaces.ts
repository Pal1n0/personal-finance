import { useQuery } from '@tanstack/react-query';
import { fetchWorkspaces } from '@/services/workspaceService';

export const useWorkspaces = () => {
  return useQuery({
    queryKey: ['workspaces'],
    queryFn: fetchWorkspaces,
    staleTime: 1000 * 60 * 5, // Data is fresh for 5 minutes
    retry: 3,
  });
};
