import apiClient from './apiClient';

export const fetchWorkspaces = async () => {
  const response = await apiClient.get('/api/workspaces/');
  return response.data?.results || [];
};

export const createWorkspace = async (workspaceData: { name: string; description: string }) => {
  const response = await apiClient.post('/api/workspaces/', workspaceData);
  return response.data;
};
