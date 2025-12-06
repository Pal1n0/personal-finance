import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

export type Workspace = {
  id: string;
  name: string;
  // Add other properties of a workspace if known
};

interface WorkspaceStore {
  activeWorkspace: Workspace | null;
  setActiveWorkspace: (workspace: Workspace) => void;
  // Potentially add a list of all workspaces if needed globally
  // workspaces: Workspace[];
  // setWorkspaces: (workspaces: Workspace[]) => void;
}

const useWorkspaceStore = create<WorkspaceStore>()(devtools((set) => ({
  activeWorkspace: null,
  setActiveWorkspace: (workspace) => set({ activeWorkspace: workspace }),
  // workspaces: [],
  // setWorkspaces: (workspaces) => set({ workspaces: workspaces }),
}), { name: 'WorkspaceStore' }));

export default useWorkspaceStore;
