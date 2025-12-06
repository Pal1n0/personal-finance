import { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { format } from "date-fns";
import { toast } from "sonner";

import { useTranslation } from "react-i18next";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";

import { Input } from "@/components/ui/input";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import apiClient from "@/services/apiClient";
import { Loader2 } from "lucide-react";

interface WorkspaceSettingsOptions {
    domestic_currency: [string, string][];
    fiscal_year_start: [number, string][];
    display_mode: [string, string][];
}

interface WorkspaceSettings {
  id: string;
  domestic_currency: string;
  fiscal_year_start: number;
  display_mode: string;
  accounting_mode: boolean;
  options: WorkspaceSettingsOptions;
}

interface Workspace {
  id: string;
  name: string;
  description: string;
  created_at: string;
  settings: WorkspaceSettings | null;
  user_role: string | null;
  user_permissions: any;
}

interface Member {
  user_id: number;
  username: string;
  role: string;
  is_owner: boolean;
  is_admin: boolean;
  joined_at: string;
}

interface MembersData {
  workspace_id: string;
  workspace_name: string;
  members: Member[];
  total_members: number;
}


import useUIStore from '@/store/useUIStore';

export function WorkspaceDetailPage() {
  const { t } = useTranslation();
  console.log("Rendering WorkspaceDetailPage");
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const setPageTitle = useUIStore((state) => state.setPageTitle);

  const {
    data: workspace,
    isPending: isWorkspaceLoading,
    error: workspaceError,
  } = useQuery<Workspace>({
    queryKey: ["workspace", id],
    queryFn: async () => {
      console.log("Fetching workspace data");
      const response = await apiClient.get(`/api/workspaces/${id}/`);
      return response.data;
    },
    enabled: !!id,
  });

    const [name, setName] = useState("");

    const [description, setDescription] = useState("");

    const [domesticCurrency, setDomesticCurrency] = useState("");

    const [fiscalYearStart, setFiscalYearStart] = useState<number | string>("");

    const [displayMode, setDisplayMode] = useState("");

    const [accountingMode, setAccountingMode] = useState(false);

    const [initialDetails, setInitialDetails] = useState({ name: "", description: "" });

    const [initialSettings, setInitialSettings] = useState({

      domestic_currency: "",

      fiscal_year_start: "",

      display_mode: "",

      accounting_mode: false,

    });

  

    const [isDetailsDirty, setIsDetailsDirty] = useState(false);

    const [isSettingsDirty, setIsSettingsDirty] = useState(false);

    const { data: membersData, isLoading: areMembersLoading } = useQuery<MembersData>({
      queryKey: ["workspaceMembers", id],
      queryFn: async () => {
        const response = await apiClient.get(`/api/workspaces/${id}/members/`);
        return response.data;
      },
      enabled: !!id && workspace?.user_role === 'owner',
    });
  

    useEffect(() => {
      if (workspace) {
        setPageTitle(workspace.name);
      }
    }, [workspace, setPageTitle]);

    useEffect(() => {

      if (workspace) {

        const details = {

          name: workspace.name,

          description: workspace.description,

        };

        setName(details.name);

        setDescription(details.description);

        setInitialDetails(details);

        setIsDetailsDirty(false);

  

        if (workspace.settings) {

          const settings = {

            domestic_currency: workspace.settings.domestic_currency,

            fiscal_year_start: String(workspace.settings.fiscal_year_start),

            display_mode: workspace.settings.display_mode,

            accounting_mode: workspace.settings.accounting_mode,

          };

          setDomesticCurrency(settings.domestic_currency);

          setFiscalYearStart(settings.fiscal_year_start);

          setDisplayMode(settings.display_mode);

          setAccountingMode(settings.accounting_mode);

          setInitialSettings(settings);

          setIsSettingsDirty(false);

        }

      }

    }, [workspace]);

  

    const updateWorkspaceMutation = useMutation({

      mutationFn: (updatedWorkspace: { name: string; description: string }) => {

        return apiClient.patch(`/api/workspaces/${id}/`, updatedWorkspace);

      },

      onSuccess: (data) => {

        queryClient.invalidateQueries({ queryKey: ["workspace", id] });

        const newDetails = { name: data.data.name, description: data.data.description };

        setInitialDetails(newDetails);

        setIsDetailsDirty(false);

        toast.success(t('workspaces.detail.updateSuccess'));

      },

      onError: () => {

        toast.error(t('workspaces.detail.updateFailed'));

      },

    });

  

    const updateSettingsMutation = useMutation({

      mutationFn: (updatedSettings: Partial<WorkspaceSettings>) => {

        return apiClient.patch(

          `/api/workspaces/${id}/settings/`,

          updatedSettings

        );

      },

      onMutate: async (newSettings) => {

        await queryClient.cancelQueries({

          queryKey: ["workspace", id],

        });

        const previousWorkspace = queryClient.getQueryData<Workspace>([

          "workspace",

          id,

        ]);

        if (previousWorkspace) {

          const newWorkspace = {

            ...previousWorkspace,

            settings: {

              ...previousWorkspace.settings,

              ...newSettings,

            },

          };

          queryClient.setQueryData(["workspace", id], newWorkspace);

        }

        return { previousWorkspace };

      },

      onSuccess: (data) => {

        queryClient.invalidateQueries({ queryKey: ["workspace", id] });

        const newSettings = {

          domestic_currency: data.data.domestic_currency,

          fiscal_year_start: String(data.data.fiscal_year_start),

          display_mode: data.data.display_mode,

          accounting_mode: data.data.accounting_mode,

        };

        setInitialSettings(newSettings);

        setIsSettingsDirty(false);

        toast.success(t('workspaces.detail.updateSuccess'));

      },

      onError: (err, newSettings, context) => {

        toast.error(t('workspaces.detail.updateFailed'));

        if (context?.previousWorkspace) {

          queryClient.setQueryData(

            ["workspace", id],

            context.previousWorkspace

          );

        }

      },

    });

  

    const handleSaveDetails = () => {

      updateWorkspaceMutation.mutate({ name, description });

    };

  

    const handleSaveSettings = () => {

      updateSettingsMutation.mutate({

        domestic_currency: domesticCurrency,

        fiscal_year_start: Number(fiscalYearStart),

        display_mode: displayMode,

        accounting_mode: accountingMode,

      });

    };

  

    const handleDetailsChange = (field: 'name' | 'description', value: string) => {

      const newDetails = { name, description, [field]: value };

      if (field === 'name') setName(value);

      if (field === 'description') setDescription(value);

      setIsDetailsDirty(newDetails.name !== initialDetails.name || newDetails.description !== initialDetails.description);

    };

  

      const handleSettingChange = (

  

        field: 'domestic_currency' | 'fiscal_year_start' | 'display_mode' | 'accounting_mode',

  

        value: string | boolean | number

  

      ) => {

  

        const newSettings = {

  

          domestic_currency: domesticCurrency,

  

          fiscal_year_start: fiscalYearStart,

  

          display_mode: displayMode,

  

          accounting_mode: accountingMode,

  

          [field]: value,

  

        };

  

    

  

        if (field === 'domestic_currency') setDomesticCurrency(value as string);

  

        if (field === 'fiscal_year_start') setFiscalYearStart(value as number);

  

        if (field === 'display_mode') setDisplayMode(value as string);

  

        if (field === 'accounting_mode') setAccountingMode(value as boolean);

  

    

  

        setIsSettingsDirty(

  

          newSettings.domestic_currency !== initialSettings.domestic_currency ||

  

          String(newSettings.fiscal_year_start) !== String(initialSettings.fiscal_year_start) ||

  

          newSettings.display_mode !== initialSettings.display_mode ||

  

          newSettings.accounting_mode !== initialSettings.accounting_mode

  

        );

  

      };

  

    

  

      if (isWorkspaceLoading) {

  

        return (

  

          <div className="flex justify-center items-center h-full">

  

            <Loader2 className="h-8 w-8 animate-spin" />

  

          </div>

  

        );

  

      }

  

    

  

      if (workspaceError) {

  

        return (

  

          <div className="flex justify-center items-center h-full text-red-500">

  

            {t('workspaces.detail.loadError')}

  

          </div>

  

        );

  

      }

  

    

  

      const settingsOptions = workspace?.settings?.options;

  

      const canEdit = workspace?.user_role === 'owner' || workspace?.user_role === 'admin';

      const membersByRole = membersData?.members.reduce((acc, member) => {
        const role = member.role || 'viewer';
        if (!acc[role]) {
          acc[role] = [];
        }
        acc[role].push(member);
        return acc;
      }, {} as Record<string, Member[]>);
  

    

  

      return (

  

        <div>

  

          <h1 className="text-3xl font-bold mb-6">{t('workspaces.detail.title')}</h1>

  

    

  

          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">

  

            <Card>

  

              <CardHeader>

  

                <div className="space-y-2">

  

                  <Label htmlFor="workspaceName">{t('workspaces.detail.name')}</Label>

  

                  <TooltipProvider>

  

                    <Tooltip>

  

                      <TooltipTrigger asChild>

  

                        <Input

  

                          id="workspaceName"

  

                          value={name}

  

                          onChange={(e) => handleDetailsChange('name', e.target.value)}

  

                          disabled={!canEdit || updateWorkspaceMutation.isPending}

  

                        />

  

                      </TooltipTrigger>

  

                      {!canEdit && (

  

                        <TooltipContent>

  

                          <p>{t('workspaces.detail.editPermissions')}</p>

  

                        </TooltipContent>

  

                      )}

  

                    </Tooltip>

  

                  </TooltipProvider>

  

                </div>

  

                <div className="space-y-2">

  

                  <Label htmlFor="workspaceDescription">{t('workspaces.detail.description')}</Label>

  

                  <TooltipProvider>

  

                    <Tooltip>

  

                      <TooltipTrigger asChild>

  

                        <Input

  

                          id="workspaceDescription"

  

                          value={description}

  

                          onChange={(e) => handleDetailsChange('description', e.target.value)}

  

                          disabled={!canEdit || updateWorkspaceMutation.isPending}

  

                        />

  

                      </TooltipTrigger>

  

                      {!canEdit && (

  

                        <TooltipContent>

  

                          <p>{t('workspaces.detail.editPermissions')}</p>

  

                        </TooltipContent>

  

                      )}

  

                    </Tooltip>

  

                  </TooltipProvider>

  

                </div>

  

              </CardHeader>

  

              <CardContent>

                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    {t('workspaces.detail.yourRole')}: {workspace?.user_role}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {t('workspaces.detail.createdAt')}{" "}
                    {workspace?.created_at
                      ? format(new Date(workspace.created_at), "PPP")
                      : t('workspaces.detail.notAvailable')}
                  </p>
                </div>

                <Button

                  onClick={handleSaveDetails}

                  disabled={updateWorkspaceMutation.isPending || !isDetailsDirty}

                  className="w-fit mt-4"

                >

                  {updateWorkspaceMutation.isPending && (

                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />

                  )}

                  {updateWorkspaceMutation.isPending ? t('workspaces.detail.saving') : t('workspaces.detail.save')}

                </Button>

              </CardContent>

  

            </Card>

  

    

  

            <Card className="lg:col-span-2">

  

              <CardHeader>

  

                <CardTitle>{t('workspaces.detail.settingsTitle')}</CardTitle>

  

                <CardDescription>

  

                  {t('workspaces.detail.settingsDescription')}

  

                </CardDescription>

  

              </CardHeader>

  

              <CardContent>

  

                <div className="grid gap-4">

  

                  <div className="grid gap-2">

  

                    <Label htmlFor="domesticCurrency">{t('workspaces.detail.domesticCurrency')}</Label>

  

                    <Select

  

                      value={domesticCurrency}

  

                      onValueChange={(value) => handleSettingChange('domestic_currency', value)}

  

                      disabled={updateSettingsMutation.isPending}

  

                    >

  

                      <SelectTrigger className="w-[180px]">

  

                        <SelectValue placeholder={t('workspaces.detail.selectCurrency')} />

  

                      </SelectTrigger>

  

                      <SelectContent>

  

                                                {settingsOptions?.domestic_currency.map(([value]) => (

  

                                                  <SelectItem key={value} value={value}>

  

                                                    {t(`currencies.${value}`)}

  

                                                  </SelectItem>

  

                                                ))}

  

                                              </SelectContent>

  

                                            </Select>

  

                                          </div>

  

                        

  

                            

  

                        

  

                                          <div className="grid gap-2">

  

                        

  

                                            <Label htmlFor="fiscalYearStart">{t('workspaces.detail.fiscalYearStartMonth')}</Label>

  

                        

  

                                            <Select

  

                        

  

                                              value={String(fiscalYearStart)}

  

                        

  

                                              onValueChange={(value) => handleSettingChange('fiscal_year_start', Number(value))}

  

                        

  

                                              disabled={updateSettingsMutation.isPending}

  

                        

  

                                            >

  

                        

  

                                              <SelectTrigger className="w-[180px]">

  

                        

  

                                                <SelectValue placeholder={t('workspaces.detail.selectMonth')} />

  

                        

  

                                              </SelectTrigger>

  

                        

  

                                              <SelectContent>

  

                        

  

                                                {settingsOptions?.fiscal_year_start.map(([value]) => (

  

                        

  

                                                  <SelectItem key={value} value={String(value)}>

  

                        

  

                                                    {t(`months.${value}`)}

  

                        

  

                                                  </SelectItem>

  

                        

  

                                                ))}

  

                        

  

                                              </SelectContent>

  

                        

  

                                            </Select>

  

                        

  

                                          </div>

  

                        

  

                            

  

                        

  

                                          <div className="grid gap-2">

  

                        

  

                                            <Label htmlFor="displayMode">{t('workspaces.detail.displayMode')}</Label>

  

                        

  

                                            <Select

  

                        

  

                                              value={displayMode}

  

                        

  

                                              onValueChange={(value) => handleSettingChange('display_mode', value)}

  

                        

  

                                              disabled={updateSettingsMutation.isPending}

  

                        

  

                                            >

  

                        

  

                                              <SelectTrigger className="w-[180px]">

  

                        

  

                                                <SelectValue placeholder={t('workspaces.detail.selectDisplayMode')} />

  

                        

  

                                              </SelectTrigger>

  

                        

  

                                              <SelectContent>

  

                        

  

                                                {settingsOptions?.display_mode.map(([value]) => (

  

                        

  

                                                  <SelectItem key={value} value={value}>

  

                        

  

                                                    {t(`displayModes.${value}`)}

  

                        

  

                                                  </SelectItem>

  

                        

  

                                                ))}

  

                        

  

                                              </SelectContent>

  

                        

  

                                            </Select>

  

                        

  

                                          </div>

  

    

  

                  <div className="flex items-center space-x-2">

  

                    <Switch

  

                      id="accountingMode"

  

                      checked={accountingMode}

  

                      onCheckedChange={(value) => handleSettingChange('accounting_mode', value)}

  

                      disabled={updateSettingsMutation.isPending}

  

                    />

  

                    <Label htmlFor="accountingMode">{t('workspaces.detail.accountingMode')}</Label>

  

                  </div>

  

    

  

                  <Button

  

                    onClick={handleSaveSettings}

  

                    disabled={updateSettingsMutation.isPending || !isSettingsDirty}

  

                    className="w-fit"

  

                  >

  

                    {updateSettingsMutation.isPending && (

  

                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />

  

                    )}

  

                    {updateSettingsMutation.isPending ? t('workspaces.detail.saving') : t('workspaces.detail.save')}

  

                  </Button>

  

                </div>

  

              </CardContent>

  

            </Card>

            {workspace?.user_role === 'owner' && (
              <Card className="lg:col-span-3">
                <CardHeader>
                  <CardTitle>{t('workspaces.detail.membersTitle')}</CardTitle>
                  <CardDescription>
                    {t('workspaces.detail.membersDescription', { count: membersData?.total_members || 0 })}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {areMembersLoading ? (
                    <Loader2 className="h-8 w-8 animate-spin" />
                  ) : (
                    <div className="space-y-4">
                      {membersByRole && Object.entries(membersByRole).map(([role, members]) => (
                        <div key={role}>
                          <h4 className="font-semibold">{t('roles.' + role)} ({members.length})</h4>
                          <ul className="list-disc pl-5 text-sm text-muted-foreground">
                            {members.map(member => (
                              <li key={member.user_id}>{member.username}</li>
                            ))}
                          </ul>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

          </div>

        </div>

      );

    }

  

  
