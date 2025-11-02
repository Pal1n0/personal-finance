# permissions.py
from rest_framework import permissions
from .models import WorkspaceMembership, Workspace

class IsWorkspaceMember(permissions.BasePermission):
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_pk') or view.kwargs.get('workspace_id')
        if workspace_id:
            return WorkspaceMembership.objects.filter(
                workspace_id=workspace_id,
                user=request.user
            ).exists()
        return True

class IsWorkspaceEditor(permissions.BasePermission):
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_pk') or view.kwargs.get('workspace_id')
        if workspace_id:
            return WorkspaceMembership.objects.filter(
                workspace_id=workspace_id,
                user=request.user,
                role__in=['editor', 'admin', 'owner']
            ).exists()
        return True

class IsWorkspaceAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_pk') or view.kwargs.get('workspace_id')
        if workspace_id:
            return WorkspaceMembership.objects.filter(
                workspace_id=workspace_id,
                user=request.user,
                role__in=['admin', 'owner']
            ).exists()
        return True

class IsWorkspaceOwner(permissions.BasePermission):
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_pk') or view.kwargs.get('workspace_id')
        if workspace_id:
            workspace = Workspace.objects.filter(id=workspace_id).first()
            return workspace and workspace.owner == request.user
        return True