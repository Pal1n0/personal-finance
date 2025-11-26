# c:\Users\pavol\Desktop\personal-finance\backend\finance\tests\unit\test_signals.py
import pytest
from django.contrib.auth import get_user_model

from finance.models import UserSettings, Workspace, WorkspaceSettings

User = get_user_model()


@pytest.mark.django_db
def test_create_user_settings_signal():
    """
    Test that UserSettings are created automatically when a new user is created.
    """
    # Ensure no UserSettings exist for a user that hasn't been created yet
    assert not UserSettings.objects.filter(user__username="new_test_user").exists()

    # Create a new user, which should trigger the post_save signal
    user = User.objects.create_user(
        username="new_test_user",
        email="new_test_user@example.com",
        password="password123",
    )

    # Check if the UserSettings were created for the new user
    assert UserSettings.objects.filter(user=user).exists()

    # Optional: Retrieve and verify the created object
    user_settings = UserSettings.objects.get(user=user)
    assert user_settings.user == user


@pytest.mark.django_db
def test_create_workspace_settings_signal(test_user):
    """
    Test that WorkspaceSettings are created automatically when a new Workspace is created.
    """
    # Ensure no WorkspaceSettings exist for a workspace that hasn't been created yet
    assert not WorkspaceSettings.objects.filter(
        workspace__name="New Test Workspace"
    ).exists()

    # Create a new workspace, which should trigger the post_save signal
    workspace = Workspace.objects.create(name="New Test Workspace", owner=test_user)

    # Check if the WorkspaceSettings were created for the new workspace
    assert WorkspaceSettings.objects.filter(workspace=workspace).exists()

    # Optional: Retrieve and verify the created object
    workspace_settings = WorkspaceSettings.objects.get(workspace=workspace)
    assert workspace_settings.workspace == workspace


@pytest.mark.django_db
def test_create_workspace_settings_with_owner_preferred_currency_signal():
    """
    Test that WorkspaceSettings' domestic_currency is set to the owner's
    UserSettings.preferred_currency when a new Workspace is created.
    """
    # 1. Create a user with a specific preferred currency
    user = User.objects.create_user(
        username="user_with_custom_currency",
        email="user_custom@example.com",
        password="password123",
    )
    # The signal for User creation will create UserSettings
    user_settings = UserSettings.objects.get(user=user)
    user_settings.preferred_currency = "USD"
    user_settings.save()

    # 2. Create a workspace owned by this user
    workspace = Workspace.objects.create(
        name="Workspace with Custom Currency", owner=user
    )

    # 3. Assert that the WorkspaceSettings for this new workspace
    #    has its domestic_currency set to the user's preferred_currency
    workspace_settings = WorkspaceSettings.objects.get(workspace=workspace)
    assert workspace_settings.domestic_currency == "USD"