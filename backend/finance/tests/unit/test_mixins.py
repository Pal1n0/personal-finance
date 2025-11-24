# tests/test_mixins.py
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase
from rest_framework import serializers
from rest_framework.exceptions import ValidationError as DRFValidationError

from finance.mixins.category_workspace import CategoryWorkspaceMixin
from finance.mixins.target_user import TargetUserMixin
from finance.mixins.workspace_context import WorkspaceContextMixin
from finance.mixins.workspace_membership import WorkspaceMembershipMixin
from finance.models import (
    ExpenseCategoryVersion,
    IncomeCategoryVersion,
    Workspace,
    WorkspaceMembership,
)
from finance.services.membership_cache_service import MembershipCacheService
from finance.services.workspace_context_service import WorkspaceContextService

User = get_user_model()


class BaseMixinTest(TestCase):
    """Base class for all mixin tests."""

    def setUp(self):
        self.factory = RequestFactory()

        # Create test users
        self.user = User.objects.create_user(
            email="user@test.com", password="testpass123", username="testuser"
        )
        self.target_user = User.objects.create_user(
            email="target@test.com", password="testpass123", username="targetuser"
        )
        self.admin_user = User.objects.create_user(
            email="admin@test.com", password="testpass123", username="adminuser"
        )

        # Create workspaces
        self.workspace1 = Workspace.objects.create(name="Workspace 1", owner=self.user)
        self.workspace2 = Workspace.objects.create(
            name="Workspace 2", owner=self.admin_user
        )

        # Create category versions
        self.expense_version1 = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace1, name="Expense Version 1", created_by=self.user
        )
        self.expense_version2 = ExpenseCategoryVersion.objects.create(
            workspace=self.workspace2,
            name="Expense Version 2",
            created_by=self.admin_user,
        )
        self.income_version1 = IncomeCategoryVersion.objects.create(
            workspace=self.workspace1, name="Income Version 1", created_by=self.user
        )

        # Create memberships
        self.membership1 = WorkspaceMembership.objects.create(
            workspace=self.workspace1, user=self.target_user, role="editor"
        )
        self.membership2 = WorkspaceMembership.objects.create(
            workspace=self.workspace2, user=self.user, role="viewer"
        )

    def create_serializer_with_mixin(self, mixin_class, context=None, instance=None):
        """Helper to create serializer with mixin."""

        class TestSerializer(mixin_class, serializers.Serializer):
            class Meta:
                fields = "__all__"

        serializer = TestSerializer(context=context or {})
        if instance:
            serializer.instance = instance
        return serializer

    def create_request(
        self, user=None, target_user=None, workspace=None, is_impersonation=False
    ):
        """Helper to create request with common attributes."""
        request = self.factory.get("/")
        request.user = user or self.user
        if target_user:
            request.target_user = target_user
        if workspace:
            request.workspace = workspace
        request.is_admin_impersonation = is_impersonation
        request.user_permissions = Mock()
        request.user_permissions.workspace_exists = False
        request.user_permissions.current_workspace_id = None
        request.user_permissions.workspace_role = None
        return request


class TestTargetUserMixin(BaseMixinTest):
    """Comprehensive tests for TargetUserMixin."""

    def test_user_assignment_from_target_user(self):
        """Test user is assigned from request.target_user."""
        request = self.create_request(
            user=self.admin_user, target_user=self.target_user
        )
        serializer = self.create_serializer_with_mixin(
            TargetUserMixin, context={"request": request}
        )

        result = serializer.validate({"field": "value"})

        self.assertEqual(result["user"], self.target_user)
        self.assertEqual(result["field"], "value")

    def test_user_assignment_overwrites_existing_user(self):
        """Test existing user is overwritten by target_user."""
        request = self.create_request(
            user=self.admin_user, target_user=self.target_user
        )
        serializer = self.create_serializer_with_mixin(
            TargetUserMixin, context={"request": request}
        )

        result = serializer.validate({"user": self.user, "field": "value"})

        self.assertEqual(result["user"], self.target_user)  # Overwritten
        self.assertEqual(result["field"], "value")

    def test_workspace_assignment_from_request(self):
        """Test workspace is assigned from request.workspace."""
        request = self.create_request(workspace=self.workspace1)
        serializer = self.create_serializer_with_mixin(
            TargetUserMixin, context={"request": request}
        )

        result = serializer.validate({"field": "value"})

        self.assertEqual(result["workspace"], self.workspace1)
        self.assertEqual(result["field"], "value")

    def test_workspace_assignment_preserves_existing_workspace(self):
        """Test existing workspace is preserved."""
        request = self.create_request(workspace=self.workspace1)
        serializer = self.create_serializer_with_mixin(
            TargetUserMixin, context={"request": request}
        )

        result = serializer.validate({"workspace": self.workspace2, "field": "value"})

        self.assertEqual(result["workspace"], self.workspace2)  # Preserved
        self.assertEqual(result["field"], "value")

    def test_no_request_context(self):
        """Test behavior without request context."""
        serializer = self.create_serializer_with_mixin(TargetUserMixin, context={})

        result = serializer.validate({"field": "value"})

        self.assertEqual(result, {"field": "value"})

    def test_request_without_target_user(self):
        """Test behavior when request has no target_user."""
        request = self.create_request()  # No target_user
        serializer = self.create_serializer_with_mixin(
            TargetUserMixin, context={"request": request}
        )

        result = serializer.validate({"field": "value"})

        self.assertEqual(result, {"field": "value"})

    @patch("finance.mixins.target_user.logger")
    def test_impersonation_logging(self, mock_logger):
        """Test logging during admin impersonation."""
        request = self.create_request(
            user=self.admin_user, target_user=self.target_user, is_impersonation=True
        )
        serializer = self.create_serializer_with_mixin(
            TargetUserMixin, context={"request": request}
        )

        serializer.validate({})

        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args[1]
        self.assertEqual(call_args["extra"]["target_user_id"], self.target_user.id)
        self.assertEqual(call_args["extra"]["impersonation_active"], True)
        self.assertEqual(call_args["extra"]["action"], "target_user_assignment")

    def test_serializer_inheritance_chain(self):
        """Test mixin works correctly in inheritance chain."""

        class ParentSerializer(serializers.Serializer):
            def validate(self, attrs):
                attrs["parent"] = True
                return super().validate(attrs)

        class ChildSerializer(TargetUserMixin, ParentSerializer):
            def validate(self, attrs):
                attrs["child"] = True
                return super().validate(attrs)

        request = self.create_request(
            user=self.admin_user, target_user=self.target_user
        )
        serializer = ChildSerializer(context={"request": request})

        result = serializer.validate({"original": "value"})

        self.assertEqual(result["user"], self.target_user)
        self.assertEqual(result["parent"], True)
        self.assertEqual(result["child"], True)
        self.assertEqual(result["original"], "value")


@patch(
    "finance.mixins.workspace_membership.WorkspaceMembershipMixin.membership_service"
)
class TestWorkspaceMembershipMixin(BaseMixinTest):
    """Comprehensive tests for WorkspaceMembershipMixin using a mocked service."""

    def setUp(self):
        super().setUp()
        self.mixin = WorkspaceMembershipMixin()

    def test_membership_cache_initialization(self, mock_membership_service):
        """Test service is called on first access when cache is empty."""
        mock_membership_service.get_comprehensive_user_data.return_value = {
            "roles": {self.workspace2.id: "viewer"}
        }
        request = self.create_request(user=self.user)

        self.assertFalse(hasattr(request, "_cached_user_memberships"))

        memberships = self.mixin._get_user_memberships(request)

        self.assertTrue(hasattr(request, "_cached_user_memberships"))
        mock_membership_service.get_comprehensive_user_data.assert_called_once_with(
            self.user.id
        )
        self.assertIn(self.workspace2.id, memberships)
        self.assertEqual(memberships[self.workspace2.id], "viewer")

    def test_membership_cache_reuse(self, mock_membership_service):
        """Test service is not called if cache is already populated."""
        request = self.create_request(user=self.user)
        request._cached_user_memberships = {self.workspace1.id: "owner"}

        # First call - should use existing cache
        memberships1 = self.mixin._get_user_memberships(request)

        # Second call - should also use existing cache
        memberships2 = self.mixin._get_user_memberships(request)

        mock_membership_service.get_comprehensive_user_data.assert_not_called()
        self.assertEqual(memberships1, memberships2)
        self.assertEqual(memberships1, {self.workspace1.id: "owner"})

    def test_membership_for_workspace_existing(self, mock_membership_service):
        """Test role retrieval for an existing membership from cache."""
        request = self.create_request(user=self.target_user)
        request._cached_user_memberships = {
            self.workspace1.id: "editor",
            self.workspace2.id: "viewer",
        }

        role = self.mixin._get_membership_for_workspace(self.workspace1, request)

        self.assertEqual(role, "editor")

    def test_membership_for_workspace_nonexistent(self, mock_membership_service):
        """Test role retrieval for a non-existent membership from cache."""
        request = self.create_request(user=self.user)
        request._cached_user_memberships = {self.workspace2.id: "viewer"}

        role = self.mixin._get_membership_for_workspace(self.workspace1, request)

        self.assertIsNone(role)

    def test_uses_target_user_for_cache_initialization(self, mock_membership_service):
        """Test that target_user is prioritized for cache initialization."""
        mock_membership_service.get_comprehensive_user_data.return_value = {
            "roles": {self.workspace1.id: "editor"}
        }
        request = self.create_request(user=self.user, target_user=self.target_user)

        self.mixin._get_user_memberships(request)

        mock_membership_service.get_comprehensive_user_data.assert_called_once_with(
            self.target_user.id
        )

    @patch("finance.mixins.workspace_membership.logger")
    def test_cache_initialization_logging(self, mock_logger, mock_membership_service):
        """Test logging when cache is initialized via the service."""
        mock_membership_service.get_comprehensive_user_data.return_value = {
            "roles": {self.workspace2.id: "viewer"}
        }
        request = self.create_request(user=self.user)

        self.mixin._get_user_memberships(request)

        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args[1]
        self.assertEqual(call_args["extra"]["user_id"], self.user.id)
        self.assertEqual(call_args["extra"]["action"], "membership_cache_initialized")

    @patch("finance.mixins.workspace_membership.logger")
    def test_cache_hit_logging(self, mock_logger, mock_membership_service):
        """Test logging when a role is successfully retrieved from cache."""
        request = self.create_request(user=self.target_user)
        request._cached_user_memberships = {self.workspace1.id: "editor"}

        self.mixin._get_membership_for_workspace(self.workspace1, request)

        cache_hit_found = False
        for call in mock_logger.debug.call_args_list:
            if call[1]["extra"].get("action") == "workspace_role_cache_hit":
                cache_hit_found = True
                self.assertEqual(call[1]["extra"]["user_role"], "editor")
                self.assertEqual(call[1]["extra"]["workspace_id"], self.workspace1.id)
                break
        self.assertTrue(cache_hit_found, "Cache hit log was not found.")


class TestCategoryWorkspaceMixin(BaseMixinTest):
    """Comprehensive tests for CategoryWorkspaceMixin."""

    def test_same_workspace_validation(self):
        """Test validation passes for same workspace."""
        request = self.create_request(workspace=self.workspace1)
        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin, context={"request": request}
        )

        data = {"version": self.expense_version1}
        result = serializer.validate(data)

        self.assertEqual(result, data)

    def test_cross_workspace_validation_blocked(self):
        """Test validation fails for cross-workspace access."""
        request = self.create_request(workspace=self.workspace1)
        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin, context={"request": request}
        )

        data = {"version": self.expense_version2}

        with self.assertRaises(DRFValidationError) as context:
            serializer.validate(data)

        self.assertIn(
            "Category version does not belong to this workspace", str(context.exception)
        )

    def test_instance_validation_same_workspace(self):
        """Test instance validation for same workspace."""
        request = self.create_request(workspace=self.workspace1)

        class MockInstance:
            version = self.expense_version1

        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin,
            context={"request": request},
            instance=MockInstance(),
        )

        result = serializer.validate({})
        self.assertEqual(result, {})

    def test_instance_validation_cross_workspace(self):
        """Test instance validation fails for cross-workspace."""
        request = self.create_request(workspace=self.workspace1)

        class MockInstance:
            version = self.expense_version2

        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin,
            context={"request": request},
            instance=MockInstance(),
        )

        with self.assertRaises(DRFValidationError):
            serializer.validate({})

    def test_data_version_overrides_instance(self):
        """Test data version takes precedence over instance version."""
        request = self.create_request(workspace=self.workspace1)

        class MockInstance:
            version = self.expense_version2  # Wrong workspace

        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin,
            context={"request": request},
            instance=MockInstance(),
        )

        data = {"version": self.expense_version1}  # Correct workspace
        result = serializer.validate(data)

        self.assertEqual(result, data)

    def test_no_version_in_data_or_instance(self):
        """Test validation passes when no version is provided."""
        request = self.create_request(workspace=self.workspace1)
        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin, context={"request": request}
        )

        result = serializer.validate({"other_field": "value"})

        self.assertEqual(result, {"other_field": "value"})

    def test_no_request_context(self):
        """Test validation without request context."""
        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin, context={}
        )

        result = serializer.validate({"version": self.expense_version1})

        self.assertEqual(result, {"version": self.expense_version1})

    def test_no_workspace_in_request(self):
        """Test validation without workspace in request."""
        request = self.create_request()  # No workspace
        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin, context={"request": request}
        )

        result = serializer.validate({"version": self.expense_version1})

        self.assertEqual(result, {"version": self.expense_version1})

    @patch("finance.mixins.category_workspace.logger")
    def test_cross_workspace_logging(self, mock_logger):
        """Test logging for cross-workspace access attempts."""
        request = self.create_request(workspace=self.workspace1, is_impersonation=True)
        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin, context={"request": request}
        )

        try:
            serializer.validate({"version": self.expense_version2})
        except DRFValidationError:
            pass

        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[1]
        self.assertEqual(
            call_args["extra"]["category_version_id"], self.expense_version2.id
        )
        self.assertEqual(call_args["extra"]["version_workspace_id"], self.workspace2.id)
        self.assertEqual(call_args["extra"]["request_workspace_id"], self.workspace1.id)
        self.assertEqual(call_args["extra"]["action"], "cross_workspace_access_blocked")

    def test_serializer_inheritance_chain(self):
        """Test that super().validate() is called correctly."""

        class ParentSerializer(serializers.Serializer):
            def validate(self, attrs):
                attrs["parent_called"] = True
                return super().validate(attrs)

        class ChildSerializer(CategoryWorkspaceMixin, ParentSerializer):
            def validate(self, attrs):
                attrs["child_called"] = True
                return super().validate(attrs)

        request = self.create_request(workspace=self.workspace1)
        serializer = ChildSerializer(context={"request": request})

        # This should not raise an error
        result = serializer.validate(
            {"version": self.expense_version1, "original": "value"}
        )

        self.assertTrue(result["parent_called"])
        self.assertTrue(result["child_called"])
        self.assertEqual(result["original"], "value")


class TestWorkspaceContextMixin(BaseMixinTest):
    """Comprehensive tests for WorkspaceContextMixin."""

    def setUp(self):
        super().setUp()
        self.mixin = WorkspaceContextMixin()

    @patch("finance.mixins.workspace_context.WorkspaceContextMixin.context_service")
    def test_initial_calls_context_service(self, mock_service):
        """Test initial method calls context service."""

        class ParentView:
            def initial(self, request, *args, **kwargs):
                self.parent_called = True

        class TestView(WorkspaceContextMixin, ParentView):
            def initial(self, request, *args, **kwargs):
                super().initial(request, *args, **kwargs)
                self.child_called = True

        request = self.create_request()
        view = TestView()

        view.initial(request, **{})

        mock_service.build_request_context.assert_called_once_with(request, {})
        self.assertTrue(view.parent_called)
        self.assertTrue(view.child_called)

    @patch("finance.mixins.workspace_context.WorkspaceContextMixin.context_service")
    def test_initial_propagates_exceptions(self, mock_service):

        mock_service.build_request_context.side_effect = Exception("Service error")

        class BaseTestView:
            def initial(self, request, *args, **kwargs):
                pass

        class TestView(WorkspaceContextMixin, BaseTestView):
            def initial(self, request, *args, **kwargs):
                super().initial(request, *args, **kwargs)

        request = self.create_request()
        view = TestView()

        with self.assertRaises(Exception) as context:
            view.initial(request, **{})

        self.assertEqual(str(context.exception), "Service error")


class TestAllMixinsIntegration(BaseMixinTest):
    """Integration tests for all mixins working together."""

    def test_comprehensive_serializer_with_all_mixins(self):
        """Test all mixins integrated in one serializer."""

        class ComprehensiveSerializer(
            TargetUserMixin,
            WorkspaceMembershipMixin,
            CategoryWorkspaceMixin,
            serializers.Serializer,
        ):
            def get_context_info(self):
                request = self.context.get("request")
                info = {}
                if request and hasattr(request, "target_user"):
                    info["target_user"] = request.target_user
                if request and hasattr(request, "workspace"):
                    info["workspace"] = request.workspace
                    info["user_role"] = self._get_membership_for_workspace(
                        request.workspace, request
                    )
                return info

        request = self.create_request(
            user=self.admin_user,
            target_user=self.target_user,
            workspace=self.workspace1,
            is_impersonation=True,
        )

        serializer = ComprehensiveSerializer(context={"request": request})

        # Test TargetUserMixin
        data = serializer.validate({"version": self.expense_version1})
        self.assertEqual(data["user"], self.target_user)
        self.assertEqual(data["workspace"], self.workspace1)

        # Test WorkspaceMembershipMixin
        context_info = serializer.get_context_info()
        self.assertEqual(context_info["target_user"], self.target_user)
        self.assertEqual(context_info["workspace"], self.workspace1)
        self.assertEqual(context_info["user_role"], "editor")  # target_user's role

        # Test CategoryWorkspaceMixin - should not raise for same workspace
        self.assertEqual(data["version"], self.expense_version1)

    def test_cross_workspace_security_in_integrated_serializer(self):
        """Test security validation in integrated serializer."""

        class SecureSerializer(
            TargetUserMixin, CategoryWorkspaceMixin, serializers.Serializer
        ):
            pass

        request = self.create_request(workspace=self.workspace1)
        serializer = SecureSerializer(context={"request": request})

        # Try to assign category from different workspace
        with self.assertRaises(DRFValidationError):
            serializer.validate({"version": self.expense_version2})

    @patch("finance.mixins.workspace_membership.logger")
    @patch("finance.mixins.target_user.logger")
    def test_integrated_logging(self, mock_target_logger, mock_membership_logger):
        """Test logging across all integrated mixins."""

        class LoggingSerializer(
            TargetUserMixin, WorkspaceMembershipMixin, serializers.Serializer
        ):
            pass

        request = self.create_request(
            user=self.admin_user, target_user=self.target_user, is_impersonation=True
        )

        serializer = LoggingSerializer(context={"request": request})

        # Trigger both mixins
        serializer.validate({})
        serializer._get_user_memberships(request)

        # Should have logs from both mixins
        debug_calls_target = [call for call in mock_target_logger.debug.call_args_list]
        debug_calls_membership = [
            call for call in mock_membership_logger.debug.call_args_list
        ]
        total_debug_calls = len(debug_calls_target) + len(debug_calls_membership)

        self.assertGreaterEqual(total_debug_calls, 2)

        target_user_log = next(
            (
                call
                for call in debug_calls_target
                if call[1]["extra"].get("action") == "target_user_assignment"
            ),
            None,
        )
        cache_log = next(
            (
                call
                for call in debug_calls_membership
                if call[1]["extra"].get("action") == "membership_cache_initialized"
            ),
            None,
        )

        self.assertIsNotNone(target_user_log)
        self.assertIsNotNone(cache_log)


class TestMixinEdgeCases(BaseMixinTest):
    """Edge case tests for mixins."""

    def test_target_user_mixin_with_anonymous_user(self):
        """Test TargetUserMixin with anonymous user."""
        from django.contrib.auth.models import AnonymousUser

        request = self.create_request()
        request.user = AnonymousUser()

        serializer = self.create_serializer_with_mixin(
            TargetUserMixin, context={"request": request}
        )

        result = serializer.validate({"field": "value"})
        self.assertEqual(result, {"field": "value"})

    @patch(
        "finance.mixins.workspace_membership.WorkspaceMembershipMixin.membership_service"
    )
    def test_workspace_membership_with_no_memberships(self, mock_membership_service):
        """Test WorkspaceMembershipMixin with user having no memberships."""
        mock_membership_service.get_comprehensive_user_data.return_value = {"roles": {}}
        new_user = User.objects.create_user(
            username="newuser", email="new@test.com", password="testpass123"
        )
        request = self.create_request(user=new_user)

        mixin = WorkspaceMembershipMixin()
        memberships = mixin._get_user_memberships(request)

        self.assertEqual(memberships, {})
        mock_membership_service.get_comprehensive_user_data.assert_called_once_with(
            new_user.id
        )

    def test_category_workspace_with_none_version(self):
        """Test CategoryWorkspaceMixin with None version."""
        request = self.create_request(workspace=self.workspace1)
        serializer = self.create_serializer_with_mixin(
            CategoryWorkspaceMixin, context={"request": request}
        )

        class MockInstance:
            version = None

        serializer.instance = MockInstance()
        result = serializer.validate({"version": None})

        self.assertEqual(result, {"version": None})
