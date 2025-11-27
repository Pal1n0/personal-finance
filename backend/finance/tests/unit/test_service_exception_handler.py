# finance/tests/unit/test_service_exception_handler.py

import logging
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import (
    APIException,
    PermissionDenied as DRFPermissionDenied,
    ValidationError as DRFValidationError,
)

from finance.mixins.service_exception_handler import ServiceExceptionHandlerMixin


class MockService:
    """A mock service to simulate different exception scenarios."""

    def method_success(self):
        return "success"

    def method_drf_validation_error(self):
        raise DRFValidationError("DRF validation error")

    def method_django_validation_error(self):
        raise DjangoValidationError("Django validation error")

    def method_drf_permission_denied(self):
        raise DRFPermissionDenied("DRF permission denied")

    def method_python_permission_error(self):
        raise PermissionError("Python permission error")

    def method_api_exception(self):
        raise APIException("API exception")

    def method_generic_exception(self):
        raise Exception("Generic service error")

class MockServiceWithContext:
    """A mock service that can be called by handle_service_call_with_context."""
    def method_with_context_raises(self):
        raise Exception("Error in method with context")


class TestServiceExceptionHandlerMixin:
    """Tests for ServiceExceptionHandlerMixin."""

    def setup_method(self, method):
        self.mixin_instance = ServiceExceptionHandlerMixin()
        self.mixin_instance.request = Mock()
        self.mixin_instance.request.user = Mock(id=1)
        self.mixin_instance.request.target_user = Mock(id=1)
        self.mock_service = MockService()

    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_success(self, mock_logger):
        """Test successful service call."""
        result = self.mixin_instance.handle_service_call(self.mock_service.method_success)
        assert result == "success"
        found_success_log = False
        for call_args, call_kwargs in mock_logger.debug.call_args_list:
            if call_args[0] == "Service call completed successfully":
                assert call_kwargs['extra']['service_name'] == 'MockService'
                assert call_kwargs['extra']['method_name'] == 'method_success'
                assert call_kwargs['extra']['user_id'] == self.mixin_instance.request.user.id
                assert call_kwargs['extra']['target_user_id'] == self.mixin_instance.request.target_user.id
                assert call_kwargs['extra']['component'] == 'ServiceExceptionHandlerMixin'
                assert call_kwargs['extra']['result_type'] == 'str'
                assert call_kwargs['extra']['action'] == 'service_call_success'
                found_success_log = True
                break
        assert found_success_log, "Expected 'Service call completed successfully' log not found."


    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_drf_validation_error(self, mock_logger):
        """Test DRFValidationError handling."""
        with pytest.raises(DRFValidationError, match="DRF validation error"):
            self.mixin_instance.handle_service_call(
                self.mock_service.method_drf_validation_error
            )
        mock_logger.warning.assert_called_once()
        assert "DRFValidationError" in mock_logger.warning.call_args[1]["extra"]["error_type"]


    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_django_validation_error(self, mock_logger):
        """Test DjangoValidationError handling."""
        with pytest.raises(DRFValidationError, match="Django validation error"):
            self.mixin_instance.handle_service_call(
                self.mock_service.method_django_validation_error
            )
        mock_logger.warning.assert_called_once()
        assert "DjangoValidationError" in mock_logger.warning.call_args[1]["extra"]["error_type"]


    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_drf_permission_denied(self, mock_logger):
        """Test DRFPermissionDenied handling."""
        with pytest.raises(DRFPermissionDenied, match="DRF permission denied"):
            self.mixin_instance.handle_service_call(
                self.mock_service.method_drf_permission_denied
            )
        mock_logger.warning.assert_called_once()
        assert "DRFPermissionDenied" in mock_logger.warning.call_args[1]["extra"]["error_type"]


    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_python_permission_error(self, mock_logger):
        """Test Python PermissionError handling."""
        with pytest.raises(DRFPermissionDenied, match="Python permission error"):
            self.mixin_instance.handle_service_call(
                self.mock_service.method_python_permission_error
            )
        mock_logger.warning.assert_called_once()
        assert "PermissionError" in mock_logger.warning.call_args[1]["extra"]["error_type"]


    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_api_exception(self, mock_logger):
        """Test APIException handling."""
        with pytest.raises(APIException, match="API exception"):
            self.mixin_instance.handle_service_call(
                self.mock_service.method_api_exception
            )
        mock_logger.error.assert_called_once()
        assert "APIException" in mock_logger.error.call_args[1]["extra"]["error_type"]


    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_generic_exception(self, mock_logger):
        """Test generic Exception handling."""
        with pytest.raises(APIException, match="Service operation failed"):
            self.mixin_instance.handle_service_call(
                self.mock_service.method_generic_exception
            )
        mock_logger.error.assert_called_once()
        assert "Exception" in mock_logger.error.call_args[1]["extra"]["error_type"]


    @patch("finance.mixins.service_exception_handler.logger")
    def test_handle_service_call_with_context_exception(self, mock_logger):
        """Test handle_service_call_with_context when an exception occurs."""
        self.mock_service_with_context = MockServiceWithContext()
        extra_context = {"test_key": "test_value"}

        with pytest.raises(APIException, match="Service operation failed"):
            self.mixin_instance.handle_service_call_with_context(
                self.mock_service_with_context.method_with_context_raises,
                extra_context=extra_context
            )
        assert mock_logger.error.call_count >= 1
        call_args, call_kwargs = mock_logger.error.call_args
        assert "error_message" in call_kwargs["extra"]["extra_context"]
        assert "test_key" in call_kwargs["extra"]["extra_context"]
