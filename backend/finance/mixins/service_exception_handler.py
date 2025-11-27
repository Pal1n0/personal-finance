"""
Production-grade service exception handler mixin.
Provides unified exception handling for service layer operations with comprehensive logging
and proper DRF exception propagation.
"""

import logging

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.exceptions import PermissionDenied as DRFPermissionDenied
from rest_framework.exceptions import ValidationError as DRFValidationError

logger = logging.getLogger(__name__)


class ServiceExceptionHandlerMixin:
    """
    Production-ready mixin for handling service layer exceptions in views.

    Features:
    - Unified exception handling for all service calls
    - Comprehensive audit logging with structured context
    - Proper DRF exception propagation with HTTP status codes
    - Support for Django ValidationError and DRF exceptions
    - Automatic exception translation between layers

    Usage:
        result = self.handle_service_call(
            self.transaction_service.bulk_create_transactions,
            transactions_data, workspace, user
        )
    """

    def handle_service_call(self, service_call, *args, **kwargs):
        """
        Execute service call with comprehensive exception handling and logging.

        Args:
            service_call: Service method to execute
            *args: Positional arguments for service call
            **kwargs: Keyword arguments for service call

        Returns:
            Any: Result from service call

        Raises:
            DRFValidationError: For business rule violations
            DRFPermissionDenied: For authorization failures
            APIException: For unexpected service errors
        """
        # Extract context for logging
        service_name = getattr(service_call, "__self__", self).__class__.__name__
        method_name = getattr(service_call, '__name__', str(service_call))
        request = getattr(self, "request", None)
        user_id = getattr(getattr(request, "user", None), "id", None) if request else None
        target_user_id = getattr(getattr(request, "target_user", None), "id", None) if request else None

        logger.debug(
            "Service call execution initiated",
            extra={
                "service_name": service_name,
                "method_name": method_name,
                "user_id": user_id,
                "target_user_id": target_user_id,
                "args_count": len(args),
                "kwargs_keys": list(kwargs.keys()),
                "action": "service_call_start",
                "component": "ServiceExceptionHandlerMixin",
            },
        )

        try:
            result = service_call(*args, **kwargs)

            logger.debug(
                "Service call completed successfully",
                extra={
                    "service_name": service_name,
                    "method_name": method_name,
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "result_type": type(result).__name__,
                    "action": "service_call_success",
                    "component": "ServiceExceptionHandlerMixin",
                },
            )

            return result

        except DRFValidationError as e:
            # Re-raise DRF validation errors directly
            logger.warning(
                "Service validation error (DRF)",
                extra={
                    "service_name": service_name,
                    "method_name": method_name,
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "error_type": "DRFValidationError",
                    "error_detail": e.detail,
                    "error_code": getattr(e, "code", "invalid"),
                    "action": "service_validation_error_drf",
                    "component": "ServiceExceptionHandlerMixin",
                    "severity": "medium",
                },
            )
            raise

        except DjangoValidationError as e:
            # Convert Django ValidationError to DRF ValidationError
            error_detail = e.message if hasattr(e, "message") else str(e)
            error_messages = e.messages if hasattr(e, "messages") else [error_detail]

            logger.warning(
                "Service validation error (Django)",
                extra={
                    "service_name": service_name,
                    "method_name": method_name,
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "error_type": "DjangoValidationError",
                    "error_messages": error_messages,
                    "action": "service_validation_error_django",
                    "component": "ServiceExceptionHandlerMixin",
                    "severity": "medium",
                },
            )

            raise DRFValidationError(error_messages)

        except DRFPermissionDenied as e:
            # Re-raise DRF permission errors directly
            logger.warning(
                "Service permission denied (DRF)",
                extra={
                    "service_name": service_name,
                    "method_name": method_name,
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "error_type": "DRFPermissionDenied",
                    "error_detail": e.detail,
                    "error_code": getattr(e, "code", "permission_denied"),
                    "action": "service_permission_denied_drf",
                    "component": "ServiceExceptionHandlerMixin",
                    "severity": "high",
                },
            )
            raise

        except PermissionError as e:
            # Convert Python PermissionError to DRF PermissionDenied
            logger.warning(
                "Service permission denied (Python)",
                extra={
                    "service_name": service_name,
                    "method_name": method_name,
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "error_type": "PermissionError",
                    "error_message": str(e),
                    "action": "service_permission_denied_python",
                    "component": "ServiceExceptionHandlerMixin",
                    "severity": "high",
                },
            )

            raise DRFPermissionDenied(str(e))

        except APIException as e:
            # Re-raise DRF API exceptions directly
            logger.error(
                "Service API exception",
                extra={
                    "service_name": service_name,
                    "method_name": method_name,
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "error_type": "APIException",
                    "error_detail": e.detail,
                    "error_code": getattr(e, "code", "error"),
                    "status_code": e.status_code,
                    "action": "service_api_exception",
                    "component": "ServiceExceptionHandlerMixin",
                    "severity": "high",
                },
            )
            raise

        except Exception as e:
            # Handle unexpected service errors
            error_type = type(e).__name__
            error_message = str(e)

            logger.error(
                "Service operation failed unexpectedly",
                extra={
                    "service_name": service_name,
                    "method_name": method_name,
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "error_type": error_type,
                    "error_message": error_message,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                    "action": "service_unexpected_error",
                    "component": "ServiceExceptionHandlerMixin",
                    "severity": "critical",
                },
                exc_info=True,  # Include full stack trace
            )

            # Create a generic API exception to prevent information leakage
            raise APIException(detail="Service operation failed", code="service_error")

    def handle_service_call_with_context(
        self, service_call, extra_context=None, *args, **kwargs
    ):
        """
        Execute service call with additional context for enhanced logging.

        Args:
            service_call: Service method to execute
            extra_context: Additional context for logging
            *args: Positional arguments for service call
            **kwargs: Keyword arguments for service call

        Returns:
            Any: Result from service call
        """
        context = extra_context or {}

        # Add request context if available
        request = getattr(self, "request", None)
        if request:
            context.update(
                {
                    "request_user_id": getattr(request, "user.id", None),
                    "target_user_id": getattr(request, "target_user.id", None),
                    "is_admin_impersonation": getattr(
                        request, "is_admin_impersonation", False
                    ),
                }
            )

        logger.debug(
            "Service call with context initiated",
            extra={
                "service_name": getattr(
                    service_call, "__self__", self
                ).__class__.__name__,
                "method_name": service_call.__name__,
                "extra_context": context,
                "action": "service_call_with_context_start",
                "component": "ServiceExceptionHandlerMixin",
            },
        )

        try:
            result = self.handle_service_call(service_call, *args, **kwargs)

            logger.debug(
                "Service call with context completed",
                extra={
                    "service_name": getattr(
                        service_call, "__self__", self
                    ).__class__.__name__,
                    "method_name": service_call.__name__,
                    "extra_context": context,
                    "action": "service_call_with_context_success",
                    "component": "ServiceExceptionHandlerMixin",
                },
            )

            return result

        except Exception as e:
            # Enhance the exception context with additional information
            context["error_type"] = type(e).__name__
            context["error_message"] = str(e)

            logger.error(
                "Service call with context failed",
                extra={
                    "service_name": getattr(
                        service_call, "__self__", self
                    ).__class__.__name__,
                    "method_name": service_call.__name__,
                    "extra_context": context,
                    "action": "service_call_with_context_failed",
                    "component": "ServiceExceptionHandlerMixin",
                    "severity": "high",
                },
                exc_info=True,
            )

            # Re-raise the original exception
            raise
