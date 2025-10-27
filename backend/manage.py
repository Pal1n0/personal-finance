#!/usr/bin/env python
"""
Django's command-line utility for administrative tasks.

This script serves as the main entry point for Django management commands.
It handles setting up the Django environment and executing commands from
the command line with proper environment configuration.
"""

import os
import sys


def main():
    """
    Run administrative tasks for Django.
    
    This function:
    1. Checks for DJANGO_SETTINGS_MODULE environment variable
    2. Sets a default if not specified
    3. Executes the Django command from the command line
    4. Provides helpful error messages if Django is not properly installed
    """
    # Determine the settings module to use, defaulting to development
    settings_module = os.environ.get('DJANGO_SETTINGS_MODULE', 'core.settings.dev')
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)
    
    try:
        # Import and execute Django management commands
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        # Provide helpful error message if Django is not available
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    
    # Execute the command with provided arguments
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()