"""
Utility functions for Django settings configuration.

This module provides environment-specific configuration loading functionality
using python-decouple for managing environment variables across different
deployment environments.
"""

import os
from pathlib import Path

from decouple import RepositoryEnv
from decouple import config as default_config


def load_environment_config(environment):
    """
    Load environment-specific configuration from the appropriate .env file.

    Args:
        environment (str): The target environment ('development', 'pre-production', 'production')

    Returns:
        function: A config function that can be used to retrieve environment variables
                 from the appropriate .env file

    Raises:
        FileNotFoundError: If the specified environment file doesn't exist (falls back to default)
    """
    # Map environment names to their corresponding .env files
    env_files = {
        "development": ".env.dev",
        "pre-production": ".env.ppe",
        "production": ".env.production",
    }

    # Determine the correct .env file for the specified environment
    env_file_name = env_files.get(environment, ".env")
    env_file_path = Path(__file__).resolve().parent.parent.parent.parent / env_file_name

    # Load environment-specific configuration if file exists
    if env_file_path.exists():
        print(f"✓ Loading environment: {environment} from {env_file_name}")
        # Create a new config function with RepositoryEnv for the specific environment file
        from decouple import Config, RepositoryEnv

        config_obj = Config(RepositoryEnv(env_file_path))
        return config_obj
    else:
        # Fall back to default configuration if environment file not found
        print(f"✗ Warning: {env_file_name} not found, using default config")
        return default_config
