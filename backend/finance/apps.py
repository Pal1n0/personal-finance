from django.apps import AppConfig


class FinanceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    # Application name (Python path)
    name = "finance"

    def ready(self):
        """Import signals to ensure they are connected when the app is ready."""
        import finance.signals
