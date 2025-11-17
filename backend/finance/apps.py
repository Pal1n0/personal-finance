from django.apps import AppConfig


class FinanceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    # Application name (Python path)
    name = "finance"

    def ready(self):
        # ✅ Načítanie signálov
        # import finance.signals
        pass
