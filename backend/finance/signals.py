# signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import WorkspaceSettings
from .services.transaction_service import TransactionService

