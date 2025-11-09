import os
import sys
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()

class Command(BaseCommand):
    help = 'Validate all superusers have authorized emails and fix violations'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Automatically deactivate unauthorized superusers',
        )
        parser.add_argument(
            '--emails',
            nargs='+',
            help='Custom protected emails (overrides settings)',
        )

    def handle(self, *args, **options):
        # Get protected emails from settings or arguments
        protected_emails = options.get('emails') or getattr(settings, 'PROTECTED_SUPERUSER_EMAILS', [])
        
        if not protected_emails:
            self.stdout.write(
                self.style.ERROR('No protected emails defined in settings.PROTECTED_SUPERUSER_EMAILS')
            )
            return
        
        self.stdout.write(f"Protected emails: {', '.join(protected_emails)}")
        
        superusers = User.objects.filter(is_superuser=True)
        self.stdout.write(f"Found {superusers.count()} superusers")
        
        unauthorized_count = 0
        
        for user in superusers:
            if user.email not in protected_emails:
                unauthorized_count += 1
                self.stdout.write(
                    self.style.ERROR(f"❌ UNAUTHORIZED: {user.email} (ID: {user.id})")
                )
                
                if options['fix']:
                    # Deactivate superuser privileges
                    user.is_superuser = False
                    user.save()
                    self.stdout.write(
                        self.style.WARNING(f"   ↳ Fixed: removed superuser privileges")
                    )
            else:
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Authorized: {user.email}")
                )
        
        # Summary
        self.stdout.write("\n" + "="*50)
        if unauthorized_count > 0:
            self.stdout.write(
                self.style.ERROR(f"Found {unauthorized_count} unauthorized superusers")
            )
            if not options['fix']:
                self.stdout.write(
                    self.style.WARNING("Run with --fix to automatically deactivate them")
                )
        else:
            self.stdout.write(
                self.style.SUCCESS("✅ All superusers are authorized!")
            )