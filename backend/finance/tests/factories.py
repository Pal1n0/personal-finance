"""
Test factories for financial management system models.
"""
import factory
from django.contrib.auth import get_user_model
from django.utils import timezone
from factory.django import DjangoModelFactory
from faker import Faker

from finance.models import (
    UserSettings, Workspace, WorkspaceMembership, WorkspaceSettings,
    ExpenseCategoryVersion, IncomeCategoryVersion, ExpenseCategory, IncomeCategory,
    ExchangeRate, Transaction, TransactionDraft
)

fake = Faker()
User = get_user_model()


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User

    username = factory.Sequence(lambda n: f"user_{n}")
    email = factory.Sequence(lambda n: f"user_{n}@example.com")
    password = factory.PostGenerationMethodCall('set_password', 'testpass123')

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Override to use create_user method for proper password handling."""
        manager = cls._get_manager(model_class)
        return manager.create_user(*args, **kwargs)


class UserSettingsFactory(DjangoModelFactory):
    class Meta:
        model = UserSettings

    user = factory.SubFactory(UserFactory)
    language = 'en'


class WorkspaceFactory(DjangoModelFactory):
    class Meta:
        model = Workspace

    name = factory.Sequence(lambda n: f"Workspace {n}")
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    owner = factory.SubFactory(UserFactory)
    is_active = True

    @factory.post_generation
    def members(self, create, extracted, **kwargs):
        if not create:
            return

        # Always add owner as member if not already present
        if not WorkspaceMembership.objects.filter(workspace=self, user=self.owner).exists():
            WorkspaceMembershipFactory(workspace=self, user=self.owner, role='admin')

        if extracted:
            for user in extracted:
                if not WorkspaceMembership.objects.filter(workspace=self, user=user).exists():
                    WorkspaceMembershipFactory(workspace=self, user=user)


class WorkspaceMembershipFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = WorkspaceMembership

    workspace = factory.SubFactory(WorkspaceFactory)
    user = factory.SubFactory(UserFactory)
    role = 'member'
    joined_at = factory.LazyFunction(timezone.now)

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        # Use get_or_create to avoid duplicates
        workspace = kwargs.get('workspace')
        user = kwargs.get('user')
        
        if workspace and user:
            membership, created = model_class.objects.get_or_create(
                workspace=workspace,
                user=user,
                defaults=kwargs
            )
            return membership
        return super()._create(model_class, *args, **kwargs)


class WorkspaceSettingsFactory(DjangoModelFactory):
    class Meta:
        model = WorkspaceSettings

    workspace = factory.SubFactory(WorkspaceFactory)
    domestic_currency = 'EUR'
    fiscal_year_start = 1
    display_mode = 'month'
    accounting_mode = False


class ExpenseCategoryVersionFactory(DjangoModelFactory):
    class Meta:
        model = ExpenseCategoryVersion

    workspace = factory.SubFactory(WorkspaceFactory)
    name = factory.Sequence(lambda n: f"Expense Version {n}")
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    created_by = factory.SubFactory(UserFactory)
    is_active = True


class IncomeCategoryVersionFactory(DjangoModelFactory):
    class Meta:
        model = IncomeCategoryVersion

    workspace = factory.SubFactory(WorkspaceFactory)
    name = factory.Sequence(lambda n: f"Income Version {n}")
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    created_by = factory.SubFactory(UserFactory)
    is_active = True


class ExpenseCategoryFactory(DjangoModelFactory):
    class Meta:
        model = ExpenseCategory

    version = factory.SubFactory(ExpenseCategoryVersionFactory)
    name = factory.Sequence(lambda n: f"Expense Category {n}")
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    level = 1
    is_active = True


class IncomeCategoryFactory(DjangoModelFactory):
    class Meta:
        model = IncomeCategory

    version = factory.SubFactory(IncomeCategoryVersionFactory)
    name = factory.Sequence(lambda n: f"Income Category {n}")
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    level = 1
    is_active = True


class ExchangeRateFactory(DjangoModelFactory):
    class Meta:
        model = ExchangeRate

    currency = factory.Iterator(['USD', 'GBP', 'CHF', 'PLN', 'CZK'])
    rate_to_eur = factory.LazyAttribute(lambda _: fake.pydecimal(left_digits=1, right_digits=6, min_value=0.5, max_value=1.5))
    date = factory.LazyFunction(timezone.now().date)


class TransactionFactory(DjangoModelFactory):
    class Meta:
        model = Transaction

    user = factory.SubFactory(UserFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    type = factory.Iterator(['income', 'expense'])
    original_amount = factory.LazyAttribute(lambda _: fake.pydecimal(left_digits=4, right_digits=2, min_value=1, max_value=10000))
    original_currency = 'EUR'
    amount_domestic = factory.LazyAttribute(lambda obj: obj.original_amount)
    date = factory.LazyFunction(timezone.now().date)
    month = factory.LazyAttribute(lambda obj: obj.date.replace(day=1))
    tags = factory.LazyFunction(lambda: [fake.word() for _ in range(2)])
    note_manual = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=100))

    @factory.post_generation
    def set_category(self, create, extracted, **kwargs):
        if not create:
            return

        if self.type == 'expense':
            self.expense_category = ExpenseCategoryFactory(
                version__workspace=self.workspace
            )
        else:
            self.income_category = IncomeCategoryFactory(
                version__workspace=self.workspace
            )
        self.save()


class TransactionDraftFactory(DjangoModelFactory):
    class Meta:
        model = TransactionDraft

    user = factory.SubFactory(UserFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    draft_type = factory.Iterator(['income', 'expense'])
    transactions_data = factory.LazyFunction(lambda: [
        {
            'type': 'expense',
            'original_amount': '100.00',  # ← STRING!
            'original_currency': 'EUR',
            'date': timezone.now().date().isoformat(),
            'note_manual': 'Test transaction'
        }
    ])