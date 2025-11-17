"""
ENHANCED Test factories for financial management system models.
Extended with workspace admin support and comprehensive test data.
"""

from datetime import date, timedelta

import factory
from django.contrib.auth import get_user_model
from django.utils import timezone
from factory.django import DjangoModelFactory
from faker import Faker

from finance.models import (ExchangeRate, ExpenseCategory,
                            ExpenseCategoryVersion, IncomeCategory,
                            IncomeCategoryVersion, Transaction,
                            TransactionDraft, UserSettings, Workspace,
                            WorkspaceAdmin, WorkspaceMembership,
                            WorkspaceSettings)

fake = Faker()
User = get_user_model()


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User
        skip_postgeneration_save = True

    username = factory.Sequence(lambda n: f"user_{n}")
    email = factory.Sequence(lambda n: f"user_{n}@example.com")
    password = factory.PostGenerationMethodCall("set_password", "testpass123")
    is_active = True
    first_name = factory.LazyAttribute(lambda _: fake.first_name())
    last_name = factory.LazyAttribute(lambda _: fake.last_name())

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Override to use create_user method for proper password handling."""
        manager = cls._get_manager(model_class)
        return manager.create_user(*args, **kwargs)

    @classmethod
    def create_superuser(cls, **kwargs):
        """Create a superuser for testing."""
        return User.objects.create_superuser(
            username=kwargs.get("username", "admin"),
            email=kwargs.get("email", "admin@example.com"),
            password=kwargs.get("password", "testpass123"),
        )


class UserSettingsFactory(DjangoModelFactory):
    class Meta:
        model = UserSettings

    user = factory.SubFactory(UserFactory)
    language = factory.Iterator(["en", "sk", "cs"])


class WorkspaceFactory(DjangoModelFactory):
    class Meta:
        model = Workspace
        skip_postgeneration_save = True

    name = factory.Sequence(lambda n: f"Workspace {n}")
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    owner = factory.SubFactory(UserFactory)
    is_active = True

    @factory.post_generation
    def members(self, create, extracted, **kwargs):
        if not create:
            return

        # Always add owner as OWNER member if not already present
        if not WorkspaceMembership.objects.filter(
            workspace=self, user=self.owner
        ).exists():
            WorkspaceMembershipFactory(workspace=self, user=self.owner, role="owner")

        if extracted:
            for user in extracted:
                if not WorkspaceMembership.objects.filter(
                    workspace=self, user=user
                ).exists():
                    WorkspaceMembershipFactory(workspace=self, user=user, **kwargs)


class WorkspaceMembershipFactory(DjangoModelFactory):
    class Meta:
        model = WorkspaceMembership

    workspace = factory.SubFactory(WorkspaceFactory)
    user = factory.SubFactory(UserFactory)
    role = factory.Iterator(["viewer", "editor", "owner"])
    joined_at = factory.LazyFunction(timezone.now)


class WorkspaceSettingsFactory(DjangoModelFactory):
    class Meta:
        model = WorkspaceSettings

    workspace = factory.SubFactory(WorkspaceFactory)
    domestic_currency = factory.Iterator(["EUR", "USD", "GBP", "CHF", "PLN"])
    fiscal_year_start = factory.Iterator([1, 4, 7, 10])  # Different start months
    display_mode = factory.Iterator(["month", "day"])
    accounting_mode = factory.Iterator([True, False])


class WorkspaceAdminFactory(DjangoModelFactory):
    class Meta:
        model = WorkspaceAdmin

    user = factory.SubFactory(UserFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    assigned_by = factory.SubFactory(UserFactory)
    is_active = True
    can_impersonate = True
    can_manage_users = True
    can_manage_categories = True
    can_manage_settings = True


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
    level = factory.Iterator([1, 2, 3, 4, 5])
    is_active = True

    @factory.post_generation
    def children(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for child in extracted:
                self.children.add(child)


class IncomeCategoryFactory(DjangoModelFactory):
    class Meta:
        model = IncomeCategory

    version = factory.SubFactory(IncomeCategoryVersionFactory)
    name = factory.Sequence(lambda n: f"Income Category {n}")
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    level = factory.Iterator([1, 2, 3, 4, 5])
    is_active = True

    @factory.post_generation
    def children(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for child in extracted:
                self.children.add(child)


class ExchangeRateFactory(DjangoModelFactory):
    class Meta:
        model = ExchangeRate

    currency = factory.Iterator(["USD", "GBP", "CHF", "PLN", "CZK"])
    rate_to_eur = factory.LazyAttribute(
        lambda _: fake.pydecimal(
            left_digits=1, right_digits=6, min_value=0.5, max_value=1.5
        )
    )
    date = factory.LazyFunction(
        lambda: fake.date_between(start_date="-30d", end_date="today")
    )


class TransactionFactory(DjangoModelFactory):
    class Meta:
        model = Transaction
        skip_postgeneration_save = True

    user = factory.SubFactory(UserFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    type = factory.Iterator(["income", "expense"])
    original_amount = factory.LazyAttribute(
        lambda _: fake.pydecimal(
            left_digits=4, right_digits=2, min_value=1, max_value=10000
        )
    )
    original_currency = factory.Iterator(["EUR", "USD", "GBP", "CHF"])
    amount_domestic = factory.LazyAttribute(lambda obj: obj.original_amount)
    date = factory.LazyFunction(
        lambda: fake.date_between(start_date="-30d", end_date="today")
    )
    month = factory.LazyAttribute(lambda obj: obj.date.replace(day=1))
    tags = factory.LazyFunction(lambda: [fake.word() for _ in range(2)])
    note_manual = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=100))
    note_auto = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=50))

    @factory.post_generation
    def set_category(self, create, extracted, **kwargs):
        if not create:
            return

        if self.type == "expense":
            self.expense_category = ExpenseCategoryFactory(
                version__workspace=self.workspace
            )
        else:
            self.income_category = IncomeCategoryFactory(
                version__workspace=self.workspace
            )
        if create:
            self.save()


class TransactionDraftFactory(DjangoModelFactory):
    class Meta:
        model = TransactionDraft

    user = factory.SubFactory(UserFactory)
    workspace = factory.SubFactory(WorkspaceFactory)
    draft_type = factory.Iterator(["income", "expense"])
    transactions_data = factory.LazyFunction(
        lambda: [
            {
                "type": "expense",
                "original_amount": str(
                    fake.pydecimal(
                        left_digits=3, right_digits=2, min_value=1, max_value=500
                    )
                ),
                "original_currency": "EUR",
                "date": fake.date_between(
                    start_date="-30d", end_date="today"
                ).isoformat(),
                "note_manual": fake.text(max_nb_chars=50),
                "tags": [fake.word() for _ in range(2)],
            }
            for _ in range(fake.random_int(min=1, max=5))
        ]
    )


# Specialized factories for specific test scenarios
class InactiveWorkspaceFactory(WorkspaceFactory):
    is_active = False


class LargeTransactionFactory(TransactionFactory):
    original_amount = factory.LazyAttribute(
        lambda _: fake.pydecimal(
            left_digits=6, right_digits=2, min_value=100000, max_value=1000000
        )
    )


class HistoricalExchangeRateFactory(ExchangeRateFactory):
    date = factory.LazyFunction(
        lambda: fake.date_between(start_date="-365d", end_date="-31d")
    )


class ComplexCategoryHierarchyFactory:
    """Factory for creating complex category hierarchies for testing."""

    @classmethod
    def create_expense_hierarchy(cls, version, levels=3, categories_per_level=2):
        """Create a complex expense category hierarchy."""
        categories = {}

        for level in range(1, levels + 1):
            level_categories = []
            for i in range(categories_per_level):
                category = ExpenseCategoryFactory(
                    version=version, name=f"Level {level} Expense {i+1}", level=level
                )
                level_categories.append(category)

                # Add children to previous level categories
                if level > 1 and categories.get(level - 1):
                    parent = categories[level - 1][i % len(categories[level - 1])]
                    parent.children.add(category)

            categories[level] = level_categories

        return categories

    @classmethod
    def create_income_hierarchy(cls, version, levels=3, categories_per_level=2):
        """Create a complex income category hierarchy."""
        categories = {}

        for level in range(1, levels + 1):
            level_categories = []
            for i in range(categories_per_level):
                category = IncomeCategoryFactory(
                    version=version, name=f"Level {level} Income {i+1}", level=level
                )
                level_categories.append(category)

                # Add children to previous level categories
                if level > 1 and categories.get(level - 1):
                    parent = categories[level - 1][i % len(categories[level - 1])]
                    parent.children.add(category)

            categories[level] = level_categories

        return categories


class BulkDataFactory:
    """Factory for creating bulk test data."""

    @classmethod
    def create_bulk_transactions(cls, user, workspace, count=50):
        """Create a large number of transactions for performance testing."""
        expense_version = ExpenseCategoryVersionFactory(workspace=workspace)
        income_version = IncomeCategoryVersionFactory(workspace=workspace)

        expense_categories = ExpenseCategoryFactory.create_batch(
            5, version=expense_version
        )
        income_categories = IncomeCategoryFactory.create_batch(
            5, version=income_version
        )

        transactions = []
        for i in range(count):
            is_expense = fake.boolean()
            transaction = TransactionFactory(
                user=user,
                workspace=workspace,
                type="expense" if is_expense else "income",
                expense_category=(
                    fake.random_element(expense_categories) if is_expense else None
                ),
                income_category=(
                    fake.random_element(income_categories) if not is_expense else None
                ),
                date=fake.date_between(start_date="-90d", end_date="today"),
            )
            transactions.append(transaction)

        return transactions

    @classmethod
    def create_bulk_exchange_rates(cls, days=30):
        """Create exchange rates for multiple days and currencies."""
        currencies = ["USD", "GBP", "CHF", "PLN", "CZK"]
        rates = []

        for i in range(days):
            rate_date = date.today() - timedelta(days=i)
            for currency in currencies:
                rate = ExchangeRateFactory(currency=currency, date=rate_date)
                rates.append(rate)

        return rates
