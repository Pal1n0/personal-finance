"""
Unit tests for the TagService.
These tests focus on the business logic of tag management,
ensuring correctness without involving the full API stack.
"""

import pytest
from rest_framework.exceptions import ValidationError

from finance.models import Tags, Transaction
from finance.services.tag_service import TagService


@pytest.mark.django_db
def test_get_or_create_tags_creates_new_tags(test_workspace):
    """
    Test that get_or_create_tags correctly creates tags that do not exist.
    """
    tag_names = ["new-tag-1", "  New-Tag-2  "]

    assert Tags.objects.count() == 0

    tags = TagService.get_or_create_tags(test_workspace, tag_names)

    assert len(tags) == 2
    assert Tags.objects.count() == 2

    created_tag_names = {tag.name for tag in tags}
    assert "new-tag-1" in created_tag_names
    assert "new-tag-2" in created_tag_names  # Check for lowercase and stripped


@pytest.mark.django_db
def test_get_or_create_tags_returns_existing_tags(test_workspace):
    """
    Test that get_or_create_tags returns existing tags without creating duplicates.
    """
    existing_tag = Tags.objects.create(workspace=test_workspace, name="existing")
    tag_names = ["existing", "EXISTING"]

    assert Tags.objects.count() == 1

    tags = TagService.get_or_create_tags(test_workspace, tag_names)

    assert len(tags) == 1
    assert tags[0].id == existing_tag.id
    assert Tags.objects.count() == 1


@pytest.mark.django_db
def test_get_or_create_tags_with_empty_list(test_workspace):
    """
    Test get_or_create_tags with an empty list of tags.
    """
    tags = TagService.get_or_create_tags(test_workspace, [])
    assert tags == []
    assert Tags.objects.count() == 0


@pytest.mark.django_db
def test_get_or_create_tags_mixed_existing_and_new(test_workspace):
    """
    Test get_or_create_tags with a mix of existing and new tags.
    """
    Tags.objects.create(workspace=test_workspace, name="existing")
    tag_names = ["existing", "new-tag"]

    tags = TagService.get_or_create_tags(test_workspace, tag_names)

    assert len(tags) == 2
    assert Tags.objects.count() == 2
    tag_names = {tag.name for tag in tags}
    assert "existing" in tag_names
    assert "new-tag" in tag_names


@pytest.mark.django_db
def test_assign_tags_to_transaction(expense_transaction_without_tags):
    """
    Test that tags can be correctly assigned to a transaction, replacing any existing ones.
    """
    # Add an initial tag
    initial_tag = Tags.objects.create(
        workspace=expense_transaction_without_tags.workspace, name="initial"
    )
    expense_transaction_without_tags.tags.add(initial_tag)
    assert expense_transaction_without_tags.tags.count() == 1

    new_tag_names = ["food", "urgent"]
    TagService.assign_tags_to_transaction(expense_transaction_without_tags, new_tag_names)

    expense_transaction_without_tags.refresh_from_db()
    assert expense_transaction_without_tags.tags.count() == 2
    tag_names = {tag.name for tag in expense_transaction_without_tags.tags.all()}
    assert "food" in tag_names
    assert "urgent" in tag_names
    assert "initial" not in tag_names  # Old tag should be gone


@pytest.mark.django_db
def test_assign_tags_to_transaction_with_empty_list(expense_transaction_without_tags):
    """
    Test assign_tags_to_transaction with an empty list of tags.
    """
    initial_tag = Tags.objects.create(
        workspace=expense_transaction_without_tags.workspace, name="initial"
    )
    expense_transaction_without_tags.tags.add(initial_tag)
    assert expense_transaction_without_tags.tags.count() == 1

    TagService.assign_tags_to_transaction(expense_transaction_without_tags, [])
    expense_transaction_without_tags.refresh_from_db()
    assert expense_transaction_without_tags.tags.count() == 0


@pytest.mark.django_db
def test_assign_tags_to_transaction_with_no_initial_tags(expense_transaction_without_tags):
    """
    Test assign_tags_to_transaction on a transaction with no initial tags.
    """
    assert expense_transaction_without_tags.tags.count() == 0
    new_tag_names = ["food", "urgent"]
    TagService.assign_tags_to_transaction(expense_transaction_without_tags, new_tag_names)
    expense_transaction_without_tags.refresh_from_db()
    assert expense_transaction_without_tags.tags.count() == 2
    tag_names = {tag.name for tag in expense_transaction_without_tags.tags.all()}
    assert "food" in tag_names
    assert "urgent" in tag_names


@pytest.mark.django_db
def test_update_tag_name(test_workspace):
    """
    Test that a tag's name can be updated successfully.
    """
    tag = Tags.objects.create(workspace=test_workspace, name="old-name")
    updated_tag = TagService.update_tag(tag, "new-name")

    assert updated_tag.name == "new-name"
    tag.refresh_from_db()
    assert tag.name == "new-name"


@pytest.mark.django_db
def test_update_tag_with_same_name(test_workspace):
    """
    Test updating a tag with the same name.
    """
    tag = Tags.objects.create(workspace=test_workspace, name="same-name")
    updated_tag = TagService.update_tag(tag, "same-name")
    assert updated_tag.name == "same-name"


@pytest.mark.django_db
def test_update_tag_with_conflicting_normalized_name(test_workspace):
    """
    Test updating a tag to a name that conflicts after normalization.
    """
    Tags.objects.create(workspace=test_workspace, name="existing-name")
    tag_to_update = Tags.objects.create(workspace=test_workspace, name="to-be-updated")

    with pytest.raises(ValidationError):
        TagService.update_tag(tag_to_update, "  EXISTING-NAME  ")


@pytest.mark.django_db
def test_update_tag_to_conflicting_name_raises_error(test_workspace):
    """
    Test that updating a tag to a name that already exists raises a ValidationError.
    """
    Tags.objects.create(workspace=test_workspace, name="existing-name")
    tag_to_update = Tags.objects.create(workspace=test_workspace, name="to-be-updated")

    with pytest.raises(ValidationError):
        TagService.update_tag(tag_to_update, "existing-name")


@pytest.mark.django_db
def test_delete_tag(test_workspace):
    """
    Test that a tag can be deleted.
    """
    tag = Tags.objects.create(workspace=test_workspace, name="to-delete")
    assert Tags.objects.count() == 1

    TagService.delete_tag(tag)
    assert Tags.objects.count() == 0


@pytest.mark.django_db
def test_delete_tag_with_associated_transaction(expense_transaction_without_tags):
    """
    Test that deleting a tag associated with a transaction does not delete the transaction.
    """
    tag = Tags.objects.create(
        workspace=expense_transaction_without_tags.workspace, name="to-delete"
    )
    expense_transaction_without_tags.tags.add(tag)
    assert expense_transaction_without_tags.tags.count() == 1
    assert Transaction.objects.count() == 1
    assert Tags.objects.count() == 1

    TagService.delete_tag(tag)

    assert Tags.objects.count() == 0
    assert Transaction.objects.count() == 1
    expense_transaction_without_tags.refresh_from_db()
    assert expense_transaction_without_tags.tags.count() == 0
