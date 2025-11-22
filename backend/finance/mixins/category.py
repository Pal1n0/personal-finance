"""
This module provides mixins related to category functionalities.
"""

from collections import deque


class CategoryDescendantsMixin:
    """
    A mixin for category models to provide a method for getting all descendants.
    """

    def get_descendants(self, include_self=False):
        """
        Retrieves all descendant categories for a given category instance
        using a breadth-first search (BFS) approach.

        This method traverses the category tree downwards from the current
        category, collecting all children, grandchildren, and so on.

        Args:
            include_self (bool): If True, the instance category will be included
                                 in the result set. Defaults to False.

        Returns:
            set: A set of category instances representing the full descendant tree.
                 Returns an empty set if the category has no children.
        """
        descendants = set()
        if include_self:
            descendants.add(self)

        # A deque is used for an efficient queue implementation (BFS)
        queue = deque(self.children.all())

        while queue:
            child = queue.popleft()
            if child not in descendants:
                descendants.add(child)
                # Add the children of the current child to the queue for further processing
                queue.extend(child.children.all())

        return descendants
