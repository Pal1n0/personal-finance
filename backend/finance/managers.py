# finance/managers.py
class UserScopedManager(models.Manager):
    def for_user(self, user, workspace=None):
        qs = self.filter(user=user)
        if workspace:
            qs = qs.filter(workspace=workspace)
        return qs