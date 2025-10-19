# users/utils.py
def get_axes_username(request, credentials):
    """
    Funkcia pre AXES_USERNAME_CALLABLE.
    Vráti username alebo email z credentials.
    """
    if not credentials:
        return None
    # vrátime username, ak je, inak email
    return credentials.get("username") or credentials.get("email")

