from django.http import JsonResponse
from rest_framework import status

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

def custom_lockout_response(request, credentials):
    return JsonResponse({
        "detail": "Account temporarily locked due to too many failed login attempts."
    }, status=status.HTTP_403_FORBIDDEN)