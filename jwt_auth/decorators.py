import functools
from django.http import HttpResponse


def login_required(func):
    @functools.wraps(func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated: return func(request, *args, **kwargs)
        response = HttpResponse(status=401)
        response['WWW-Authenticate'] = 'Bearer realm="Site for only logged in users"'
        return response

    return wrapper
