from django.contrib.auth import authenticate


class JWTAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if 'Authorization' in request.headers and request.headers['Authorization'].split(" ")[0] == "Bearer":
            token = request.headers['Authorization'].split(" ")[1]
            user = authenticate(request, token=token)
            if user is not None:
                request.user = user
        return self.get_response(request)
