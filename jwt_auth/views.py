import datetime
import uuid
import jwt, secrets
from django.conf import settings
from django.contrib.auth import authenticate
from django.http.response import JsonResponse, HttpResponse
from django.views import View
from .exceptions import *
from .models import RefreshToken
from .decorators import *
from django.utils.decorators import method_decorator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

# get data from settings or set defaults
try:
    PRIVATE_KEY = settings.JWT_AUTH_PRIVATE_KEY
except:
    raise MissingPrivateKey('No rsa private key is defined in settings')

try:
    PUBLIC_KEY = settings.JWT_AUTH_PUBLIC_KEY
except:
    raise MissingPublicKey('No rsa public key is defined in settings')

try:
    SECRET = settings.JWT_AUTH_SECRET
except:
    SECRET = settings.SECRET_KEY

try:
    AT_EXPIRES_IN = settings.JWT_AUTH_ACCESS_TOKEN_EXPIRES_IN
except:
    AT_EXPIRES_IN = 3600

try:
    RT_EXPIRES_IN = settings.JWT_AUTH_REFRESH_TOKEN_EXPIRES_IN
except:
    RT_EXPIRES_IN = 7776000

rsa_key = RSA.importKey(PRIVATE_KEY)
cipher = PKCS1_OAEP.new(rsa_key)


class GetToken(View):
    def get(self, request, *args, **kwargs):
        return JsonResponse({'method': 'PKCS1', 'public_key': PUBLIC_KEY.decode()})

    def post(self, request, *args, **kwargs):
        username = request.POST.get("username", '')
        try:
            rawPassword = b64decode(request.POST.get("password", ''))
            password = cipher.decrypt(rawPassword)
        except:
            return JsonResponse({'error': 'Password decode error'}, status=400)
        user = authenticate(request, username=username, password=password)
        rtuuid = uuid.uuid4()
        pid = secrets.token_hex(32)

        if user:
            atPayload = {
                "id": user.id,
                "username": user.username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=AT_EXPIRES_IN),
                "refreshID": pid
            }
            at = jwt.encode(atPayload, SECRET).decode()

            rtPayload = {
                "id": str(rtuuid),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=RT_EXPIRES_IN)
            }
            rt = jwt.encode(rtPayload, SECRET).decode()

            RefreshToken.objects.create(id=rtuuid, expireAt=datetime.datetime.utcnow(
            ) + datetime.timedelta(seconds=RT_EXPIRES_IN), user=user, pid=pid)

            return JsonResponse({"access_token": at, "refresh_token": rt})
        else:
            return JsonResponse({'error': 'Wrong username or password'}, status=403)


class RenewToken(View):
    def post(self, request, *args, **kwargs):
        rt = request.POST.get("refresh_token", '')
        try:
            payload = jwt.decode(rt, settings.SECRET_KEY)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred during verifying the token: {e}'}, status=403)
        tm = RefreshToken.objects.filter(id=uuid.UUID(
            payload["id"]), expireAt__gte=datetime.datetime.utcnow())
        if tm.exists():
            atPayload = {
                "id": tm[0].user.id,
                "username": tm[0].user.username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=AT_EXPIRES_IN),
                "refreshID": tm[0].pid
            }
            at = jwt.encode(atPayload, SECRET).decode()

            rtPayload = {
                "id": payload['token'],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=RT_EXPIRES_IN)
            }
            rt = jwt.encode(rtPayload, SECRET).decode()

            tm.update(expireAt=datetime.datetime.utcnow() +
                               datetime.timedelta(seconds=RT_EXPIRES_IN))
            return JsonResponse({"access_token": at, "refresh_token": rt})
        else:
            return JsonResponse({'error': 'Invalid refresh token'}, status=403)


class Logout(View):
    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        token = request.headers['Authorization'].split(" ")[1]
        payload = jwt.decode(token, SECRET)
        RefreshToken.objects.get(pid=payload["refreshID"]).delete()
        return HttpResponse()


class LogoutEverywhere(View):
    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        RefreshToken.objects.filter(user=request.user).delete()
        return HttpResponse()


class ChangePassword(View):
    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        try:
            rawOldPassword = b64decode(request.POST.get("old_password", ''))
            oldpassword = cipher.decrypt(rawOldPassword)
            rawPassword = b64decode(request.POST.get("password", ''))
            password = cipher.decrypt(rawPassword)
        except:
            return JsonResponse({'error': 'Password decode error'}, status=400)
        token = request.headers['Authorization'].split(" ")[1]
        payload = jwt.decode(token, SECRET)
        user = authenticate(username=payload['username'], password=oldpassword)
        if user:
            user.set_password(password)
            user.save()
            RefreshToken.objects.filter(user=request.user).exclude(pid=payload['refreshID']).delete()
            return HttpResponse()
        return HttpResponse(status=401)

    def get(self, request, *args, **kwargs):
        return JsonResponse({'method': 'PKCS1', 'public_key': PUBLIC_KEY.decode()})
