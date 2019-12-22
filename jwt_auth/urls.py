from django.urls import path
from .views import *

urlpatterns = [
    path('login', GetToken.as_view()),
    path('renew', RenewToken.as_view()),
    path('logout', Logout.as_view()),
    path('logouteverywhere', LogoutEverywhere.as_view()),
    path('changepassword',ChangePassword.as_view())
]
