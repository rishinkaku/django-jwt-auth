from django.db import models
from django.contrib.auth.models import User


class RefreshToken(models.Model):
    user = models.ForeignKey(User, models.CASCADE)
    id = models.UUIDField(unique=True, primary_key=True)
    pid = models.CharField(max_length=32, unique=True)
    expireAt = models.DateTimeField()
