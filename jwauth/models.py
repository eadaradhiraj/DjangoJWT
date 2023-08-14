from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class User(AbstractUser):
    username=models.CharField(max_length=255, unique=True)
    password=models.CharField(max_length=255)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD='username'
    REQUIRED_FIELDS=[]

class Tasks(models.Model):
    taskname=models.CharField(max_length=100)
    completion=models.BooleanField(default=False)
    username = models.ForeignKey(User, on_delete=models.CASCADE)