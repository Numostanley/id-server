from datetime import datetime

from django.contrib.auth.hashers import check_password
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ObjectDoesNotExist


# Create your models here.
class User(AbstractUser):
    _id = models.CharField(max_length=150)
    firstName = models.CharField(max_length=100)
    email = models.EmailField(max_length=250, unique=True)
    phoneNumber = models.CharField(max_length=18, unique=True)
    role = models.TextField()
    phoneNumberIntCode = models.CharField(max_length=30, default="+234 ")
    lastName = models.CharField(max_length=100)
    passwordHash = models.TextField()
    pin = models.TextField()
    address = models.TextField()

    emailVerified = models.BooleanField(default=False)
    phoneNumberVerified = models.BooleanField(default=False)
    passwordSet = models.BooleanField(default=False)

    dateOfBirth = models.DateField()
    dateJoined = models.DateTimeField(default=datetime.utcnow)
    updatedAt = models.DateTimeField(default=datetime.utcnow)

    def validate_password(self, password: str):
        return check_password(password, self.passwordHash)

    @staticmethod
    def get_user_by_email(email: str):
        try:
            return User.objects.get(email=email)
        except ObjectDoesNotExist:
            return None
