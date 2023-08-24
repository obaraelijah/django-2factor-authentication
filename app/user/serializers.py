from datetime import datetime, timezone
from io import BytesIO

import pyotp
import qrcode
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.core.files.base import ContentFile
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers
from rest_framework.serializers import ModelSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "password", "qr_code"]

        extra_kwargs = {
            "password": {"write_only": True},
            "qr_code": {"read_only": True},
        }

    def validate(self, attrs: dict):
        email = attrs.get("email").lower().strip()
        if get_user_model().objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError({"phone": "Email already exists!"})
        return super().validate(attrs)

    def create(self, validated_data: dict):
        """creates a QR code image for two-factor authentication, and associates it with the user. This approach ensures that the user 
        is set up for two-factor authentication immediately upon registration.
        """
        otp_base32 = pyotp.random_base32()
        email = validated_data.get("email")
        otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
            name=email.lower(), issuer_name="Elijah Samson"
        )
        stream = BytesIO()
        image = qrcode.make(f"{otp_auth_url}")
        image.save(stream)
        user_info = {
            "email": validated_data.get("email"),
            "password": make_password(validated_data.get("password")),
            "otp_base32": otp_base32,
        }
        user: User = get_user_model().objects.create(**user_info)
        user.qr_code = ContentFile(
            stream.getvalue(), name=f"qr{get_random_string(10)}.png"
        )
        user.save()

        return user