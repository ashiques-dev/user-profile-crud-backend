from rest_framework_simplejwt.settings import api_settings
from rest_framework import serializers
from authentication.models import User
import re
from rest_framework_simplejwt.tokens import RefreshToken

username_regex = r'^(?=.*[a-zA-Z])[a-zA-Z0-9_.-]{4,30}$'
email_regex = r'^[a-zA-Z0-9._]{2,30}@[a-zA-Z0-9.-]{2,30}\.[a-zA-Z]{2,30}$'
password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z0-9!@#$%^&*()_+=\-[\]{}|\\:;"\'<>,.?/~]{8,30}$'
combined_regex = r'^(?=.*[a-zA-Z])[a-zA-Z0-9_.-]{4,30}$|^[a-zA-Z0-9._]{2,30}@[a-zA-Z0-9.-]{2,30}\.[a-zA-Z]{2,30}$'
otp_regex = r"^\d{6}$"


def validate_regex(value, pattern, error_message):
    if not re.match(pattern, value):
        raise serializers.ValidationError(error_message)
    return value


class UserSignUpSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username',  'email', 'password',
                  'confirm_password')
        extra_kwargs = {'password': {'write_only': True},
                        'confirm_password': {'write_only': True}}

    def validate_username(self, value):
        return validate_regex(value, username_regex,
                              'Username must be 4-30 characters long and contain only alphanumeric characters.'
                              )

    def validate_email(self, value):
        return validate_regex(value, email_regex,
                              'Please enter a valid email address.'
                              )

    def validate_password(self, value):
        return validate_regex(value, password_regex,
                              'Password must be 8-30 characters long and include at least one lowercase letter, one uppercase letter, and one number.'
                              )

    def validate_confirm_password(self, value):
        password = self.initial_data.get('password')
        if value != password:
            raise serializers.ValidationError(
                "Passwords don't match. Please make sure both password fields are identical."
            )
        return value


class UserOtpVerificationSerializer(serializers.Serializer):
    otp = serializers.IntegerField(write_only=True)




class ForgotPasswordSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate_username(self, value):
        return validate_regex(value, combined_regex,
                              'Please provide a valid username or email.'
                              )


class UserSignInSerializer(ForgotPasswordSerializer):
    password = serializers.CharField()

    def validate_password(self, value):
        return validate_regex(value, password_regex,
                              'Password must be 8-30 characters long and include at least one lowercase letter, one uppercase letter, and one number.'
                              )


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate_password(self, value):
        return validate_regex(value, password_regex,
                              'Password must be 8-30 characters long and include at least one lowercase letter, one uppercase letter, and one number.'
                              )

    def validate_confirm_password(self, value):
        password = self.initial_data.get('password')
        if value != password:
            raise serializers.ValidationError(
                'Password mismatch.'
            )
        return value


class CustomTokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField(read_only=True)
    token_class = RefreshToken

    def validate(self, attrs):
        refresh = self.token_class(attrs["refresh"])

        user_id = refresh.payload.get('user_id')

        user = User.objects.get(id=user_id)

        role = 'merchant' if user.is_merchant else (
            'superuser' if user.is_superuser else 'user')

        refresh['role'] = role
        refresh['user'] = user.username
        refresh['is_blocked'] = user.is_blocked

        data = {"access": str(refresh.access_token)}

        if api_settings.ROTATE_REFRESH_TOKENS:
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    # Attempt to blacklist the given refresh token
                    refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, `blacklist` method will
                    # not be present
                    pass

            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()

            data["refresh"] = str(refresh)

        return data
