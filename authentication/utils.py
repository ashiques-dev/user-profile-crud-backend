from django.utils.crypto import get_random_string
from datetime import timedelta
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from authentication.models import *
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.utils import timezone

from rest_framework_simplejwt.tokens import RefreshToken
from authentication.tasks import *


def generate_otp_and_validity():
    otp = get_random_string(length=6, allowed_chars='9876543210')
    valid_until = timezone.localtime() + timedelta(minutes=10)
    return otp, valid_until


def generate_uid_and_token(user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return uid, token


def check_uid_token(uid, token, is_password_reset=False):
    try:
        pk = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=pk)
        if is_password_reset:
            reset_link = PasswordReset.objects.get(
                user=user, uid=uid, token=token)
            return user, reset_link

        else:
            verify_otp = OTPVerification.objects.get(
                user=user, uid=uid, token=token,)
            return user, verify_otp
    except Exception:
        return None, None


def generate_token(user, role):
    refresh = RefreshToken.for_user(user)
    refresh['role'] = role
    refresh['user'] = user.username
    refresh['is_blocked'] = False
    access = str(refresh.access_token)
    refresh = str(refresh)
    return refresh, access


def send_verification_mail(user):
    otp, valid_until = generate_otp_and_validity()
    uid, token = generate_uid_and_token(user)

    print('utils', valid_until)

    auth_send_email.delay(
        user.username, user.email, uid, token, valid_until,
        otp=otp)

    user_otp, created = OTPVerification.objects.get_or_create(user=user,  defaults={
        'otp': otp, 'token': token, 'valid_until': valid_until, 'uid': uid})

    if not created:
        user_otp.otp = otp
        user_otp.uid = uid
        user_otp.token = token
        user_otp.valid_until = valid_until
        user_otp.save()


def change_password(user, for_html):
    valid_until = timezone.localtime() + timedelta(minutes=20)
    uid, token = generate_uid_and_token(user)

    auth_send_email.delay(
        user.username, user.email,  uid, token, valid_until, for_html)

    reset_link, created = PasswordReset.objects.get_or_create(user=user,  defaults={
        'token': token, 'valid_until': valid_until, 'uid': uid})

    if not created:
        reset_link.uid = uid
        reset_link.token = token
        reset_link.valid_until = valid_until
        reset_link.save()

    role = 'merchant' if user.is_merchant else (
        'superuser' if user.is_superuser else 'user')

    return role
