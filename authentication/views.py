from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from django.contrib.auth import authenticate, login

from authentication.tasks import *
from authentication.models import *
from authentication.serializers import *
from authentication.utils import *


class UserSignUpView(APIView):
    def post(self, request, role):
        serializer = UserSignUpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.validated_data.pop('confirm_password', None)

        user = User.objects.create_user(**serializer.validated_data)

        if role == 'merchant':
            user.is_merchant = True

        user.save()

        send_verification_mail(user)

        return Response({"message": 'Your account has been successfully created. Please check your email to verify your account.'}, status=status.HTTP_201_CREATED)


class OtpVerificationView(APIView):

    def get(self, request, uid, token):
        user, verify_otp = check_uid_token(uid, token)

        if not (user and verify_otp):
            return Response({'message': "The activation link is invalid."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'message': 'Good to go.'}, status=status.HTTP_200_OK)

    def post(self, request, uid, token):
        user, verify_otp = check_uid_token(uid, token)

        if not (user and verify_otp):
            return Response({'message': "The activation link is invalid"}, status=status.HTTP_400_BAD_REQUEST)
        if not verify_otp.valid_until >= timezone.now():
            return Response({"message": 'The OTP is expired. Try clicking on Resend OTP'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserOtpVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data['otp']

        if verify_otp.otp == otp:
            user.is_verified = True
            user.save()
            verify_otp.delete()

            role = 'merchant' if user.is_merchant else 'user'

            login(request, user)

            refresh, access = generate_token(user, role)

            return Response({'message': 'User successfully verified', 'role': role, 'refresh': refresh, 'access': access}, status=status.HTTP_200_OK)
        else:
            return Response({"message": 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


class ResendOtpView(APIView):
    def get(self, request, uid, token):
        user, verify_otp = check_uid_token(uid, token)

        if not (user and verify_otp):
            return Response({'message': "The activation link is invalid"}, status=status.HTTP_400_BAD_REQUEST)

        otp, valid_until = generate_otp_and_validity()

        auth_send_email.delay(user.username, user.email, uid, token, valid_until,
                              otp=otp)

        verify_otp.otp = otp
        verify_otp.valid_until = valid_until
        verify_otp.save()
        return Response({"message": 'OTP successfully resent. Please check your email.'}, status=status.HTTP_200_OK)


class UserSignInView(APIView):
    def post(self, request, role):
        serializer = UserSignInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            if '@' in username:
                temp_user = User.objects.get(email=username)
                username = temp_user.username
        except:
            return Response({"message": 'Invalid user credentials'}, status=status.HTTP_404_NOT_FOUND)

        user = authenticate(username=username, password=password)

        if user is not None:
            data = {}
            pos = 'merchant' if user.is_merchant else (
                'superuser' if user.is_superuser else 'user')

            if role != pos:
                data['pos'] = False

            elif not user.is_verified:
                send_verification_mail(user)
                data['not_verified'] = True

            elif user.is_blocked:
                data['is_blocked'] = True

            else:
                login(request, user)

                refresh, access = generate_token(user, role)

                data['role'] = role
                data['refresh'] = refresh
                data['access'] = access

            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"message": 'Invalid user credentials'}, status=status.HTTP_404_NOT_FOUND)


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        try:
            user = None
            if '@' in username:
                user = User.objects.get(email=username)
            else:
                user = User.objects.get(username=username)

        except:
            return Response({'message': 'user not found'}, status=status.HTTP_404_NOT_FOUND)

        role = change_password(user, 'reset-password')

        return Response({'role': role}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    def get(self, request, uid, token):
        user, reset_link = check_uid_token(uid, token, is_password_reset=True)

        if not (user and reset_link):
            return Response({'message': "The activation link is invalid"}, status=status.HTTP_400_BAD_REQUEST)
        if not reset_link.valid_until >= timezone.now():
            return Response({"message": 'The activation link is expired'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'message': 'Good to go.'}, status=status.HTTP_200_OK)

    def post(self, request, uid, token):
        user, reset_link = check_uid_token(uid, token, is_password_reset=True)

        if not (user and reset_link):
            return Response({'message': "The activation link is invalid"}, status=status.HTTP_400_BAD_REQUEST)
        if not reset_link.valid_until >= timezone.now():
            return Response({"message": 'The activation link is expired'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data['password']

        user.set_password(password)
        user.save()
        reset_link.delete()

        role = change_password(user, 'reset-success')

        return Response({'role': role}, status=status.HTTP_200_OK)


class CustomTokenRefreshView(APIView):
    def post(self, request):
        serializer = CustomTokenRefreshSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validated_data)
