from django.urls import path
from authentication.views import *

urlpatterns = [
    path('sign-up/<str:role>/', UserSignUpView.as_view(), name='sign-up'),

    path('verify-otp/<str:uid>/<str:token>/',
         OtpVerificationView.as_view(), name='verify-otp'),
    path('resend-otp/<str:uid>/<str:token>/',
         ResendOtpView.as_view(), name='resend-otp'),

    path('sign-in/<str:role>/', UserSignInView.as_view(), name='sign-in'),

    path('forgot-password/',
         ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/<str:uid>/<str:token>/',
         ResetPasswordView.as_view(), name='reset-password'),

    path('refresh/', CustomTokenRefreshView.as_view(),
         name='token-refresh'),

]

