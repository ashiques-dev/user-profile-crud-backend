from django.urls import path
from userprofile.views import *

urlpatterns = [
    path('', UserProfileView.as_view(), name='user-profile'),
]
