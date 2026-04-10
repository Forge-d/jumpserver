# apps/authentication/urls/oidc.py
from django.urls import path
from authentication.views.grydd_iam import (
    IAMLoginView,
    IAMCallbackView,
    IAMLogoutView,
)

urlpatterns = [
    path('login/', IAMLoginView.as_view(), name='iam-login'),
    path('callback/', IAMCallbackView.as_view(), name='iam-callback'),
    path('logout/', IAMLogoutView.as_view(), name='iam-logout'),
]