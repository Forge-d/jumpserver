# apps/authentication/urls/oidc.py
from django.urls import path
from authentication.views.grydd_iam import (
    IAMLoginView,
    IAMCallbackView,
    IAMLogoutView,
    IAMStepUpView,
)

urlpatterns = [
    path('login/', IAMLoginView.as_view(), name='iam-login'),
    path('callback/', IAMCallbackView.as_view(), name='iam-callback'),
    path('logout/', IAMLogoutView.as_view(), name='iam-logout'),
    # Action-level MFA re-verification (step-up): called when CONFIRM TTL expires
    # mid-session and the user needs to re-prove their second factor via IAM.
    path('stepup/', IAMStepUpView.as_view(), name='iam-stepup'),
]