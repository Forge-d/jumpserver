from django.urls import path
from .views import IAMConfigView, IAMConfigSyncView

app_name = 'grydd_platform'

urlpatterns = [
    path('iam/', IAMConfigView.as_view(), name='iam-config'),
    path('iam/sync/', IAMConfigSyncView.as_view(), name='iam-sync'),
]