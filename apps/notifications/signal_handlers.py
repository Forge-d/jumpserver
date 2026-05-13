import inspect
from importlib import import_module

from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.functional import LazyObject

from common.decorators import on_transaction_commit
from common.utils import get_logger
from common.utils.connection import RedisPubSub
from notifications.backends import BACKEND
from users.models import User
from .models import MessageContent, SystemMsgSubscription, UserMsgSubscription
from .notifications import SystemMessage

logger = get_logger(__name__)


class NewSiteMsgSubPub(LazyObject):
    def _setup(self):
        self._wrapped = RedisPubSub('notifications.SiteMessageCome')


new_site_msg_chan = NewSiteMsgSubPub()


@receiver(post_save, sender=MessageContent)
@on_transaction_commit
def on_site_message_create(sender, instance, created, **kwargs):
    if not created:
        return
    logger.debug('New site msg created, publish it')
    user_ids = instance.users.all().values_list('id', flat=True)
    user_ids = [str(i) for i in user_ids]
    data = {
        'id': str(instance.id),
        'subject': instance.subject,
        'message': instance.message,
        'users': user_ids
    }
    new_site_msg_chan.publish(data)


@receiver(post_migrate, dispatch_uid='notifications.signal_handlers.create_system_messages')
def create_system_messages(app_config: AppConfig, **kwargs):
    try:
        notifications_module = import_module('.notifications', app_config.module.__package__)

        for name, obj in notifications_module.__dict__.items():
            if _should_skip_obj(name, obj):
                continue

            should_stop = _process_system_message(obj, app_config)
            if should_stop:
                return

    except ModuleNotFoundError:
        pass

def _should_skip_obj(name, obj):
    if name.startswith('_'):
        return True
    if not inspect.isclass(obj):
        return True
    if not issubclass(obj, SystemMessage):
        return True

    attrs = obj.__dict__
    return not (
        'message_type_label' in attrs and
        'category' in attrs and
        'category_label' in attrs
    )

def _process_system_message(obj, app_config):
    message_type = obj.get_message_type()
    sub, created = SystemMsgSubscription.objects.get_or_create(
        message_type=message_type
    )

    if not created:
        return True  # signal to stop outer function

    try:
        obj.post_insert_to_db(sub)
        logger.info(
            f'Create MsgSubscription: package={app_config.module.__package__} type={message_type}'
        )
    except Exception:
        pass

    return False

@receiver(post_save, sender=User)
def on_user_post_save(sender, instance, created, **kwargs):
    if not created:
        return
    receive_backends = []
    # Todo: IDE 识别不了 get_account
    for backend in BACKEND:
        if backend.get_account(instance):
            receive_backends.append(backend)
    UserMsgSubscription.objects.create(user=instance, receive_backends=receive_backends)
