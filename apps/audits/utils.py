import copy
from datetime import datetime
from itertools import chain

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.db.models import F, Value, CharField
from django.db.models.functions import Concat
from django.utils import translation

from common.db.fields import RelatedManager
from common.utils import validate_ip, get_ip_city, get_logger
from common.utils.timezone import as_current_tz
from .const import DEFAULT_CITY, ActivityChoices as LogChoice
from .handler import create_or_update_operate_log
from .models import ActivityLog

logger = get_logger(__name__)


def write_login_log(*args, **kwargs):
    from audits.models import UserLoginLog

    ip = kwargs.get('ip') or ''
    if not (ip and validate_ip(ip)):
        ip = ip[:15]
        city = DEFAULT_CITY
    else:
        city = get_ip_city(ip) or DEFAULT_CITY
    kwargs.update({'ip': ip, 'city': city})
    return UserLoginLog.objects.create(**kwargs)


def _get_instance_field_value(
        instance, include_model_fields,
        model_need_continue_fields, exclude_fields=None
):
    data = {}
    opts = getattr(instance, '_meta', None)
    if opts is None:
        return data

    for f in chain(opts.concrete_fields, opts.private_fields):
        if _should_skip_field(f, include_model_fields, model_need_continue_fields):
            continue

        try:
            value = getattr(instance, f.name, None) or getattr(instance, f.attname, None)
        except ObjectDoesNotExist:
            continue

        if not isinstance(value, (bool, int)) and not value:
            continue

        value = _resolve_choice_label(f, value)

        if _merge_nested_one_to_one(f, value, include_model_fields, model_need_continue_fields, exclude_fields, data):
            continue

        _store_field_in_data(f, value, data)
    return data

def _should_skip_field(f, include_model_fields, model_need_continue_fields):
    if not include_model_fields and not getattr(f, 'primary_key', False):
        return True
    if isinstance(f, (GenericForeignKey, models.FileField, models.ImageField)):
        return True
    if getattr(f, 'attname', None) in model_need_continue_fields:
        return True
    return False


def _resolve_choice_label(f, value):
    for c_value, c_label in (getattr(f, 'choices', []) or []):
        if c_value == value:
            return c_label
    return value


def _merge_nested_one_to_one(f, value, include_model_fields, model_need_continue_fields, exclude_fields, data):
    """Handle OneToOneField pointing to a Model; mutates data. Returns True if caller should continue."""
    if not (isinstance(f, models.OneToOneField) and isinstance(value, models.Model)):
        return False
    nested_data = _get_instance_field_value(
        value, include_model_fields, model_need_continue_fields, ('id',)
    )
    for k, v in nested_data.items():
        if exclude_fields and k in exclude_fields:
            continue
        data.setdefault(k, v)
    return True


def _convert_field_value(f, value):
    """Convert a non-primary-key field value to its serialisable form."""
    if isinstance(value, list):
        return copy.deepcopy(value)
    if isinstance(value, dict):
        return dict(copy.deepcopy(value))
    if isinstance(value, datetime):
        return as_current_tz(value).strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, RelatedManager):
        return value.value
    if isinstance(f, GenericRelation):
        return [str(v) for v in value.all()]
    return value


def _store_field_in_data(f, value, data):
    """Apply pk label override, convert value, then write into data."""
    if getattr(f, 'primary_key', False):
        f.verbose_name = 'id'
    else:
        value = _convert_field_value(f, value)
    try:
        data.setdefault(
            str(f.verbose_name), {'name': getattr(f, 'column', ''), 'value': value}
        )
    except Exception as e:
        print(f.__dict__)
        raise e

def model_to_dict_for_operate_log(
        instance, include_model_fields=True, include_related_fields=None
):
    data = _get_instance_field_value(
        instance, include_model_fields, ['date_updated']
    )

    if not include_related_fields:
        return data

    opts = instance._meta
    fields = chain(opts.many_to_many, opts.related_objects)

    for f in fields:
        if getattr(f, 'related_model', None) not in include_related_fields:
            continue
        _process_related_field(instance, f, data)

    return data

def _process_related_field(instance, f, data):
    if instance.pk is None:
        return

    related_name = getattr(f, 'attname', '') or getattr(f, 'related_name', '')
    if not related_name or related_name in ['history_passwords']:
        return

    try:
        qs = getattr(instance, related_name).all()
    except Exception:
        return

    if not qs:
        return

    value = [str(i) for i in qs]
    if not value:
        return

    try:
        field_key = getattr(f, 'verbose_name', None) or f.related_model._meta.verbose_name
        data.setdefault(
            str(field_key), {'name': getattr(f, 'column', ''), 'value': value}
        )
    except Exception:
        pass

def construct_userlogin_usernames(user_queryset):
    usernames_original = user_queryset.values_list('username', flat=True)
    usernames_combined = user_queryset.annotate(
        usernames_combined_field=Concat(F('name'), Value('('), F('username'), Value(')'), output_field=CharField())
    ).values_list("usernames_combined_field", flat=True)
    usernames = list(chain(usernames_original, usernames_combined))
    return usernames


def record_operate_log_and_activity_log(ids, action, detail, model, **kwargs):
    from orgs.utils import current_org

    org_id = current_org.id
    with translation.override('en'):
        resource_type = kwargs.pop('resource_type', None) or model._meta.verbose_name
        create_or_update_operate_log(action, resource_type, force=True, **kwargs)
        base_data = {'type': LogChoice.operate_log, 'detail': detail, 'org_id': org_id}
        activities = [ActivityLog(resource_id=r_id, **base_data) for r_id in ids]
        ActivityLog.objects.bulk_create(activities)
