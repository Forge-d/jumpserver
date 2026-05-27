#!/usr/bin/python
#

import os
import sys
from collections import Counter
import django
from django.db.models import Count


if os.path.exists('../apps'):
    sys.path.insert(0, '../apps')
elif os.path.exists('./apps'):
    sys.path.insert(0, './apps')

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "jumpserver.settings")
django.setup()

from users.models import UserGroup
from django.core.exceptions import FieldError


def clean_group(interactive=True):
    try:
        UserGroup.objects.all().filter(is_discard=True).delete()
    except FieldError:
        pass
    groups = UserGroup.objects.all()
    groups_name_list = groups.values_list('name', flat=True)
    groups_with_info = groups.annotate(Count('users'))\
        .annotate(Count('asset_permissions'))

    counter = Counter(groups_name_list)
    for name, count in counter.items():
        if count == 0:
            continue
        groups_duplicate = groups_with_info.filter(name=name)
        need_clean_count = groups_duplicate.count()

        for group in groups_duplicate:
            need_clean = _check_need_clean(group, need_clean_count)

            if need_clean:
                confirm = _get_confirm(name, group, interactive)
                if confirm:
                    group.delete()
                    print("Delete success: {}".format(name))
                    need_clean_count -= 1
                else:
                    continue


def _check_need_clean(group, need_clean_count):
    if group.users__count > 0:
        return False
    if group.asset_permissions__count > 0:
        return False
    if need_clean_count == 1:
        return False
    return True


def _get_confirm(name, group, interactive):
    if not interactive:
        return True
    while True:
        confirm = input(
            "Delete user group <{}>, create at {}? ([y]/n)".format(
                name, group.date_created)
        )
        if confirm.lower() in ["y", ""]:
            return True
        elif confirm.lower() == "n":
            return False
        else:
            print("No valid input")
            continue

if __name__ == '__main__':
    clean_group()
