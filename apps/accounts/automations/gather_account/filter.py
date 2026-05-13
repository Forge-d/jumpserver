from datetime import datetime
from ast import literal_eval

from django.utils import timezone

__all__ = ['GatherAccountsFilter']


def parse_date(date_str, default=None):
    if not date_str:
        return default
    if date_str in ['Never', 'null']:
        return default
    formats = [
        '%Y/%m/%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%d-%m-%Y %H:%M:%S',
        '%Y/%m/%d',
        '%d-%m-%Y',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return timezone.make_aware(dt, timezone.get_current_timezone())
        except ValueError:
            continue
    return default


def parse_int(value, default=None):
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        return _parse_int_from_bytes(value, default)
    if isinstance(value, str):
        return _parse_int_from_text(value, default)
    return default


def _parse_int_from_bytes(value, default=None):
    return int.from_bytes(value, byteorder="little", signed=False) if value else default


def _parse_int_from_text(text, default=None):
    text = text.strip()
    if not text or text.lower() in {"none", "null"}:
        return default
    if text.startswith(("b'", 'b"')):
        return _parse_int_from_bytes_literal(text, default)
    try:
        return int(text)
    except ValueError:
        return default


def _parse_int_from_bytes_literal(text, default=None):
    try:
        maybe_bytes = literal_eval(text)
    except (ValueError, SyntaxError):
        return default
    if isinstance(maybe_bytes, (bytes, bytearray)):
        return _parse_int_from_bytes(maybe_bytes, default)
    return default


def _parse_posix_colon_lines(lines, skip_blank_value=False, split_value=False):
    result = {}
    for line in lines:
        if ':' not in line:
            continue
        username, value = line.split(':', 1)
        value = value.strip()
        if skip_blank_value and not value:
            continue
        result[username.strip()] = value.split() if split_value else value
    return result


def _parse_posix_last_login(lines):
    result = {}
    for line in lines:
        if not line.strip() or ' ' not in line:
            continue
        username, login = line.split(' ', 1)
        result[username] = login.split()
    return result


def _set_posix_last_login(user, login):
    if not login or len(login) != 3:
        return
    user['address_last_login'] = login[0][:32]
    try:
        login_date = timezone.datetime.fromisoformat(login[1])
        user['date_last_login'] = login_date
    except ValueError:
        return


def _set_posix_password_dates(user, password_date):
    if not password_date or len(password_date) != 2:
        return
    start_date = timezone.make_aware(timezone.datetime(1970, 1, 1))
    if password_date[0]:
        user['date_password_change'] = start_date + timezone.timedelta(days=int(password_date[0]))
    if password_date[1]:
        user['date_password_expired'] = start_date + timezone.timedelta(days=int(password_date[1]))


def _build_posix_user(
    username, username_groups, username_sudo, username_authorized,
    user_last_login, username_password_date,
):
    user = {}
    _set_posix_last_login(user, user_last_login.get(username) or '')
    _set_posix_password_dates(user, username_password_date.get(username) or '')
    detail = {
        'groups': username_groups.get(username) or '',
        'sudoers': username_sudo.get(username) or '',
        'authorized_keys': username_authorized.get(username) or ''
    }
    user['detail'] = detail
    return user


class GatherAccountsFilter:
    def __init__(self, tp):
        self.tp = tp

    @staticmethod
    def mysql_filter(info):
        result = {}
        for host, user_dict in info.items():
            for username, user_info in user_dict.items():
                password_last_changed = parse_date(user_info.get('password_last_changed'))
                password_lifetime = user_info.get('password_lifetime')
                user = {
                    'username': username,
                    'date_password_change': password_last_changed,
                    'date_password_expired': password_last_changed + timezone.timedelta(
                        days=password_lifetime) if password_last_changed and password_lifetime else None,
                    'date_last_login': None,
                    'groups': '',
                }
                result[username] = user
        return result

    @staticmethod
    def postgresql_filter(info):
        result = {}
        for username, user_info in info.items():
            user = {
                'username': username,
                'date_password_change': None,
                'date_password_expired': parse_date(user_info.get('valid_until')),
                'date_last_login': None,
                'groups': '',
            }
            detail = {
                'can_login': user_info.get('canlogin'),
                'superuser': user_info.get('superuser'),
            }
            user['detail'] = detail
            result[username] = user
        return result

    @staticmethod
    def sqlserver_filter(info):
        if not info:
            return {}
        result = {}
        for user_info in info[0][0]:
            days_until_expiration = parse_int(user_info.get('days_until_expiration'))
            date_password_expired = timezone.now() + timezone.timedelta(
                days=int(days_until_expiration)) if days_until_expiration else None
            user = {
                'username': user_info.get('name', ''),
                'date_password_change': parse_date(user_info.get('modify_date')),
                'date_password_expired': date_password_expired,
                'date_last_login': parse_date(user_info.get('last_login_time')),
                'groups': '',
            }
            detail = {
                'create_date': user_info.get('create_date', ''),
                'is_disabled': user_info.get('is_disabled', ''),
                'default_database_name': user_info.get('default_database_name', ''),
            }
            user['detail'] = detail
            result[user['username']] = user
        return result

    @staticmethod
    def oracle_filter(info):
        result = {}
        for default_tablespace, users in info.items():
            for username, user_info in users.items():
                user = {
                    'username': username,
                    'date_password_change': parse_date(user_info.get('password_change_date')),
                    'date_password_expired': parse_date(user_info.get('expiry_date')),
                    'date_last_login': parse_date(user_info.get('last_login')),
                    'groups': '',
                }
                detail = {
                    'uid': user_info.get('user_id', ''),
                    'create_date': user_info.get('created', ''),
                    'account_status': user_info.get('account_status', ''),
                    'default_tablespace': default_tablespace,
                    'roles': user_info.get('roles', []),
                    'privileges': user_info.get('privileges', []),
                }
                user['detail'] = detail
                result[user['username']] = user
        return result

    @staticmethod
    def posix_filter(info):
        username_groups = _parse_posix_colon_lines(info.pop('user_groups', []))
        username_sudo = _parse_posix_colon_lines(info.pop('user_sudo', []), skip_blank_value=True)
        user_last_login = _parse_posix_last_login(info.pop('last_login', ''))
        username_authorized = _parse_posix_colon_lines(info.pop('user_authorized', []))
        username_password_date = _parse_posix_colon_lines(info.pop('passwd_date', []), split_value=True)

        result = {}
        users = info.pop('users', '')

        for username in users:
            if not username:
                continue
            result[username] = _build_posix_user(
                username,
                username_groups,
                username_sudo,
                username_authorized,
                user_last_login,
                username_password_date,
            )
        return result

    @staticmethod
    def windows_filter(info):
        result = {}
        for user_details in info['user_details']:
            user_info = {}
            lines = user_details['stdout_lines']
            for line in lines:
                if not line.strip():
                    continue
                parts = line.split('  ', 1)
                if len(parts) == 2:
                    key, value = parts
                    user_info[key.strip()] = value.strip()
            detail = {'groups': user_info.get('Global Group memberships', ''), }

            username = user_info.get('User name')
            if not username:
                continue

            result[username] = {
                'username': username,
                'date_password_change': parse_date(user_info.get('Password last set')),
                'date_password_expired': parse_date(user_info.get('Password expires')),
                'date_last_login': parse_date(user_info.get('Last logon')),
                'groups': detail,
            }
        return result

    @staticmethod
    def windows_ad_filter(info):
        result = {}
        for user_info in info['user_details']:
            detail = {'groups': user_info.get('GlobalGroupMemberships', ''), }
            username = user_info.get('SamAccountName')
            if not username:
                continue
            result[username] = {
                'username': username,
                'date_password_change': parse_date(user_info.get('PasswordLastSet')),
                'date_password_expired': parse_date(user_info.get('PasswordExpires')),
                'date_last_login': parse_date(user_info.get('LastLogonDate')),
                'groups': detail,
            }
        return result

    @staticmethod
    def mongodb_filter(info):
        result = {}
        for db, users in info.items():
            for username, user_info in users.items():
                user = {
                    'username': username,
                    'date_password_change': None,
                    'date_password_expired': None,
                    'date_last_login': None,
                    'groups': '',
                }
                result['detail'] = {'db': db, 'roles': user_info.get('roles', [])}
                result[username] = user
        return result

    def run(self, method_id_meta_mapper, info):
        run_method_name = None
        for k, v in method_id_meta_mapper.items():
            if self.tp not in v['type']:
                continue
            run_method_name = k.replace(f'{v["method"]}_', '')

        if not run_method_name:
            return info

        if hasattr(self, f'{run_method_name}_filter'):
            return getattr(self, f'{run_method_name}_filter')(info)
        return info
