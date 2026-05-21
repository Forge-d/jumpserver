import abc
import io
import re
from datetime import datetime

import pyzipper
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.renderers import BaseRenderer
from rest_framework.utils import encoders, json

from common.serializers import fields as common_fields
from common.utils import get_logger
from .mixins import LogMixin


logger = get_logger(__file__)


class BaseFileRenderer(LogMixin, BaseRenderer):
    # 渲染模板标识, 导入、导出、更新模板: ['import', 'update', 'export']
    template = 'export'
    serializer = None

    @staticmethod
    def _check_validation_data(data):
        detail_key = "detail"
        if detail_key in data:
            return False
        return True

    @staticmethod
    def _json_format_response(response_data):
        return json.dumps(response_data)

    def set_response_disposition(self, response):
        serializer = self.serializer
        if response and hasattr(serializer, 'Meta') and hasattr(serializer.Meta, "model"):
            filename_prefix = serializer.Meta.model.__name__.lower()
        else:
            filename_prefix = 'download'
        suffix = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if self.template == 'import':
            suffix = 'template'
        filename = "{}_{}.{}".format(filename_prefix, suffix, self.format)
        disposition = 'attachment; filename="{}"'.format(filename)
        response['Content-Disposition'] = disposition

    def get_rendered_fields(self):
        fields = self.serializer.fields
        meta = getattr(self.serializer, 'Meta', None)
        if self.template == 'import':
            fields = [v for k, v in fields.items() if not v.read_only and k != "org_id" and k != 'id']
            fields_unimport = getattr(meta, 'fields_unimport_template', [])
            fields = [v for v in fields if v.field_name not in fields_unimport]
        elif self.template == 'update':
            fields = [v for k, v in fields.items() if not v.read_only and k != "org_id"]
        else:
            fields = [v for k, v in fields.items() if not v.write_only and k != "org_id"]

        fields_unexport = getattr(meta, 'fields_unexport', [])
        fields = [v for v in fields if v.field_name not in fields_unexport]
        return fields

    @staticmethod
    def get_column_titles(render_fields):
        titles = []
        for field in render_fields:
            name = field.label
            if field.required:
                name = '*' + name
            titles.append(name)
        return titles

    def process_data(self, data):
        results = data['results'] if 'results' in data else data

        if isinstance(results, dict):
            results = [results]

        if self.template == 'import':
            results = [results[0]] if results else results
        else:
            # 限制数据数量
            results = results[:settings.MAX_LIMIT_PER_PAGE]
        # 会将一些 UUID 字段转化为 string
        results = json.loads(json.dumps(results, cls=encoders.JSONEncoder))
        return results

    @staticmethod
    def to_id_name(value):
        if value is None:
            return '-'
        pk = str(value.get('id', '') or value.get('pk', ''))
        name = value.get('display_name', '') or value.get('name', '')
        return '{}({})'.format(name, pk)

    @staticmethod
    def to_choice_name(value):
        if value is None:
            return '-'
        value = value.get('value', '')
        return value

    def render_value(self, field, value):
        if value is None:
            value = self._render_none_value()
        elif hasattr(field, 'to_file_representation'):
            value = self._render_file_representation(field, value)
        elif isinstance(value, bool):
            value = self._render_bool_value(value)
        elif isinstance(field, common_fields.LabeledChoiceField):
            value = self._render_labeled_choice_value(value)
        elif isinstance(field, common_fields.ObjectRelatedField):
            value = self._render_object_related_value(field, value)
        elif self._is_list_like_field(field):
            value = self._render_list_like_value(field, value)
        elif isinstance(field, serializers.Serializer) and value.get('id'):
            value = self._render_serializer_with_id_value(value)
        elif isinstance(field, serializers.ManyRelatedField):
            value = self._render_many_related_value(field, value)
        value = self._render_stringify_value(value)
        return value

    @staticmethod
    def _is_list_like_field(field):
        return isinstance(field, serializers.ListSerializer) or isinstance(field, serializers.ListField)

    def _render_list_like_value(self, field, value):
        # Handles both ListSerializer and ListField
        child = getattr(field, 'child', None) or getattr(field, 'child_relation', None)
        if child is not None:
            return [self.render_value(child, v) for v in value]
        return value

    @staticmethod
    def _render_stringify_value(value):
        if not isinstance(value, str):
            value = json.dumps(value, cls=encoders.JSONEncoder, ensure_ascii=False)
        return str(value)

    @staticmethod
    def _render_none_value():
        return '-'

    @staticmethod
    def _render_file_representation(field, value):
        return field.to_file_representation(value)

    @staticmethod
    def _render_bool_value(value):
        return 'Yes' if value else 'No'

    @staticmethod
    def _render_labeled_choice_value(value):
        value = value or {}
        return '{}({})'.format(value.get('label'), value.get('value'))

    def _render_object_related_value(self, field, value):
        if field.many:
            return [self.to_id_name(v) for v in value]
        return self.to_id_name(value)

    def _render_list_serializer_value(self, field, value):
        return [self.render_value(field.child, v) for v in value]

    @staticmethod
    def _render_serializer_with_id_value(value):
        return BaseFileRenderer.to_id_name(value)

    def _render_many_related_value(self, field, value):
        return [self.render_value(field.child_relation, v) for v in value]

    def _render_list_field_value(self, field, value):
        return [self.render_value(field.child, v) for v in value]

    def get_field_help_text(self, field):
        text = ''
        if hasattr(field, 'get_render_help_text'):
            text = field.get_render_help_text()
        elif isinstance(field, serializers.BooleanField):
            text = self._help_text_boolean(field)
        elif isinstance(field, serializers.IntegerField):
            text = self._help_text_integer(field)
        elif isinstance(field, serializers.IPAddressField):
            text = self._help_text_ip(field)
        elif isinstance(field, common_fields.PhoneField):
            text = self._help_text_phone(field)
        elif isinstance(field, serializers.CharField):
            text = self._help_text_char(field)
        elif isinstance(field, serializers.DateTimeField):
            text = self._help_text_datetime(field)
        elif isinstance(field, common_fields.LabeledChoiceField):
            text = self._help_text_labeled_choice(field)
        elif isinstance(field, serializers.ChoiceField):
            text = self._help_text_choice(field)
        elif isinstance(field, common_fields.ObjectRelatedField):
            text = self._help_text_object_related(field)
        elif isinstance(field, serializers.PrimaryKeyRelatedField):
            text = self._help_text_primary_key_related(field)
        elif isinstance(field, serializers.ManyRelatedField):
            text = self._help_text_many_related(field)
        elif isinstance(field, serializers.ListSerializer):
            text = self._help_text_list_serializer(field)
        return text

    @staticmethod
    def _help_text_boolean(field):
        return _('Yes/No')

    @staticmethod
    def _help_text_integer(field):
        text = _('Number, min {} max {}').format(field.min_value, field.max_value)
        return text.replace('min None', '').replace('max None', '')

    @staticmethod
    def _help_text_ip(field):
        return _('IP')

    @staticmethod
    def _help_text_phone(field):
        return _("Phone number, format +8612345678901")

    @staticmethod
    def _help_text_char(field):
        if field.max_length:
            return _('Text, max length {}').format(field.max_length)
        else:
            return _("Long text, no length limit")

    @staticmethod
    def _help_text_datetime(field):
        return _('Datetime format {}').format(timezone.now().strftime(settings.REST_FRAMEWORK['DATETIME_FORMAT']))

    @staticmethod
    def _help_text_labeled_choice(field):
        return _('Label, format ["key:value"]')

    @staticmethod
    def _help_text_choice(field):
        choices = [str(v) for v in field.choices.keys()]
        if isinstance(field, common_fields.LabeledChoiceField):
            return _("Choices, format name(value), name is optional for human read,"
                     " value is requisite, options {}" ).format(','.join(choices))
        else:
            return _( "Choices, options {}" ).format(",".join(choices))

    @staticmethod
    def _help_text_object_related(field):
        return _( "Object, format name(id), name is optional for human read, id is requisite" )

    @staticmethod
    def _help_text_primary_key_related(field):
        return _('Object, format id')

    @staticmethod
    def _help_text_many_related(field):
        child_relation_class_name = field.child_relation.__class__.__name__
        if child_relation_class_name == "ObjectRelatedField":
            return _('Objects, format ["name(id)", ...], name is optional for human read, id is requisite')
        elif child_relation_class_name == "LabelRelatedField":
            return _('Labels, format ["key:value", ...], if label not exists, will create it')
        else:
            return _('Objects, format ["id", ...]')

    @staticmethod
    def _help_text_list_serializer(field):
        child = field.child
        if hasattr(child, 'get_render_help_text'):
            return child.get_render_help_text()
        return ''

    def generate_rows(self, data, render_fields):
        for item in data:
            row = []
            for field in render_fields:
                field._row = item
                value = item.get(field.field_name)
                value = self.render_value(field, value)
                row.append(value)
            yield row

    def write_help_text_if_need(self):
        if self.template == 'export':
            return
        fields = self.get_rendered_fields()
        row = []
        for f in fields:
            text = self.get_field_help_text(f)
            row.append(text)
        row[0] = '#Help ' + str(row[0])
        self.write_row(row)

    @abc.abstractmethod
    def initial_writer(self):
        raise NotImplementedError

    def write_column_titles(self, column_titles):
        self.write_row(column_titles)

    def write_rows(self, rows):
        for row in rows:
            self.write_row(row)

    @abc.abstractmethod
    def write_row(self, row):
        raise NotImplementedError

    @abc.abstractmethod
    def get_rendered_value(self):
        raise NotImplementedError

    def after_render(self):
        pass

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if data is None:
            return bytes()

        if not self._check_validation_data(data):
            return self._json_format_response(data)

        try:
            renderer_context = renderer_context or {}
            request = renderer_context['request']
            response = renderer_context['response']
            view = renderer_context['view']
            self.template = request.query_params.get('template', 'export')
            self.serializer = view.get_serializer()
            self.set_response_disposition(response)
        except Exception as e:
            logger.debug(e, exc_info=True)
            value = 'The resource not support export!'.encode('utf-8')
            return value

        try:
            rendered_fields = self.get_rendered_fields()
            column_titles = self.get_column_titles(rendered_fields)
            data = self.process_data(data)
            rows = self.generate_rows(data, rendered_fields)
            self.initial_writer()
            self.write_column_titles(column_titles)
            self.write_help_text_if_need()
            self.write_rows(rows)
            self.after_render()
            value = self.get_rendered_value()
            if getattr(view, 'export_as_zip', False) and self.template == 'export':
                value = self.compress_into_zip_file(value, request, response)
        except Exception as e:
            logger.debug(e, exc_info=True)
            value = 'Render error! ({})'.format(self.media_type).encode('utf-8')
            return value

        self.record_logs(request, view, data)
        return value

    def compress_into_zip_file(self, value, request, response):
        filename_pattern = re.compile(r'filename="([^"]+)"')
        content_disposition = response['Content-Disposition']
        match = filename_pattern.search(content_disposition)
        filename = match.group(1)
        response['Content-Disposition'] = content_disposition.replace(self.format, 'zip')

        contents_io = io.BytesIO()
        secret_key = request.user.secret_key
        if not secret_key:
            content = _("{} - The encryption password has not been set - "
                        "please go to personal information -> file encryption password "
                        "to set the encryption password").format(request.user.name)

            response['Content-Disposition'] = content_disposition.replace(self.format, 'txt')
            contents_io.write(content.encode('utf-8'))
            return contents_io.getvalue()

        with pyzipper.AESZipFile(
                contents_io, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(secret_key.encode('utf8'))
            zf.writestr(filename, value)
        return contents_io.getvalue()
