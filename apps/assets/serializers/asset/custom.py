from django.db.models import QuerySet
from django.utils.translation import gettext_lazy as _, get_language

from assets.models import Custom, Platform, Asset
from common.const import UUID_PATTERN
from common.serializers import create_serializer_class
from common.serializers.common import DictSerializer, MethodSerializer
from terminal.models import Applet
from .common import AssetSerializer

__all__ = ['CustomSerializer']


class CustomSerializer(AssetSerializer):
    custom_info = MethodSerializer(label=_('Custom info'), required=False, allow_null=True)

    class Meta(AssetSerializer.Meta):
        model = Custom
        fields = AssetSerializer.Meta.fields + ['custom_info']
        fields_unimport_template = ['custom_info']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if hasattr(self, 'initial_data') and not self.initial_data.get('custom_info'):
            self.initial_data['custom_info'] = {}

    @staticmethod
    def _get_default_custom_info_serializer():
        return DictSerializer()

    def _set_instance_from_request_path(self, request):
        if self.instance or not UUID_PATTERN.findall(request.path):
            return
        pk = UUID_PATTERN.findall(request.path)[0]
        self.instance = Asset.objects.filter(id=pk).first()

    def _get_platform_from_request(self, request):
        if self.instance:
            return self.instance.platform
        if not request.query_params.get('platform'):
            return None
        platform_id = request.query_params.get('platform')
        platform_id = int(platform_id) if platform_id.isdigit() else 0
        return Platform.objects.filter(id=platform_id).first()

    @staticmethod
    def _translate_custom_fields(custom_fields, i18n):
        lang = get_language()
        lang_short = lang[:2]

        def translate_text(key):
            return (
                    i18n.get(key, {}).get(lang)
                    or i18n.get(key, {}).get(lang_short)
                    or key
            )

        for field in custom_fields:
            label = field.get('label')
            help_text = field.get('help_text')
            if label:
                field['label'] = translate_text(label)
            if help_text:
                field['help_text'] = translate_text(help_text)

    def get_custom_info_serializer(self):
        request = self.context.get('request')
        default_field = self._get_default_custom_info_serializer()

        if not request:
            return default_field

        if self.instance and isinstance(self.instance, (QuerySet, list)):
            return default_field

        self._set_instance_from_request_path(request)
        platform = self._get_platform_from_request(request)

        if not platform:
            return default_field

        custom_fields = platform.custom_fields

        if not custom_fields:
            return default_field
        name = platform.name.title() + 'CustomSerializer'

        applet = Applet.objects.filter(
            name=platform.created_by.replace('Applet:', '')
        ).first()

        if not applet:
            return create_serializer_class(name, custom_fields)()

        i18n = applet.manifest.get('i18n', {})
        self._translate_custom_fields(custom_fields, i18n)
        return create_serializer_class(name, custom_fields)()
