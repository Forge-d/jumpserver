# views.py

import re
from functools import lru_cache
from typing import Dict

from django.urls import URLPattern
from django.urls import URLResolver
from drf_spectacular.utils import OpenApiParameter
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

BASE_URL = "http://localhost:8080"


def clean_path(path: str) -> str:
    """
    清理掉 DRF 自动生成的正则格式内容，让其变成普通 RESTful URL path。
    """

    # 去掉格式后缀匹配： \.(?P<format>xxx)
    path = re.sub(r'\\\.\(\?P<format>[^)]+\)', '', path)

    # 去掉括号式格式匹配
    path = re.sub(r'\(\?P<format>[^)]+\)', '', path)

    # 移除 DRF 中正则参数的部分 (?P<param>pattern)
    path = re.sub(r'\(\?P<\w+>[^)]+\)', '{param}', path)

    # 如果有多个括号包裹的正则（比如前缀路径），去掉可选部分包装
    path = re.sub(r'\(\(([^)]+)\)\?\)', r'\1', path)  # ((...))? => ...

    # 去掉中间和两边的 ^ 和 $
    path = path.replace('^', '').replace('$', '')

    # 去掉尾部 ?/
    path = re.sub(r'\?/?$', '', path)

    # 去掉反斜杠
    path = path.replace('\\', '')

    # 替换多重斜杠
    path = re.sub(r'/+', '/', path)

    # 添加开头斜杠，移除多余空格
    path = path.strip()
    if not path.startswith('/'):
        path = '/' + path
    if not path.endswith('/'):
        path += '/'

    return path


def extract_resource_paths(urlpatterns, prefix='/api/v1/') -> Dict[str, Dict[str, str]]:
    resource_map = {}

    for pattern in urlpatterns:
        if isinstance(pattern, URLResolver):
            nested_prefix = prefix + str(pattern.pattern)
            resource_map.update(extract_resource_paths(pattern.url_patterns, nested_prefix))

        elif isinstance(pattern, URLPattern):
            resource, entry = _build_resource_entry(pattern, prefix)
            if entry is not None:
                resource_map[resource] = entry

    print("Extracted resource paths:", list(resource_map.keys()))
    return resource_map


def _get_model_from_view(view_cls):
    if not view_cls:
        return None
    queryset = getattr(view_cls, 'queryset', None)
    if queryset is not None:
        return getattr(queryset, 'model', None)
    # 有些 View 用 get_queryset()
    try:
        instance = view_cls()
        qs = instance.get_queryset()
        return getattr(qs, 'model', None)
    except Exception:
        return None


def _get_resource_name(name, path):
    # 尝试获取资源名称
    if name and name.endswith('-list'):
        resource = name[:-5]
    else:
        resource = path.strip('/').split('/')[-1]
    # 不强行加 s，资源名保持原状即可
    return resource if resource.endswith('s') else resource + 's'


def _build_resource_entry(pattern, prefix):
    callback = pattern.callback
    actions = getattr(callback, 'actions', {})
    if not actions:
        return None, None
    if 'get' not in actions or actions['get'] != 'list':
        return None, None

    path = clean_path(prefix + str(pattern.pattern))
    resource = _get_resource_name(pattern.name, path)

    # 获取 View 类和 model 的 verbose_name
    view_cls = getattr(callback, 'cls', None)
    model = _get_model_from_view(view_cls)
    if not model:
        return None, None

    app = str(getattr(model._meta, 'app_label', ''))
    verbose_name = str(getattr(model._meta, 'verbose_name', ''))
    entry = {
        'path': path,
        'app': app,
        'verbose_name': verbose_name,
        'description': model.__doc__.__str__()
    }
    return resource, entry



def param_dic_to_param(d):
    return OpenApiParameter(
        name=d['name'], location=d['in'],
        description=d['description'], type=d['type'], required=d.get('required', False)
    )


@lru_cache()
def get_full_resource_map():
    from apps.jumpserver.urls import resource_api
    resource_map = extract_resource_paths(resource_api)
    print("Building URL for resource:", resource_map)
    return resource_map
