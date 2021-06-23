# -*- coding: utf-8 -*-

"""
@author: 猿小天
@contact: QQ:1638245306
@Created on: 2021/6/2 002 14:43
@Remark: 自定义的JsonResonpse文件
"""

import six
from rest_framework.response import Response
from rest_framework.serializers import Serializer


class SuccessResponse(Response):
    """
    标准响应成功的返回, SuccessResponse(data)或者SuccessResponse(data=data)
    (1)默认code返回2000, 不支持指定其他返回码
    """

    def __init__(self, data=None, msg='success', status=None, template_name=None, headers=None, exception=False,
                 content_type=None):
        std_data = {
            "code": 2000,
            "data": {
                "page":1,
                "limit":1,
                "total":1,
                "data":data
            },
            "msg": msg
        }
        super().__init__(std_data, status, template_name, headers, exception, content_type)


class ErrorResponse(Response):
    """
    标准响应错误的返回,ErrorResponse(msg='xxx')
    (1)默认错误码返回400, 也可以指定其他返回码:ErrorResponse(code=xxx)
    """

    def __init__(self, data=None, msg='error', code=400, status=None, template_name=None, headers=None,
                 exception=False, content_type=None):
        std_data = {
            "code": code,
            "data": data,
            "msg": msg
        }
        super().__init__(std_data, status, template_name, headers, exception, content_type)