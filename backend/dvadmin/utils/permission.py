# -*- coding: utf-8 -*-

"""
@author: 猿小天
@contact: QQ:1638245306
@Created on: 2021/6/6 006 10:30
@Remark: 自定义权限
"""
import re

from django.db.models import F
from rest_framework.permissions import BasePermission

from dvadmin.system.models import ApiWhiteList


def ValidationApi(reqApi, validApi):
    """
    验证当前用户是否有接口权限
    :param reqApi: 当前请求的接口
    :param validApi: 用于验证的接口
    :return: True或者False
    """
    if validApi is not None:
        valid_api = validApi.replace('{id}', '.*?')
        matchObj = re.match(valid_api, reqApi, re.M | re.I)
        if matchObj:
            return True
        else:
            return False
    else:
        return False


def ReUUID(api):
    """
    将接口的uuid替换掉
    :param api:
    :return:
    """
    pattern = re.compile(r'[a-f\d]{4}(?:[a-f\d]{4}-){4}[a-f\d]{12}/$')
    m = pattern.search(api)
    if m:
        res = api.replace(m.group(0),".*/")
        return res
    else:
        return None


class CustomPermission(BasePermission):
    """自定义权限"""

    def has_permission(self, request, view):

        # 对ViewSet下的def方法进行权限判断
        # 当权限为空时,则可以访问
        is_head = getattr(view, 'head', None)
        if is_head:
            head_kwargs = getattr(view.head, 'kwargs', None)
            if head_kwargs:
                _permission_classes = getattr(head_kwargs, 'permission_classes', None)
                if _permission_classes is None:
                    return True

        # 判断是否是超级管理员
        if request.user.is_superuser:
            return True
        else:
            api = request.path  # 当前请求接口
            method = request.method  # 当前请求方法
            print(ApiWhiteList.objects.values("url","method"))
            methodList = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
            method = methodList.index(method)
            # ***接口白名单***
            url= ReUUID(api)
            if url:
                apiWhiteList_instance = ApiWhiteList.objects.filter(url__regex=url, method=method).first()
                print(apiWhiteList_instance)
                if apiWhiteList_instance:
                    return True
            # ********#
            if not hasattr(request.user, "role"):
                return False
            userApiList = request.user.role.values('permission__api', 'permission__method' )  # 获取当前用户的角色拥有的所有接口
            ApiList = [str(item.get('permission__api'))+":"+str(item.get('permission__method')) for item in userApiList]
            now_api = api+":"+str(method)
            return now_api in ApiList
