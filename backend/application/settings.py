"""
Django settings for application project.

Generated by 'django-admin startproject' using Django 3.2.3.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# ================================================= #
# ******************** 动态配置 ******************** #
# ================================================= #

from conf.env import *

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure--z8%exyzt7e_%i@1+#1mm=%lb5=^fx_57=1@a+_y7bg5-w%)sm'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_comment_migrate',
    'rest_framework',
    'django_filters',
    'corsheaders',  # 注册跨域app
    'dvadmin.system',
    'drf_yasg',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',  # 跨域中间件
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'dvadmin.utils.middleware.ApiLoggingMiddleware',
]

ROOT_URLCONF = 'application.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'application.wsgi.application'

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': DATABASE_ENGINE,
        'NAME': DATABASE_NAME,
        'USER': DATABASE_USER,
        'PASSWORD': DATABASE_PASSWORD,
        'HOST': DATABASE_HOST,
        'PORT': DATABASE_PORT,
    }
}
AUTH_USER_MODEL = 'system.Users'
USERNAME_FIELD = 'username'

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'zh-hans'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = False

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'
# # 设置django的静态文件目录
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]
# 收集静态文件，必须将 MEDIA_ROOT,STATICFILES_DIRS先注释
# python manage.py collectstatic
# STATIC_ROOT=os.path.join(BASE_DIR,'static')

# ================================================= #
# ******************* 跨域的配置 ******************* #
# ================================================= #

# 全部允许配置
CORS_ORIGIN_ALLOW_ALL = True
# 允许cookie
CORS_ALLOW_CREDENTIALS = True  # 指明在跨域访问中，后端是否支持对cookie的操作

# ================================================= #
# ********************* 日志配置 ******************* #
# ================================================= #

# log 配置部分BEGIN #
SERVER_LOGS_FILE = os.path.join(BASE_DIR, 'logs', 'server.log')
ERROR_LOGS_FILE = os.path.join(BASE_DIR, 'logs', 'error.log')
if not os.path.exists(os.path.join(BASE_DIR, 'logs')):
    os.makedirs(os.path.join(BASE_DIR, 'logs'))

# 格式:[2020-04-22 23:33:01][micoservice.apps.ready():16] [INFO] 这是一条日志:
# 格式:[日期][模块.函数名称():行号] [级别] 信息
STANDARD_LOG_FORMAT = '[%(asctime)s][%(name)s.%(funcName)s():%(lineno)d] [%(levelname)s] %(message)s'
CONSOLE_LOG_FORMAT = '[%(asctime)s][%(name)s.%(funcName)s():%(lineno)d] [%(levelname)s] %(message)s'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': STANDARD_LOG_FORMAT
        },
        'console': {
            'format': CONSOLE_LOG_FORMAT,
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'file': {
            'format': CONSOLE_LOG_FORMAT,
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': SERVER_LOGS_FILE,
            'maxBytes': 1024 * 1024 * 100,  # 100 MB
            'backupCount': 5,  # 最多备份5个
            'formatter': 'standard',
            'encoding': 'utf-8',
        },
        'error': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': ERROR_LOGS_FILE,
            'maxBytes': 1024 * 1024 * 100,  # 100 MB
            'backupCount': 3,  # 最多备份3个
            'formatter': 'standard',
            'encoding': 'utf-8',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'console',
        }
    },
    'loggers': {
        # default日志
        '': {
            'handlers': ['console', 'error', 'file'],
            'level': 'INFO',
        },
        # 数据库相关日志
        'django.db.backends': {
            'handlers': [],
            'propagate': True,
            'level': 'INFO',
        },
    }
}

# ================================================= #
# *************** REST_FRAMEWORK配置 *************** #
# ================================================= #

REST_FRAMEWORK = {
    'DATETIME_FORMAT': "%Y-%m-%d %H:%M:%S",  # 日期时间格式配置
    'DATE_FORMAT': "%Y-%m-%d",
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',

    ),
    'DEFAULT_PAGINATION_CLASS': 'dvadmin.utils.pagination.CustomPagination',  # 自定义分页
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'EXCEPTION_HANDLER': 'dvadmin.utils.exception.CustomExceptionHandler',  # 自定义的异常处理
}

# ================================================= #
# ****************** simplejwt配置 ***************** #
# ================================================= #
from datetime import timedelta

SIMPLE_JWT = {
    # token有效时长
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=2),
    # token刷新后的有效时间
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    # 设置前缀
    'AUTH_HEADER_TYPES': ('JWT',),
}

# ================================================= #
# ******************** 其他配置 ******************** #
# ================================================= #
API_LOG_ENABLE = True
# API_LOG_METHODS = 'ALL' # ['POST', 'DELETE']
API_LOG_METHODS = ['POST', 'UPDATE', 'DELETE']  # ['POST', 'DELETE']
DJANGO_CELERY_BEAT_TZ_AWARE = False
CELERY_TIMEZONE = 'Asia/Shanghai'  # celery 时区问题
