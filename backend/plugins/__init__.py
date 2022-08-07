# # dvadmin 插件
# # ================================================= #
# # ******************** 插件配置 ******************** #
# # ================================================= #
import json
import os

from application import settings
from application.settings import BASE_DIR, PLUGINS_WEB_YAML_PATH, PLUGINS_BACKEND_YAML_PATH

# 拉取插件
from dvadmin.utils.git_utils import GitRepository


def get_all_plugins():
    """
    获取所有插件字典
    :return:
    """

    with open(PLUGINS_WEB_YAML_PATH, 'r', encoding='utf-8') as doc:
        # 进行排序
        plugins_dict = dict(sorted(json.load(doc).items(), key=lambda x: x[1]['priority'], reverse=True))
    with open(PLUGINS_BACKEND_YAML_PATH, 'r', encoding='utf-8') as doc:
        # 进行排序
        plugins_dict.update(dict(sorted(json.load(doc).items(), key=lambda x: x[1]['priority'], reverse=True)))
    settings.PLUGINS_LIST = {plugins_name: plugins_values for plugins_name, plugins_values in plugins_dict.items() if
                             plugins_values.get('enable', None)}
    return plugins_dict


def plugins_exists():
    """
    校验插件是否存在，不存在下载
    :return:
    """
    plugins_dict = get_all_plugins()
    for key, plugins in plugins_dict.items():
        # 启动状态的插件不存在下载
        # if not plugins.get('enable'):
        #     continue
        # 获取插件的目录，校验插件是否存在
        yaml_path = ""
        if plugins.get('type', None) == 'web':
            yaml_path = PLUGINS_WEB_YAML_PATH
        elif plugins.get('type', None) == 'backend':
            yaml_path = PLUGINS_BACKEND_YAML_PATH
        if not yaml_path:
            continue
        plugins_path = os.path.join(os.path.split(yaml_path)[0], key)
        plugins_name = plugins.get('name')
        tags = plugins.get('tags')
        repo_url = plugins.get('git')
        # 目录不存在则下拉
        if not os.path.exists(plugins_path):
            # 进行下载
            print(f"插件[{plugins_name}]({repo_url})插件未安装，正在安装中...")
            # 从远程仓库将代码下载到上面创建的目录中
            repo = GitRepository(repo_url=repo_url, local_path=plugins_path)
            if not repo.tags_exists(tags):
                print(f"插件[{plugins_name}]中无[{tags}]标签，请检查！")
                continue
            repo.change_to_tag(tag=tags)
            print(f"插件[{plugins_name}][{tags}]插件安装完成！")
        else:
            repo = GitRepository(repo_url=repo_url, local_path=plugins_path)
            if not repo.tags_exists(tags):
                print(f"插件[{plugins_name}]中无[{tags}]标签，请检查！")
                continue
            repo.change_to_tag(tag=tags)


def import_plugins_settings():
    yaml_path = os.path.join(BASE_DIR, "plugins", "config.json")
    with open(yaml_path, 'r', encoding='utf-8') as doc:
        plugins_dict = json.load(doc)
        # 进行排序
        plugins_dict = dict(sorted(plugins_dict.items(), key=lambda x: x[1]['priority'], reverse=True))
        for plugins_name, plugins_values in plugins_dict.items():
            # 校验插件是否
            if plugins_values.get('enable', None):
                exec(f"from plugins.{plugins_name}.settings import *")
                print(f"【{plugins_values.get('name', None)}】导入成功")


plugins_exists()
import_plugins_settings()
