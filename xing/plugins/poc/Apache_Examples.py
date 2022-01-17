from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Apache Examples 文件泄露"
        self.app_name = 'Java'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        check = b"Expression Language"
        paths = ["/examples/servlets/servlet/CookieExample.html", "/examples/servlets/servlet/RequestHeaderExample"]
        print(target)
        for path in paths:
            url = target + path
            conn = http_req(url, disable_normal=True)
            if conn.status_code != 200:
                continue

            if check not in conn.content:
                continue

            if check in conn.content:
                self.logger.success("发现Apache Examples 文件泄露 vuln {}".format(url))
                return url

