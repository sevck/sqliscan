# coding=utf-8
import os
import sys
import inspect
import urllib

from lib.core.data import paths
from lib.core.data import conf
from lib.core.data import kb
from lib.core.common import we_are_frozen
from lib.core.checks import check_dyn_param
from lib.core.checks import check_sql_injection
from lib.core.checks import check_connection
from lib.core.checks import check_stability
from lib.core.init import set_default_headers
from lib.core.init import feed_targets
from lib.core.init import set_global_data
from lib.core.init import set_path
from lib.parse.payload import load_boundaries
from lib.parse.payload import load_payloads
from lib.parse.payload import load_errors
from general_poc_base import GeneralPOCBase


def _get_module_path():
	"""
	获取项目根路径
	:return:
	"""
	try:
		_ = sys.executable if we_are_frozen() else __file__
	except NameError:
		_ = inspect.getsource(_get_module_path)
	return os.path.dirname(os.path.realpath(_))


class SqliScanPlugin(GeneralPOCBase):
	def __init__(self):
		"""
		对通用POC扫描插件进行初始化
		其中setting为配置选项，以后如果要添加配置项，可以在这个字段进行操作
		:return: None
		"""
		GeneralPOCBase.__init__(self)

		# setting for the place to scan
		self.setting = {
			"place": {
				"cookie": 1,
				"params": 1,
				"ua": 1,
				"url_rewrite": 1,
				"headers": {
					"X-Forwarded-For": "1.1.1.1",
					"Referer": "",
					"Client-IP": ""
				},
			},
		}

		self.poc_info = {
			"author": "exploit_cat",
			"name": "SQL注入检测",
			"vulType": "SQL注入漏洞",
			"desc": "由于参数过滤不当，导致SQL注入漏洞",
			"createDate": "2016-4-6",
			"level": "high"
		}

		# 初始化工作
		self._init()

	def _init(self):
		# 设置kb 和 conf全局对象
		set_global_data()

		# 设置conf.headers
		set_default_headers()

		# 设置项目相关的路径
		paths.ROOT_PATH = _get_module_path()
		set_path()

		# 载入报错规则
		load_errors()

		# 载入边界文件
		load_boundaries()

		# 载入策略文件
		load_payloads()

	def audit(self, target, body=None, cookies=None):
		target = urllib.unquote(target)
		if body:
			body = urllib.unquote(body)

		if not check_connection(target, body=body):
			return self.scan_result
		if not kb.is_connect:
			return self.scan_result

		# 载入place信息
		feed_targets(target, self.setting, body=body)

		# 检测页面是否是动态的 设置page_stable和dynamic_marks
		check_stability(target, body=None, cookies=None)

		# 进行扫描
		for place in conf.parameters.keys():
			# 普通参数型注入检测
			if place == "params":
				param_dict = conf.parameters[place]
				for parameter, value in param_dict:
					check = check_dyn_param(place, parameter, value)
					if not check:
						print "parameter %s is [NOT] Dynamic" % parameter
						continue
					else:
						print "parameter %s is Dynamic" % parameter
					injection = check_sql_injection(place, parameter, value)
					if injection:
						self.scan_result['pocInfo'] = self.poc_info
						self.scan_result['url'] = target
						self.scan_result['type'] = u"SQL Injection"
						self.scan_result['method'] = kb.targets.method
						self.scan_result['payload'] = conf.hint_payloads
			elif place == "ua":
				pass
			elif place == "cookie":
				pass
			elif place == "headers":
				pass
			elif place == "url_rewrite":
				pass
			else:
				continue

	def attack(self, target):
		pass


def main():
	scanner = SqliScanPlugin()
	# scanner.audit("http://music.baidu.com:80/story/edit/124810874?fr=ios")
	# scanner.audit("http://vedio.baidu.com.cn:80/comic_intro/?e=1&service=json&dtype=comicplayurl&site=&callback=jquery1111003589733876287937_1435363200029&id=936&_=1435363200000")
	# scanner.audit("http://127.0.0.1/sqli/in.php?in=admin")
	# scanner.audit("http://127.0.0.1/sqli/reflect.php?id=1")
	scanner.audit("http://www.70jj.com/shop/index.php?shop_id=1")
	# scanner.audit("http://wapbaike.baidu.com.cn:80/subview/757333/757333.htm?step=28&bd_page_type=1&net=0&page=10&st=1")
	# scanner.audit("http://vedio.baidu.com.cn:80/comic_intro/?e=1&service=json&dtype=comicplayurl&site=&callback=jquery1111003589733876287937_1435363200029&id=936&_=1435363200000")

	# scanner.audit("http://127.0.0.1/sqli/sqli.php?id=1")
	# scanner.audit("http://127.0.0.1/sqli/orderby.php?order=1")
	# scanner.audit("http://127.0.0.1/sqli/in.php?in=admin")
	# scanner.audit("http://127.0.0.1/sqli/search.php?like=admin")
	# scanner.audit("http://127.0.0.1/sqli/post.php", "id=1&name=admin")
	# scanner.audit("http://127.0.0.1/sqli/limit.php?limit=1")
	print "[kb.targets]:", kb.targets
	print "[conf.parameters]:", conf.parameters
	print "[Scan Results]:", scanner.scan_result
	print "[Payload info]:", conf.hint_payloads


if __name__ == '__main__':
	main()
