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
from lib.core.init import set_default_encoding
from lib.core.settings import URL_REWRITE_REPLACE
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

		# 设置需要扫描的位置 0:关闭 1:开启
		self.setting = {
			"place": {
				"cookies": 1,
				"params": 1,
				"ua": 1,
				"url_rewrite": 1,
				"headers": 1,
			},
		}

		# POC信息填写
		self.poc_info = {
			"author": "exploit_cat",
			"name": "SQL注入检测",
			"vulType": "SQL注入漏洞",
			"desc": "由于参数过滤不当，导致SQL注入漏洞",
			"createDate": "2016-4-6",
			"level": "high"
		}

		# 初始化工作
		self.init()

	def init(self):
		"""
		扫描任务初始化
		:return:
		"""
		# 设置kb 和 conf全局对象
		set_global_data()

		# 设置conf.headers
		set_default_headers()

		# 设置内置编码
		set_default_encoding()

		# 设置项目相关的路径
		paths.ROOT_PATH = _get_module_path()
		set_path()

		# 载入报错规则
		load_errors()

		# 载入边界文件
		load_boundaries()

		# 载入策略文件
		load_payloads()

	def _set_result(self, target):
		"""
		设置扫描结果，扫描完成后调用
		self.scan_result['payload']保存命中的扫描规则，是一个dict结构，
		有error和bool两个key，分别表示报错注入规则和盲注规则，其中每个key对应的
		value都是一个list。list的元素存放的是字符串，该字符串代表一个命中规则，举例：
		GET类型的报错注入: GET|http://127.0.0.1/sql.php?id=1'
		POST类型的盲注: POST|http://127.0.0.1/sql.php|id=1 and 1=1
		Payload的详细输出请看comment.py中的get_url_with_payload函数
		:param target: 扫描目标URL
		:return: None
		"""
		self.scan_result['pocInfo'] = self.poc_info
		self.scan_result['url'] = target
		self.scan_result['type'] = "SQL Injection"
		self.scan_result['method'] = kb.targets.method
		self.scan_result['payload'] = conf.hint_payloads

	def audit(self, target, body=None, cookies=None, headers=None):
		"""
		框架调用audit方法实现扫描
		:string target: URL 可以携带参数
		:string body:  POST数据包请求部分的body
		:dict cookies:
		:dict headers:
		:return: None
		"""
		target = urllib.unquote(target)
		if body is not None:
			body = urllib.unquote(body)

		# 判断目标是否连接正常
		if not check_connection(target, body=body, cookies=cookies, headers=headers):
			return self.scan_result

		# 载入place信息
		feed_targets(target, self.setting, body=body, cookies=cookies, headers=headers)

		# 检测页面是否是动态的 设置page_stable和dynamic_marks
		check_stability(target, body=body)

		# 进行扫描
		for place in conf.parameters.keys():
			injection = False
			# 普通参数型注入检测
			if place == "params":
				param_tuples = conf.parameters[place]
				for parameter, value in param_tuples:
					check = check_dyn_param(place, parameter, value)
					if not check:
						print "parameter %s is [NOT] Dynamic" % parameter
						continue
					else:
						print "parameter %s is Dynamic" % parameter
					injection = check_sql_injection(place, parameter, value)

			# User-Agent注入
			elif place == "ua":
				parameter = "User-Agent"
				value = conf.parameters['ua']
				injection = check_sql_injection(place, parameter, value)

			# Cookies注入
			elif place == "cookies":
				if cookies is None:
					continue
				cookies_tuples = conf.parameters["cookies"]
				print cookies_tuples
				for parameter, value in cookies_tuples:
					check = check_dyn_param(place, parameter, value)
					if not check:
						print "parameter %s is [NOT] Dynamic" % parameter
						continue
					else:
						print "parameter %s is Dynamic" % parameter
					injection = check_sql_injection(place, parameter, value)

			# header注入
			elif place == "headers":
				if headers is None:
					continue
				headers_tuples = conf.parameters["headers"]
				for parameter, value in headers_tuples:
					injection = check_sql_injection(place, parameter, value)

			# 伪静态注入检测
			elif place == "url_rewrite":
				if URL_REWRITE_REPLACE not in target:
					continue
				else:
					injection = check_sql_injection(place)

			if injection:
				self._set_result(target)

		# 返回扫描结果
		return self.scan_result

	def attack(self, target):
		pass


def main():
	scanner = SqliScanPlugin()
	scanner.audit("http://api.baiyue.baidu.com/sn/api/instantfulltext?url=http://www.zmdnews.cn/paper2/news.php?id=238262&pid=2107&title=%e5%ba%9e%e9%98%81%e6%9d%91%e6%9c%89%e8%ae%b8%e5%a4%9a%e8%8b%b1%e9%9b%84%e7%9a%84%e6%95%85%e4%ba%8b&site=%e9%a9%bb%e9%a9%ac%e5%ba%97%e6%96%b0%e9%97%bb%e7%bd%91")
	# scanner.audit("http://123.125.65.137:8089/tag/11373552?sort=hot_desc&start=41 AND 8272=8271&limit=20")
	# scanner.audit("http://static.app.m.v1.cn/www/mod/mob/ctl/subscription/act/my/uid/8473817[__payload__]/pcode/010110000/version/4.0.mindex.html")
	# scanner.audit("http://www.rohde-schwarz.com.cn", headers={'X-Forwarded-For': '1.1.1.1'})
	# scanner.audit("http://127.0.0.1/sqli/cookie.php", None, cookies={'id': '1', 'name': 'chongrui'})
	# scanner.audit("http://127.0.0.1/sqli/header.php", None, headers={'X-Forwarded-For':'1'})
	# scanner.audit("http://127.0.0.1/sqli/in.php?in=admin")
	# scanner.audit("http://127.0.0.1/sqli/reflect.php?id=1")
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
