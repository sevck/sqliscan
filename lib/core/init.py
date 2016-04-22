# coding=utf-8
import os
import socket

from lib.core.data import kb
from lib.core.data import conf
from lib.core.data import AttribDict
from lib.core.data import paths
from lib.core.common import get_ua
from lib.core.common import get_urlparse
from lib.core.common import get_params_tuples
from lib.core.common import get_params_dict
from lib.core.common import random_str
from lib.core.common import is_multipart
from lib.core.common import get_unicode
from lib.core.settings import KB_CHARS_BOUNDARY_CHAR
from lib.core.settings import KB_CHARS_LOW_FREQUENCY_ALPHABET


def set_sock_timeout():
	"""
	设置socket超时时间
	:return:
	"""
	socket.setdefaulttimeout(conf.timeout)


def set_path():
	"""
	设置文件的路径
	:return: None
	"""
	paths.XML_PATH = os.path.join(paths.ROOT_PATH, "xml")
	paths.ERRORS_XML = os.path.join(paths.XML_PATH, "error-sqli.xml")
	paths.BLIND_XML = os.path.join(paths.XML_PATH, "blind-sqli.xml")
	paths.BOUNDARIES_XML = os.path.join(paths.XML_PATH, "boundary.xml")
	paths.PAYLOADS_PATH = os.path.join(paths.XML_PATH, "payloads")
	paths.ERRORS = os.path.join(paths.XML_PATH, "errors.xml")


def set_global_data():
	"""
	设置随机字符串的方法
	两个全局变量
	kb.chars.start
	kb.chars.stop
	:return:
	"""
	kb.chars = AttribDict()
	kb.chars.start = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR,
								 random_str(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET),
								 KB_CHARS_BOUNDARY_CHAR)
	kb.chars.stop = "%s%s%s" % (KB_CHARS_BOUNDARY_CHAR,
								random_str(length=3, alphabet=KB_CHARS_LOW_FREQUENCY_ALPHABET),
								KB_CHARS_BOUNDARY_CHAR)
	kb.chars.at, kb.chars.space, kb.chars.dollar, kb.chars.hash_ = \
		("%s%s%s" % (KB_CHARS_BOUNDARY_CHAR, _, KB_CHARS_BOUNDARY_CHAR) \
		 for _ in random_str(length=4, lowercase=True))
	kb.match_ratio = None
	kb.targets = AttribDict()
	kb.page_encoding = "utf-8"

	conf.parameters = AttribDict()
	conf.params_dict = AttribDict()
	conf.cookies_dict = AttribDict()
	conf.headers_dict = AttribDict()
	conf.headers = AttribDict()
	conf.cookies = AttribDict()
	conf.boundaries = []
	conf.errors = []
	conf.tests = []
	conf.hint_payloads = {"error": [], "bool": []}
	conf.timeout = 5
	conf.parser = None

	set_sock_timeout()


def set_default_headers():
	"""
	设置默认的HTTP包头
	:return:
	"""
	if not conf.headers:
		conf.headers["Accept-Language"] = "zh-CN,zh;q=0.8"
		if "charset" in conf.keys() and conf.charset:
			conf.headers["Accept-Encoding"] = "%s;q=0.7,*;q=0.1" % conf.charset
		else:
			conf.headers["Accept-Encoding"] = "utf-8;q=0.7,*;q=0.1"
		conf.headers["Cache-control"] = "no-cache,no-store"
		conf.headers["Pragma"] = "no-cache"
		conf.headers["User-Agent"] = get_ua()


def feed_targets(target, setting, body=None, cookies=None, headers=None):
	"""
	:param target: url, method, data, cookies
	:param body:
	:return:
	"""
	parser = get_urlparse(target)
	conf.parser = parser
	kb.targets.target = "%s://%s%s" % (parser.scheme, parser.netloc, parser.path)
	kb.targets.target = get_unicode(kb.targets.target)

	# 设置cookies的conf.parameters
	cookies_params = None
	if cookies is not None:
		cookies_params = [(k, v) for k, v in cookies.items()]
		conf.cookies_dict = cookies

	if headers is not None:
		conf.headers_dict = headers
		headers_params = [(k, v) for k, v in headers.items()]

	if not body:
		# get method
		kb.targets.method = "GET"

		# 设置参数类型的conf.parameters
		query_str = parser.query
		params = get_params_tuples(query_str, sep="&")
		conf.params_dict = get_params_dict(query_str, sep="&")

		for k, v in setting["place"].items():
			if k == "params" and v == 1:
				conf.parameters["params"] = params  # tuples
			if k == "ua" and v == 1:
				conf.parameters["ua"] = get_ua()
			if k == "headers" and v == 1:
				if headers is not None and headers_params is not None:
					conf.parameters["headers"] = headers_params
			if k == "url_rewrite" and v == 1:
				pass
			if k == "cookies" and v == 1:
				if cookies is not None and cookies_params is not None:
					conf.parameters["cookies"] = cookies_params

	else:
		# 文件上传POST包
		if is_multipart(body):
			kb.is_multipart = True
		else:
			kb.is_multipart = False
		# post method
		kb.targets.method = "POST"
		# 如果存在POST报文中URL上也有参数的情况
		conf.query_str = get_params_dict(conf.parser.query, sep="&")
		params = get_params_tuples(body, sep="&")
		conf.params_dict = get_params_dict(body, sep="&")
		for k, v in setting["place"].items():
			if k == "params" and v == 1:
				conf.parameters["params"] = params
			if k == "ua" and v == 1:
				conf.parameters["ua"] = get_ua()
			if k == "headers" and v == 1:
				if headers is not None and headers_params is not None:
					conf.parameters["headers"] = headers_params
			if k == "url_rewrite" and v == 1:
				pass
			if k == "cookies" and v == 1:
				if cookies is not None and cookies_params is not None:
					conf.paramemters["cookies"] = cookies_params


if __name__ == '__main__':
	set_global_data()
	print kb



