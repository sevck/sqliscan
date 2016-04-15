# coding=utf-8
import requests
from lib.core.data import kb
from lib.core.data import conf
from lib.core.common import get_params_dict
from lib.core.settings import PROXIES


class Request(object):
	@staticmethod
	def http_send(url, params=None, cookies=None, data=None, other_header=None):
		headers = None
		timeout = 10
		if "headers" in conf.keys() and conf.headers:
			headers = conf.headers
		if "timeout" in conf.keys() and conf.timeout:
			timeout = conf.timeout
		if other_header is not None:
			headers = dict(headers, **other_header)
		# 防止requests的编码
		try:
			req = None
			if not data:
				# get method
				req = requests.get(url, params=params, cookies=cookies,
								headers=headers, timeout=timeout,
								   data=data, verify=False,
								   proxies=PROXIES, allow_redirects=False)
			else:
				# post method
				data = get_params_dict(data)
				req = requests.post(url, params=params, cookies=cookies,
								headers=headers, timeout=timeout,
								   data=data, verify=False,
								   proxies=PROXIES, allow_redirects=False)

			# 只对2xx的响应码进行判断
			if 400 > req.status_code > 300 or req.status_code == 404:
				return req
			return req
		except Exception, ex:
			print ex, url
			return None

	@staticmethod
	def query_page(req_payload, place):
		if place == "params":
			# Get请求
			if kb.targets.method == "GET":
				target = kb.targets.target
				url = "%s?%s" % (target, req_payload)
				req = Request.http_send(url)
				if req:
					return req.content, req.headers

			# POST请求
			elif kb.targets.method == "POST":
				target = "%s?%s" % (kb.targets.target, conf.parser.query)
				req = Request.http_send(target, data=req_payload)
				if req:
					return req.content, req.headers

		# User-Agent注入
		elif place == "ua":
			pass
		elif place == "url_rewrite":
			pass
		elif place == "cookie":
			pass
		else:
			# 其他的常见headers
			pass
		return None, None

if __name__ == '__main__':
	req = Request.http_send("http://127.0.0.1/sqli/sqli.php?id=1")
	print req.content