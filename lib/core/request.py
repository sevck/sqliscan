# coding=utf-8
import requests
from lib.core.data import kb
from lib.core.data import conf
from lib.core.common import get_params_dict
from lib.core.common import page_encoding
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
			if not data:
				# get method
				req = requests.get(url, params=params, cookies=cookies,
								headers=headers, timeout=timeout,
								data=data, verify=False,
								allow_redirects=False, proxies=PROXIES)
			else:
				# post method
				data = get_params_dict(data, sep="&")
				req = requests.post(url, params=params, cookies=cookies,
								headers=headers, timeout=timeout,
								data=data, verify=False,
								allow_redirects=False, proxies=PROXIES)

			# 只对2xx的响应码进行判断
			if 400 > req.status_code > 300 or req.status_code == 404:
				return None
			return req
		except Exception, ex:
			print ex, url
			return None

	@staticmethod
	def query_page(req_payload, place):
		req = None
		if place == "params":
			# Get请求
			if kb.targets.method == "GET":
				target = kb.targets.target
				url = "%s?%s" % (target, req_payload)
				req = Request.http_send(url)
			# POST请求
			elif kb.targets.method == "POST":
				target = "%s?%s" % (kb.targets.target, conf.parser.query)
				req = Request.http_send(target, data=req_payload)

		# User-Agent注入
		elif place == "ua":
			target = kb.targets.target
			ua = {
				'User-Agent': req_payload
			}
			req = Request.http_send(target, other_header=ua)

		elif place == "url_rewrite":
			req = Request.http_send(req_payload)

		elif place == "cookies":
			cookies = get_params_dict(req_payload, sep=';')
			req = Request.http_send(kb.targets.target, cookies=cookies)

		elif place == "headers":
			# 其他的常见headers
			headers = get_params_dict(req_payload, sep='|')
			req = Request.http_send(kb.targets.target, other_header=headers)

		if req is not None:
			content = r'%s' % req.content
			content = page_encoding(content, encoding=kb.page_encoding)
			return content, req.headers
		return None, None

if __name__ == '__main__':
	req = Request.http_send("http://127.0.0.1/sqli/sqli.php?id=1")
	print req.content