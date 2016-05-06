# coding=utf-8
import requests

from lib.core.data import kb
from lib.core.data import conf
from lib.core.common import get_params_dict
from lib.core.common import page_encoding
from lib.core.settings import PROXIES
from lib.core.settings import RETRY_COUNT


class Request(object):
	@staticmethod
	def http_send(url, params=None, cookies=None, data=None, other_header=None):
		headers = None
		timeout = 10

		# 设置requests的重试次数
		requests.adapters.DEFAULT_RETRIES = RETRY_COUNT

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
			req.encoding = "utf-8"
			# 只对2xx的响应码进行判断
			if 400 > req.status_code > 300 or req.status_code == 404:
				return None
			return req
		except Exception, ex:
			print "Request.http_send:%s" % ex
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
	req = Request.http_send("http://tq.91.com/api/?cact=4&dm=sm-n9009&checkcode=003c90116f57482d354d4f4a6f75b01b&format=html&sharetype=2931&timestamp=1455054711023&pid=115&title=%E7%8C%B4%E5%B9%B4%E7%9A%84%E5%A4%A9%E6%B0%94%EF%BC%8C%E8%BF%98%E4%BC%9A%E9%82%A3%E4%B9%88%E4%B8%8D%E6%AD%A3%E5%B8%B8%E5%90%97%EF%BC%9F%EF%BC%88%E6%98%A5%E8%8A%82%E5%A4%A9%E6%B0%94%E5%B1%95%E6%9C%9B%EF%BC%89&chl=1010969b&sv=3.14.2&osv=5.0&mt=4&sessionid=1&sdktype=1&act=502&cuid=ce91c7bd86a0a9b6f8b6e326c7308af6%7C2a478b7400000a&imei=a0000047b874a2&model=season&infotag=8&nt=0&id=31552")
	print req.text