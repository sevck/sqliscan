# coding=utf-8
import re
import copy
import time
import random
import socket

from lib.core.data import conf
from lib.core.data import kb
from lib.core.common import findDynamicContent
from lib.core.common import get_url_with_payload
from lib.core.common import get_injection_tests
from lib.core.common import cleanup_payload
from lib.core.common import payload_packing
from lib.core.common import prefix_packing
from lib.core.common import suffix_packing
from lib.core.common import extract_regex_result
from lib.core.common import list_to_str
from lib.core.common import random_str
from lib.core.common import is_error_contain
from lib.core.common import compare_pages
from lib.core.common import removeReflectiveValues
from lib.core.common import random_int
from lib.core.common import get_urlparse
from lib.core.common import extract_payload
from lib.core.common import remove_payload_delimiters
from lib.core.common import content_type_filter
from lib.core.common import page_encoding
from lib.core.common import check_char_encoding
from lib.core.request import Request
from lib.core.settings import FORMAT_EXCEPTION_STRINGS
from lib.core.settings import HEURISTIC_CHECK_ALPHABET
from lib.core.settings import META_CHARSET_REGEX
from lib.core.settings import URL_REWRITE_REPLACE


def check_connection(target, body=None, cookies=None, headers=None):
	"""
	检测页面是否可正常访问
	kb.original_page 原页面
	kb.is_connect 链接成功
	:return:
	"""
	try:
		try:
			# URL重写的形式
			if URL_REWRITE_REPLACE in target:
				target = target.replace(URL_REWRITE_REPLACE, "")

			parser = get_urlparse(target)
			hostname = parser.netloc.split(":")[0]
			socket.getaddrinfo(hostname, None)
		except socket.error, ex:
			print ex
			return False
		req = Request.http_send(target, data=body, cookies=cookies, other_header=headers)

		# 对跳转和404进行处理
		if req is None:
			return False
		if req is not None and not req.content:
			kb.original_page = None
			return False

		# 获取网页编码
		content_type = req.headers['Content-Type']
		http_charset, meta_charset = None, None
		if content_type and (content_type.find("charset=") != -1):
			http_charset = check_char_encoding(content_type.split("charset=")[-1])
		meta_charset = check_char_encoding(extract_regex_result(META_CHARSET_REGEX, req.content))

		kb.page_encoding = meta_charset or http_charset or "utf-8"

		# 筛选合适的content-type
		if not content_type_filter(req):
			return False

		# 对网页内容进行编码操作
		content = page_encoding(req.content, encoding=kb.page_encoding)
		kb.original_page = content
		return True
	except Exception, ex:
		print ex
		return False

def check_dyn_param(place, parameter, value):
	"""
	判断参数是否是动态的
	"""

	kb.matchRatio = None
	dynResult = None
	randInt = random_int()

	try:
		payload = payload_packing(place, parameter, value=value, newValue=randInt, where=3)
		page, headers = Request.query_page(payload, place)
		if page is None:
			return False
		dynResult = compare_pages(kb.original_page, page)
	except Exception, e:
		print e

	# 如果compare方法显示 两个页面不相同则说明参数是动态的
	# 如果两个页面相同，说明非动态
	result = not dynResult
	return result


def check_stability(target, body=None):
	"""
	检测页面动态内容
	设置了两个全局变量：
		kb.dynamic_marks 不同位置的标记
		kb.page_stable 页面是否固定的标志位
	:return:
	"""
	print "check page stability"

	# URL重写形式默认为stable
	if URL_REWRITE_REPLACE not in target:
		kb.page_stable = True
		return kb.page_stable

	first_page = None
	second_page = None
	# kb.original_page在check_connection方法中设置
	if kb.original_page:
		first_page = kb.original_page

	delay = random.random()
	time.sleep(delay)
	second_req = Request.http_send(target, data=body,
								   cookies=conf.cookies_dict, other_header=conf.headers_dict)

	if second_req is not None:
		content = page_encoding(second_req.content, encoding=kb.page_encoding)
		second_page = content

	kb.page_stable = (first_page == second_page)
	if not kb.page_stable:
		kb.dynamic_marks = findDynamicContent(first_page, second_page)
	return kb.page_stable


def fuzzing_error_sqli(place, parameter, value):
	"""
	进行启发式扫描的方法
	:param place: 扫描位置
	:param parameter: 参数的键
	:param value: 参数的值
	:return: true or false
	"""
	prefix = ""
	suffix = ""
	rand_str = ""
	result = False
	while "'" not in rand_str:
		rand_str = random_str(length=10, alphabet=HEURISTIC_CHECK_ALPHABET)

	payload = "%s%s%s" % (prefix, rand_str, suffix)

	# 正常URL检测
	payload = payload_packing(place, parameter, value=value, newValue=payload, delimiters=False)
	randstr_page, _ = Request.query_page(payload, place)
	result = is_error_contain(randstr_page)

	# 判断是否是类型转换的错误
	def is_casting(page):
		return any(_ in (page or "") for _ in FORMAT_EXCEPTION_STRINGS)

	casting = is_casting(randstr_page) and not is_casting(kb.originalPage)

	# 报错注入fuzzing成功
	if not casting and result:
		result = True
	return result, get_url_with_payload(payload, kb.targets.method, place)


def check_sql_injection(place, parameter=None, value=None):
	"""
	检测SQL注入的方法
	:param place: 扫描的位置
	:param parameter: 参数的key
	:param value: 参数的value
	:return: True or False
	"""
	print "check %s=%s parameter" % (parameter, value)
	injectable = False

	# 进行fuzzing
	fuzzing_check_first, fuzzing_payload = fuzzing_error_sqli(place, parameter, value)
	if fuzzing_check_first is True:
		print "fuzzing success for parameter %s=%s" % (parameter, value)
		conf.hint_payloads["error"].append((fuzzing_payload, ))
		injectable = True
		return injectable

	# 载入规则库
	tests = get_injection_tests()

	while tests:
		test = tests.pop(0)
		title = test.title

		comment = None
		if "comment" in test.request:
			comment = test.request.comment

		fst_payload = cleanup_payload(test.request.payload, orig_value=value)
		if value and value.isdigit():
			boundaries = sorted(copy.deepcopy(conf.boundaries), \
								key=lambda x: any(_ in (x.prefix or "") \
									or _ in (x.suffix or "") for _ in ('"', '\'')))
		else:
			boundaries = conf.boundaries

		# 选取相对应的边界策略
		for boundary in boundaries:
			clause_match = False
			for clause_test in test.clause:
				if clause_test in boundary.clause:
					clause_match = True
					break

			if test.clause != [0] and boundary.clause != [0] and not clause_match:
				continue

			where_match = False
			for where in test.where:
				if where in boundary.where:
					where_match = True
					break

			if not where_match:
				continue

			# 组装payload
			prefix = boundary.prefix if boundary.prefix else ""
			suffix = boundary.suffix if boundary.suffix else ""

			# 考虑where的位置，放置参数和payload的位置
			for where in test.where:
				if fst_payload:
					bound_payload = prefix_packing(fst_payload, prefix, where=where)
					bound_payload = suffix_packing(bound_payload, suffix, comment=comment)
					req_payload = payload_packing(place, parameter, value=value,
												  newValue=bound_payload, where=where)
					req_payload = cleanup_payload(req_payload, orig_value=value)
				else:
					req_payload = None

				for method, check in test.response.items():
					# 报错注入检测
					if method == "grep":
						check = cleanup_payload(check, orig_value=value)
						page, headers = Request.query_page(req_payload, place)
						output = extract_regex_result(check, page, re.DOTALL | re.IGNORECASE) \
									or extract_regex_result(check, list_to_str( \
									[headers[key] for key in headers.keys()] \
									if headers else None), re.DOTALL | re.IGNORECASE)
						if output == "1":
							info_msg = "parameter '%s' is '%s' injectable " % (parameter, title)
							print info_msg
							url_with_payload = get_url_with_payload(req_payload,
																	kb.targets.method, place)
							conf.hint_payloads["error"].append((url_with_payload, ))
							return injectable

					# 盲注检测
					elif method == "comparison":
						true_payload = remove_payload_delimiters(req_payload)
						true_page, headers = Request.query_page(true_payload, place)
						# 去除反射内容
						reflect_payload = extract_payload(req_payload)
						true_page = removeReflectiveValues(true_page, reflect_payload)

						# 组装第二次验证的payload
						snd_boundpayload = cleanup_payload(test.response.comparison, orig_value=value)
						snd_boundpayload = prefix_packing(snd_boundpayload, prefix, where=where)
						snd_boundpayload = suffix_packing(snd_boundpayload, suffix, comment=comment)
						snd_payload = payload_packing(place, parameter, value=value,
												  newValue=snd_boundpayload, where=where)
						snd_payload = cleanup_payload(snd_payload, orig_value=value)
						snd_payload_with_deli = snd_payload
						# 去除payload边界占位符
						snd_payload = remove_payload_delimiters(snd_payload)
						false_page, headers = Request.query_page(snd_payload, place)

						# 去除反射内容
						reflect_payload2 = extract_payload(snd_payload_with_deli)
						false_page = removeReflectiveValues(false_page, reflect_payload2)

						# 当超时链接发生时，页面就会返回None
						if true_page is None or false_page is None:
							continue

						# 判断是否盲注
						original_page = kb.original_page
						true_result = compare_pages(original_page, true_page)
						false_result = compare_pages(original_page, false_page)

						if true_result and not (true_page == false_page):
							if not false_result:
								infoMsg = "parameter '%s' is '%s' injectable " % \
										  (parameter if parameter else "rewrite url", title)
								print infoMsg
								injectable = True
								record_one = get_url_with_payload(req_payload,
																   kb.targets.method, place)
								record_second = get_url_with_payload(snd_payload,
																   kb.targets.method, place)
								conf.hint_payloads["bool"].append((record_one, record_second))

	# 更改盲注判别策略，当盲注命中Payload只有一条，则判断为误报，原因是
	# 基于同样的语法结构，若实际上存在漏洞，应该可以命中多条payload
	if len(conf.hint_payloads["bool"]) > 1:
		injectable = True
		return injectable
	else:
		conf.hint_payloads["bool"] = []
		injectable = False
		return injectable
