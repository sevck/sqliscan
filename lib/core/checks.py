# coding=utf-8
import re
import copy
import time
import random
import socket

from lib.core.data import conf
from lib.core.data import kb
from lib.core.datatype import InjectionDict
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
from lib.core.request import Request
from lib.core.settings import FORMAT_EXCEPTION_STRINGS
from lib.core.settings import HEURISTIC_CHECK_ALPHABET


def check_connection(target, body=None):
	"""
	检测页面是否可正常访问
	kb.original_page 原页面
	kb.is_connect 链接成功
	:return:
	"""
	try:
		try:
			parser = get_urlparse(target)
			hostname = parser.netloc.split(":")[0]
			socket.getaddrinfo(hostname, None)
		except socket.error, ex:
			print ex
			kb.is_connect = False
			return False
		req = Request.http_send(target, data=body)
		# 对跳转和404进行处理
		if req is None:
			kb.is_connect = False
			return False
		if req is not None and not req.content:
			kb.original_page = None
			kb.is_connect = False
			return False
		kb.original_page = req.content
		kb.is_connect = True
		return True
	except Exception, ex:
		print ex
		kb.is_connect = False
		return False

def check_dyn_param(place, parameter, value):
	"""
	判断参数是否是动态的
	"""

	kb.matchRatio = None
	dynResult = None
	randInt = random_int()

	try:
		payload = payload_packing(place, parameter, value, randInt, where=3)
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


def check_stability(target, body=None, cookies=None):
	"""
	检测页面动态内容
	设置了两个全局变量：
		kb.dynamic_marks 不同位置的标记
		kb.page_stable 页面是否固定的标志位
	:return:
	"""
	print "check page stability"
	first_page = None
	second_page = None
	# kb.original_page在check_connection方法中设置
	if kb.original_page:
		first_page = kb.original_page

	delay = random.random()
	time.sleep(delay)
	second_req = Request.http_send(target, data=body, cookies=cookies)
	if second_req is not None:
		second_page = second_req.content
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
	payload = payload_packing(place, parameter, value=value, newValue=payload)
	randstr_page, _ = Request.query_page(payload, place)

	infoMsg = "heuristic (basic) test shows that parameter "
	infoMsg += "'%s' might " % parameter
	result = is_error_contain(randstr_page)

	# 判断是否是类型转换的错误
	def is_casting(page):
		return any(_ in (page or "") for _ in FORMAT_EXCEPTION_STRINGS)

	casting = is_casting(randstr_page) and not is_casting(kb.originalPage)

	# 报错注入fuzzing成功
	if not casting and result:
		result = True
	return result


def check_sql_injection(place, parameter, value):
	"""
	检测SQL注入的方法
	:param place: 扫描的位置
	:param parameter: 参数的key
	:param value: 参数的value
	:return: True or False
	"""
	print "check %s=%s parameter" % (parameter, value)
	tests = get_injection_tests()
	injectable = False
	injection = None
	while tests:
		test = tests.pop(0)
		title = test.title
		injection = InjectionDict()
		injection.parameter = parameter
		injection.value = value
		injection.place = place
		injection.stype = test.stype

		comment = None
		if "comment" in test.request:
			comment = test.request.comment

		fst_payload = cleanup_payload(test.request.payload, orig_value=value)
		if value.isdigit():
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
			injection.prefix = prefix
			injection.suffix = suffix

			# 考虑where的位置，放置参数和payload的位置
			for where in test.where:
				if fst_payload:
					bound_payload = prefix_packing(fst_payload, prefix, where=where)
					bound_payload = suffix_packing(bound_payload, suffix, comment=comment)
					req_payload = payload_packing(place, parameter,
												  newValue=bound_payload, where=where)
					req_payload = cleanup_payload(req_payload, orig_value=value)
				else:
					req_payload = None

				for method, check in test.response.items():
					# 报错注入检测
					if method == "grep":
						check = cleanup_payload(check, orig_value=value)
						# 对报错注入进行fuzzing
						fuzzing_check = fuzzing_error_sqli(place, parameter, value)
						if not fuzzing_check:
							continue
						page, headers = Request.query_page(req_payload, place)
						output = extract_regex_result(check, page, re.DOTALL | re.IGNORECASE) \
									or extract_regex_result(check, list_to_str( \
									[headers[key] for key in headers.keys()] \
									if headers else None), re.DOTALL | re.IGNORECASE)
						if output:
							result = output == "1"

							if result:
								infoMsg = "parameter '%s' is '%s' injectable " % (parameter, title)
								print infoMsg
								url_with_payload = get_url_with_payload(req_payload,
																		kb.targets.method, place)
								conf.hint_payloads["error"].append((url_with_payload, ))
								injectable = True
								injection.data[1] += 1
								return injectable

					# 盲注检测
					elif method == "comparison":
						true_page, headers = Request.query_page(req_payload, place)
						# 去除反射内容
						true_page = removeReflectiveValues(true_page, req_payload)

						# 组装第二次验证的payload
						snd_payload = cleanup_payload(test.response.comparison, orig_value=value)
						snd_payload = prefix_packing(snd_payload, prefix, where=where)
						snd_payload = suffix_packing(snd_payload, suffix, comment=comment)
						snd_payload = payload_packing(place, parameter,
												  newValue=snd_payload, where=where)
						snd_payload = cleanup_payload(snd_payload, orig_value=value)
						false_page, headers = Request.query_page(snd_payload, place)

						# 去除反射内容
						false_page = removeReflectiveValues(false_page, snd_payload)

						# 盲注检测，进行两次页面的比较
						if is_error_contain(true_page) or is_error_contain(false_page):
							continue

						# 当超时链接发生时，页面就会返回None
						if true_page is None or false_page is None:
							continue

						# 判断是否盲注
						original_page = kb.original_page
						true_result = compare_pages(original_page, true_page)
						false_result = compare_pages(original_page, false_page)

						if true_result and not (true_page == false_page):
							if not false_result:
								infoMsg = "parameter '%s' is '%s' injectable " % (parameter, title)
								print infoMsg
								injectable = True
								record_one = get_url_with_payload(req_payload,
																   kb.targets.method, place)
								record_second = get_url_with_payload(snd_payload,
																   kb.targets.method, place)
								is_false_position = check_false_positive(injection)
								if is_false_position:
									print "Detect parameter %s=%s is false positive" % (parameter, value)
									injectable = False
									return injectable
								conf.hint_payloads["bool"].append((record_one, record_second))
								injection.data[2] += 1

								# 如果盲注规则命中了两条则直接返回
								# 命中规则选取第一条
								if injection.data[2] > 1:
									conf.hint_payloads = conf.hint_payloads["bool"][0]
									return injectable

	# 	# 如果最终只有一条盲注命中，则开始进行误报检测
	# 	if injection.data[2] == 1:
	# 		is_false_position = check_false_position(injection)
	# 		if is_false_position:
	# 			injectable = False
	# return injectable


def check_false_positive(injection):
	"""
	检测盲注中的
	:param injection:
	:return:
	"""
	flag = False
	rand_int1, rand_int2, rand_int3 = 0, 0, 0

	def _():
		return int(random_int(2)) + 1

	while True:
		rand_int1, rand_int2, rand_int3 = (_() for j in xrange(3))

		rand_int1 = min(rand_int1, rand_int2, rand_int3)
		rand_int3 = max(rand_int1, rand_int2, rand_int3)

		if rand_int3 > rand_int2 > rand_int1:
			break
	if not check_bool_expression("and %d=%d" % (rand_int1, rand_int1), injection):
		flag = True
	if check_bool_expression("and %d=%d" % (rand_int1, rand_int3), injection):
		flag = True
	elif check_bool_expression("and %d=%d" % (rand_int3, rand_int2), injection):
		flag = True
	elif not check_bool_expression("and %d=%d" % (rand_int2, rand_int2), injection):
		flag = True
	return flag


def check_bool_expression(expression, injection):
	"""
	检测布尔条件是否成立
	:param expression:
	:param injection:
	:return:
	"""
	original_page = kb.original_page
	prefix = injection.prefix
	suffix = injection.suffix
	parameter = injection.parameter
	value = injection.value
	place = injection.place

	payload = prefix_packing(expression, prefix)
	payload = suffix_packing(payload, suffix)
	payload = payload_packing(place, parameter, value=value, newValue=payload)
	page, headers = Request.query_page(payload, place)
	if page is None:
		return True
	ret = compare_pages(original_page, page)
	return ret