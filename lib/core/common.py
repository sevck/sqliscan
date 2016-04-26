# coding=utf-8
"""
项目中的公用代码部分
"""
import os
import sys
import copy
import codecs
import re
import random
import string
import urllib
import urlparse
import difflib

from urllib import quote

from lib.core.settings import BOUNDARY_BACKSLASH_MARKER
from lib.core.settings import REFLECTED_REPLACEMENT_REGEX
from lib.core.settings import REFLECTED_BORDER_REGEX
from lib.core.settings import REFLECTED_MAX_REGEX_PARTS
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import INVALID_UNICODE_CHAR_FORMAT
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import CONTENT_TYPE_WHITE_LIST
from lib.core.settings import URL_REWRITE_REPLACE
from lib.core.settings import GLOBAL_TIME_OUT
from lib.core.data import kb
from lib.core.data import conf
from lib.core.exception import SqliSystemException
from lib.core.exception import TimeoutException
from lib.core.timeout import time_limit

kb.global_time_out = GLOBAL_TIME_OUT


def get_ua():
	"""
	需要实现一个获取随机ua的方法
	:return:
	"""
	return "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36 SE 2.X MetaSr 1.0"


def we_are_frozen():
	return hasattr(sys, "frozen")


def check_file(filename):
	"""
	判断文件是否存在，是否是可读的公用方法
	"""

	valid = True

	if filename is None or not os.path.isfile(filename):
		valid = False

	if valid:
		try:
			with open(filename, "rb"):
				pass
		except:
			valid = False

	if not valid:
		raise SqliSystemException("unable to read file '%s'" % filename)


def get_injection_tests():
	ret_val = copy.deepcopy(conf.tests)
	return ret_val


def trimAlphaNum(value):
	"""
	工具方法，去掉字符串开头和结尾的字母数字
	"""
	while value and get_unicode(value[-1]).isalnum():
		value = value[:-1]
	while value and get_unicode(value[0]).isalnum():
		value = value[1:]

	return value


def find_dynamic_content(first_page, second_page):
	"""
	寻找页面中的动态内容
	"""
	DYNAMICITY_MARK_LENGTH = 32
	if not first_page or not second_page:
		return
	seq_matcher = difflib.SequenceMatcher(None, first_page, second_page)
	blocks = seq_matcher.get_matching_blocks()
	dynamic_markings = []

	# Removing too small matching blocks
	for block in blocks[:]:
		(_, _, length) = block

		if length <= DYNAMICITY_MARK_LENGTH:
			blocks.remove(block)

	if len(blocks) > 0:
		blocks.insert(0, None)
		blocks.append(None)

		for i in xrange(len(blocks) - 1):
			prefix = first_page[blocks[i][0]:blocks[i][0] + blocks[i][2]] if blocks[i] else None
			suffix = first_page[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

			if prefix is None and blocks[i + 1][0] == 0:
				continue

			if suffix is None and (blocks[i][0] + blocks[i][2] >= len(first_page)):
				continue

			prefix = trimAlphaNum(prefix)
			suffix = trimAlphaNum(suffix)

			dynamic_markings.append((prefix[-DYNAMICITY_MARK_LENGTH / 2:] if prefix else None, suffix[:DYNAMICITY_MARK_LENGTH / 2] if suffix else None))

	if len(dynamic_markings) > 0:
		return dynamic_markings


def compatible_find_dynamic_content(first_page, second_page):
	"""
	引入兼容性的动态内容处理
	:param first_page:
	:param second_page:
	:return:
	"""
	# Windows系统不支持信号量设置超时时间
	if kb.support_signal is False:
		dynamic_marks = find_dynamic_content(first_page, second_page)

	# 类UNIX系统中使用信号量
	else:
		try:
			with time_limit(kb.global_time_out):
				dynamic_marks = find_dynamic_content(first_page, second_page)
		except TimeoutException, e:
			print "[-]find dynamic content time out!"
			dynamic_marks = None
	return dynamic_marks


def remove_dynamic_content(page, dynamic_markings):
	"""
	去掉页面中的动态内容
	"""
	if page and dynamic_markings:
		for item in dynamic_markings:
			prefix, suffix = item

			if prefix is None and suffix is None:
				continue
			elif prefix is None:
				page = re.sub(r'(?s)^.+%s' % re.escape(suffix), suffix.replace('\\', r'\\'), page)
			elif suffix is None:
				page = re.sub(r'(?s)%s.+$' % re.escape(prefix), prefix.replace('\\', r'\\'), page)
			else:
				page = re.sub(r'(?s)%s.+%s' % (re.escape(prefix), re.escape(suffix)), '%s%s' % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)
	return page


def get_params_tuples(query_str, sep="&"):
	"""
	>>>get_params_tuples("name=1&id=2", seq="&")
	>>>[('name', '1'), ('id', '2')]
	>>>get_params_dict("name=1; id=2", sep=";")
	>>>[('id', '2'), ('name', '1')]
	:param query_str:
	:return:
	"""
	ret = []
	items = query_str.split(sep)
	for item in items:
		if item is None:
			continue
		elif item.find('=') == -1:
			continue
		item = item.strip()
		pos = item.index('=')
		k = item[:pos]
		v = item[pos+1:]
		ret.append((k, v))
	return ret


def get_params_dict(query_str, sep="&"):
	"""
	>>>get_params_dict("name=1&id=3")
	>>>{'name': '1', 'id': '3'}
	:param query_str:
	:return:
	"""
	ret_dict = {}
	ts = get_params_tuples(query_str, sep=sep)
	for item in ts:
		ret_dict[item[0]] = item[1]
	return ret_dict


def get_urlparse(url):
	"""
	>>> url=urlparse.urlparse('http://www.baidu.com/index.php?username=guol')
	>>> print url
	ParseResult(scheme='http', netloc='www.baidu.com', path='/index.php',
	params='', query='username=guol', fragment='')
	>>> print url.netloc
	www.baidu.com
	>>>
	:param url:
	:return:
	"""
	parser = urlparse.urlparse(url)
	return parser


def get_unicode(value, encoding=None, noneToNull=False):
	"""
	Return the unicode representation of the supplied value:

	>>> getUnicode(u'test')
	u'test'
	>>> getUnicode('test')
	u'test'
	>>> getUnicode(1)
	u'1'
	"""
	def is_list_like(value):
		return isinstance(value, (list, tuple, set))

	if noneToNull and value is None:
		return None

	if is_list_like(value):
		value = list(get_unicode(_, encoding, noneToNull) for _ in value)
		return value

	if isinstance(value, unicode):
		return value
	elif isinstance(value, basestring):
		while True:
			try:
				return unicode(value, encoding or (kb.get("page_encoding") if kb.get("original_page") else None) or UNICODE_ENCODING)
			except UnicodeDecodeError, ex:
				try:
					return unicode(value, UNICODE_ENCODING)
				except:
					value = value[:ex.start] + "".join(INVALID_UNICODE_CHAR_FORMAT % ord(_) for _ in value[ex.start:ex.end]) + value[ex.end:]
	else:
		try:
			return unicode(value)
		except UnicodeDecodeError:
			return unicode(str(value), errors="ignore")


def random_int(length=4, seed=None):
	"""
	>>> random.seed(0)
	>>> randomInt(6)
	874254
	"""

	choice = random.WichmannHill(seed).choice if seed is not None else random.choice

	return int("".join(choice(string.digits if _ != 0 else string.digits.replace('0', '')) for _ in xrange(0, length)))


def random_str(length=4, lowercase=False, alphabet=None, seed=None):
	"""
	>>> random.seed(0)
	>>> randomStr(6)
	'RNvnAv'
	"""

	choice = random.WichmannHill(seed).choice if seed is not None else random.choice

	if alphabet:
		ret_val = "".join(choice(alphabet) for _ in xrange(0, length))
	elif lowercase:
		ret_val = "".join(choice(string.ascii_lowercase) for _ in xrange(0, length))
	else:
		ret_val = "".join(choice(string.ascii_letters) for _ in xrange(0, length))

	return ret_val


def list_to_str(value):
	"""
	>>> listToStrValue([1,2,3])
	'1, 2, 3'
	"""
	if isinstance(value, (set, tuple)):
		value = list(value)
	if isinstance(value, list):
		retVal = value.__str__().lstrip('[').rstrip(']')
	else:
		retVal = value
	return retVal


def cleanup_payload(payload, orig_value=None):
	"""
	填充payload中的随机值
	:param payload:
	:param origValue:
	:return:
	"""
	if payload is None:
		return
	_ = (
			("[DELIMITER_START]", kb.chars.start), ("[DELIMITER_STOP]", kb.chars.stop),\
			("[AT_REPLACE]", kb.chars.at), ("[SPACE_REPLACE]", kb.chars.space), ("[DOLLAR_REPLACE]", kb.chars.dollar),\
			("[HASH_REPLACE]", kb.chars.hash_),
		)
	payload = reduce(lambda x, y: x.replace(y[0], y[1]), _, payload)

	for _ in set(re.findall(r"\[RANDNUM(?:\d+)?\]", payload, re.I)):
		payload = payload.replace(_, str(random_int()))

	for _ in set(re.findall(r"\[RANDSTR(?:\d+)?\]", payload, re.I)):
		payload = payload.replace(_, random_str())

	if orig_value is not None and "[ORIGVALUE]" in payload:
		payload = payload.replace("[ORIGVALUE]", orig_value)
	return payload


def prefix_packing(expr, prefix, where=None):
	"""
	组装前缀部分
	:param expr:
	:param prefix:
	:param where:
	:return:
	"""
	expr = cleanup_payload(expr)
	query = None

	# where=3 为直接替换payload
	if where == 3:
		query = " " + expr
	else:
		query = prefix or ""
		if not (expr and expr[0] == ';') and \
			not (query and query[-1] in ('(', ')') \
			and expr and expr[0] in ('(', ')')) \
			and not (query and query[-1] == '('):
			query += " "
		query = "%s%s" % (query.replace('\\', BOUNDARY_BACKSLASH_MARKER), expr)
	return query


def suffix_packing(expr, suffix, comment=None):
	"""
	组装后缀部分
	:param expr:
	:param comment:
	:param suffix:
	:param where:
	:return:
	"""
	expr = cleanup_payload(expr)
	if comment is not None:
		expr += comment
	if suffix and not comment:
		expr += suffix.replace('\\', BOUNDARY_BACKSLASH_MARKER)
	return expr


def add_payload_delimiters(value):
	"""
	Adds payload delimiters around the input string
	"""

	return "%s%s%s" % (PAYLOAD_DELIMITER, value, PAYLOAD_DELIMITER) if value else value


def remove_payload_delimiters(value):
	"""
	Removes payload delimiters from inside the input string
	"""

	return value.replace(PAYLOAD_DELIMITER, '') if value else value


def payload_packing(place, parameter=None, value="", newValue=None, where=None, delimiters=True):
	"""
	组装payload
	:param place: params ua headers url_rewrite
	:param parameter:参数的key
	:param value: 参数值
	:param newValue: bound_payload
	:param where: where值
	:return:
	"""
	ret_payload = ""
	newValue = get_unicode(newValue)
	# 参数位置的注入检测
	if place == "params":
		for k, v in conf.parameters[place]:
			k = get_unicode(k)
			v = get_unicode(v)
			if k == parameter:
				# 考虑payload和参数的结合方式（where值）
				if where == 1 or where == 2 or not where:
					# 加入payload的前缀和后缀
					if delimiters:
						newValue = add_payload_delimiters("%s%s" % (v, newValue))
					ret_payload += "%s=%s" % (k, newValue)
				elif where == 3:
					ret_payload += "%s=%s" % (k, newValue)
			else:
				ret_payload += "%s=%s" % (k, v)
			ret_payload += "&"
		return ret_payload[:-1]

	elif place == "ua":
		ret_payload = "%s%s" % (value, newValue)
		return ret_payload
	elif place == "headers":
		ret_payload = ""
		for k, v in conf.parameters[place]:
			if k == parameter:
				# 考虑payload和参数的结合方式（where值）
				if where == 1 or where == 2 or not where:
					# 加入payload的前缀和后缀
					if delimiters:
						newValue = add_payload_delimiters("%s%s" % (v, newValue))
					ret_payload += "%s=%s" % (k, newValue)
				elif where == 3:
					ret_payload += "%s=%s" % (k, newValue)
			else:
				ret_payload += "%s=%s" % (k, v)
			ret_payload += "|"
		return ret_payload[:-1]
	elif place == "url_rewrite":
		target = kb.targets.target
		ret_payload = target.replace(URL_REWRITE_REPLACE, newValue)
		return ret_payload
	elif place == "cookies":
		for k, v in conf.parameters[place]:
			if k == parameter:
				# 考虑payload和参数的结合方式（where值）
				if where == 1 or where == 2 or not where:
					# 加入payload的前缀和后缀
					if delimiters:
						newValue = add_payload_delimiters("%s%s" % (v, newValue))
					ret_payload += "%s=%s" % (k, newValue)
				elif where == 3:
					ret_payload += "%s=%s" % (k, newValue)
			else:
				ret_payload += "%s=%s" % (k, v)
			ret_payload += ";"
		return ret_payload[:-1]


def extract_regex_result(regex, content, flags=0):
	"""
	>>> extractRegexResult(r'a(?P<result>[^g]+)g', 'abcdefg')
	'bcdef'
	"""
	retVal = None
	if regex and content and "?P<result>" in regex:
		match = re.search(regex, content, flags)
		if match:
			retVal = match.group("result")
	return retVal


def is_error_contain(page):
	"""
	判断页面中是否有报错信息
	:param page:
	:return:
	"""
	for reg in conf.errors:
		if page is not None:
			if re.findall(reg, page, re.MULTILINE | re.IGNORECASE):
				return True
	return False


def is_multipart(body):
	"""
	判断POST报文是否是文件上传包
	:param body:
	:return:
	"""
	body = quote(body)
	if body.find("Content-Disposition: form-data;") != -1:
		return True
	else:
		return False


def htmlunescape(value):
	"""
	HTML解码函数

	>>> htmlunescape('a&lt;b')
	'a<b'
	"""

	retVal = value
	if value and isinstance(value, basestring):
		codes = (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&nbsp;', ' '), ('&amp;', '&'))
		retVal = reduce(lambda x, y: x.replace(y[0], y[1]), codes, retVal)
		try:
			retVal = re.sub(r"&#x([^;]+);", lambda match: unichr(int(match.group(1), 16)), retVal)
		except ValueError:
			pass
	return retVal

def getFilteredPageContent(page, onlyText=True):
	"""
	去除script, style, comments标签

	>>> getFilteredPageContent(u'<html><title>foobar</title><body>test</body></html>')
	u'foobar test'
	"""

	retVal = page

	# only if the page's charset has been successfully identified
	if isinstance(page, unicode):
		retVal = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if onlyText else ""), " ", page)
		while retVal.find("  ") != -1:
			retVal = retVal.replace("  ", " ")
		retVal = htmlunescape(retVal.strip())

	return retVal


def compare_pages(first_page, secd_page):
	"""
	盲注检测中的页面对比方案
	:param first_page:
	:param secd_page:
	:return:
	"""
	if not kb.page_stable:
		try:
			first_page = remove_dynamic_content(first_page, kb.dynamic_marks)
			secd_page = remove_dynamic_content(secd_page, kb.dynamic_marks)
		except TimeoutException, e:
			return None

	matcher = difflib.SequenceMatcher()
	matcher.set_seq1(first_page)

	seq1 = getFilteredPageContent(matcher.a, True)
	seq2 = getFilteredPageContent(secd_page, True)

	seq1 = seq1.replace(REFLECTED_VALUE_MARKER, "")
	seq2 = seq2.replace(REFLECTED_VALUE_MARKER, "")

	count = 0
	while count < min(len(seq1), len(seq2)):
		if seq1[count] == seq2[count]:
			count += 1
		else:
			break
	if count:
		try:
			_seq1 = seq1[count:]
			_seq2 = seq2[count:]
		except MemoryError:
			pass
		else:
			seq1 = _seq1
			seq2 = _seq2

	while True:
		try:
			matcher.set_seq1(seq1)
		except MemoryError:
			seq1 = seq1[:len(seq1) / 1024]
		else:
			break

	while True:
		try:
			matcher.set_seq2(seq2)
		except MemoryError:
			seq2 = seq2[:len(seq2) / 1024]
		else:
			break

	ratio = round(matcher.quick_ratio(), 3)

	if kb.match_ratio is None:
		if 0.98 > ratio > 0.02:
			kb.match_ratio = ratio

	if ratio >= 0.98:
		return True
	elif ratio <= 0.02:
		return False
	else:
		return (ratio - kb.match_ratio) > 0.05


def get_url_with_payload(payload, method, place):
	"""
	获取URL和payload的组合字符串结果
	:param payload:
	:return:
	"""
	ret_value = ""
	payload = remove_payload_delimiters(payload)
	if place == "params":
		if method == "GET":
			ret_value = "GET|%s?%s" % (kb.targets.target, payload)
		elif method == "POST":
			ret_value = "POST|%s|%s" % (kb.targets.target, payload)
	elif place == "ua":
		ret_value = "UA|User-Agent: %s" % payload
	elif place == "cookies":
		ret_value = "COOKIES|Cookie: %s" % payload
	elif place == "url_rewrite":
		ret_value = "REWRITE|%s" % payload
	elif place == "headers":
		ret_value = "HEADERS|%s" % payload
	return ret_value


def filterStringValue(value, charRegex, replacement=""):
	"""
	Returns string value consisting only of chars satisfying supplied
	regular expression (note: it has to be in form [...])

	>>> filterStringValue(u'wzydeadbeef0123#', r'[0-9a-f]')
	u'deadbeef0123'
	"""
	retVal = value
	if value:
		retVal = re.sub(charRegex.replace("[", "[^") if "[^" not in charRegex else charRegex.replace("[^", "["), replacement, value)
	return retVal


def urlencode(value):
	return urllib.quote(value)


def urldecode(value):
	if not value:
		return None
	return urllib.unquote(value)


def remove_reflective_values(content, payload):
	"""
	去除网页内容中的反射内容
	(e.g.
		..search.php?q=1 AND 1=2 -->
		"...searching for <b>1%20AND%201%3D2</b>..." --> "
		...searching for <b>__REFLECTED_VALUE__</b>..."
	)
	"""

	retVal = content
	payload = urldecode(payload)
	try:
		if all([content, payload]):
			def _(value):
				while 2 * REFLECTED_REPLACEMENT_REGEX in value:
					value = value.replace(2 * REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX)
				return value

			regex = _(filterStringValue(payload, r"[A-Za-z0-9]",
										REFLECTED_REPLACEMENT_REGEX.encode("string-escape")))

			if regex != payload:
				if all(part.lower() in content.lower()
					   for part in filter(None, regex.split(REFLECTED_REPLACEMENT_REGEX))[1:]):
					parts = regex.split(REFLECTED_REPLACEMENT_REGEX)
					retVal = content.replace(payload, REFLECTED_VALUE_MARKER)

					if len(parts) > REFLECTED_MAX_REGEX_PARTS:
						regex = _("%s%s%s" % (REFLECTED_REPLACEMENT_REGEX.join(parts[:REFLECTED_MAX_REGEX_PARTS / 2]), REFLECTED_REPLACEMENT_REGEX, REFLECTED_REPLACEMENT_REGEX.join(parts[-REFLECTED_MAX_REGEX_PARTS / 2:])))

					parts = filter(None, regex.split(REFLECTED_REPLACEMENT_REGEX))

					if regex.startswith(REFLECTED_REPLACEMENT_REGEX):
						regex = r"%s%s" % (REFLECTED_BORDER_REGEX, regex[len(REFLECTED_REPLACEMENT_REGEX):])
					else:
						regex = r"\b%s" % regex

					if regex.endswith(REFLECTED_REPLACEMENT_REGEX):
						regex = r"%s%s" % (regex[:-len(REFLECTED_REPLACEMENT_REGEX)], REFLECTED_BORDER_REGEX)
					else:
						regex = r"%s\b" % regex

					retVal = re.sub(r"(?i)%s" % regex, REFLECTED_VALUE_MARKER, retVal)

					if len(parts) > 2:
						regex = REFLECTED_REPLACEMENT_REGEX.join(parts[1:])
						retVal = re.sub(r"(?i)\b%s\b" % regex, REFLECTED_VALUE_MARKER, retVal)
	except MemoryError:
		pass
	return retVal


def compatible_remove_reflective_values(content, payload):
	"""
	兼容性考虑，进行反射内容去除
	:param content:
	:param payload:
	:return:
	"""
	page = None
	# Windows系统不支持信号量
	if kb.support_signal is False:
		page = remove_reflective_values(content, payload)

	# UNIX生产环境设置超时
	else:
		try:
			with time_limit(kb.global_time_out):
				page = remove_reflective_values(content, payload)
		except TimeoutException:
			print "[-]remove reflective values in true page time out!"
	return page


def extract_payload(value):
	"""
	从payload定位符之间获取payload
	"""
	_ = re.escape(PAYLOAD_DELIMITER)
	return extract_regex_result("(?s)%s(?P<result>.*?)%s" % (_, _), value)


def page_encoding(content, encoding="utf-8"):
	"""
	将页面进行unicode编码
	:param content:
	:param encoding:
	:return:
	"""
	content = get_unicode(content, encoding=encoding)
	return content


def check_char_encoding(encoding):
	"""
	识别编码的名称
	>>> checkCharEncoding('iso-8858', False)
	'iso8859-1'
	>>> checkCharEncoding('en_us', False)
	'utf8'
	"""

	if encoding:
		encoding = encoding.lower()
	else:
		return encoding

	translate = {"windows-874": "iso-8859-11", "utf-8859-1": "utf8",
				 "en_us": "utf8", "macintosh": "iso-8859-1",
				 "euc_tw": "big5_tw", "th": "tis-620",
				 "unicode": "utf8",  "utc8": "utf8",
				 "ebcdic": "ebcdic-cp-be", "iso-8859": "iso8859-1",
				 "ansi": "ascii", "gbk2312": "gbk", "windows-31j": "cp932"}

	for delimiter in (';', ',', '('):
		if delimiter in encoding:
			encoding = encoding[:encoding.find(delimiter)].strip()

	encoding = encoding.replace("&quot", "")

	if "8858" in encoding:
		encoding = encoding.replace("8858", "8859")
	elif "8559" in encoding:
		encoding = encoding.replace("8559", "8859")
	elif "5889" in encoding:
		encoding = encoding.replace("5889", "8859")
	elif "5589" in encoding:
		encoding = encoding.replace("5589", "8859")
	elif "2313" in encoding:
		encoding = encoding.replace("2313", "2312")
	elif encoding.startswith("x-"):
		encoding = encoding[len("x-"):]
	elif "windows-cp" in encoding:
		encoding = encoding.replace("windows-cp", "windows")

	# name adjustment for compatibility
	if encoding.startswith("8859"):
		encoding = "iso-%s" % encoding
	elif encoding.startswith("cp-"):
		encoding = "cp%s" % encoding[3:]
	elif encoding.startswith("euc-"):
		encoding = "euc_%s" % encoding[4:]
	elif encoding.startswith("windows") and not encoding.startswith("windows-"):
		encoding = "windows-%s" % encoding[7:]
	elif encoding.find("iso-88") > 0:
		encoding = encoding[encoding.find("iso-88"):]
	elif encoding.startswith("is0-"):
		encoding = "iso%s" % encoding[4:]
	elif encoding.find("ascii") > 0:
		encoding = "ascii"
	elif encoding.find("utf8") > 0:
		encoding = "utf8"
	elif encoding.find("utf-8") > 0:
		encoding = "utf-8"

	# Reference: http://philip.html5.org/data/charsets-2.html
	if encoding in translate:
		encoding = translate[encoding]
	elif encoding in ("null", "{charset}", "*") or not re.search(r"\w", encoding):
		return None

	try:
		codecs.lookup(encoding.encode(UNICODE_ENCODING) if isinstance(encoding, unicode) else encoding)
	except (LookupError, ValueError):
		encoding = None

	if encoding:
		try:
			unicode(random_str(), encoding)
		except:
			encoding = None

	return encoding


def valid_content_type(headers):
	"""
	:param headers:
	:return:
	"""
	content_type = None

	if "Content-Type" in headers.keys():
		content_type = headers['Content-Type']

	if content_type is None:
		return False
	else:
		# 拆分text/html; charset=utf-8
		if ";" in content_type:
			content_type = content_type.split(";")[0].strip()
		else:
			content_type = content_type.strip()

		# 设置content-type检测白名单
		if content_type in CONTENT_TYPE_WHITE_LIST:
			return True
		else:
			return False


def content_type_filter(req):
	"""
	对connection进行筛选
	:param req:
	:return:
	"""
	# http头部筛选
	headers = req.headers

	# 对检测的content-type进行筛选
	if not valid_content_type(headers):
		return False
	return True


if __name__ == '__main__':
	pass