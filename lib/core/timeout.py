# -*- coding: utf-8 -*-
"""
对某个函数设置超时时间，主要用于对耗时过长的计算操作进行超时时间的设置，
防止程序长时间卡死，影响扫描效率。
@time_limited(2)
def fn_1(secs):
	time.sleep(secs)
	return 'Finished'

if __name__ == "__main__":
	try:
		print fn_1(4)
	except TimeoutException, e:
		print "Timeout !"
"""
import time
import signal

from contextlib import contextmanager
from lib.core.exception import TimeoutException


@contextmanager
def time_limit(seconds):
	def signal_handler(signum, frame):
		raise TimeoutException, "Timed out!"
	signal.signal(signal.SIGALRM, signal_handler)
	signal.alarm(seconds)
	try:
		yield
	finally:
		signal.alarm(0)


if __name__ == '__main__':
	def method(timeout):
		time.sleep(timeout)

	try:
		with time_limit(5):
			response = method(4)
	except TimeoutException:
		print "TimeoutException"