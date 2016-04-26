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
from threading import Thread
from lib.core.exception import TimeoutException

ThreadStop = Thread._Thread__stop


def time_limited(timeout):
	def decorator(function):
		def decorator2(*args, **kwargs):
			class TimeLimited(Thread):
				def __init__(self, _error=None,):
					Thread.__init__(self)
					self._error =  _error

				def run(self):
					try:
						self.result = function(*args, **kwargs)
					except Exception, e:
						self._error = e

				def _stop(self):
					if self.isAlive():
						try:
							self.terminate()
						except Exception, e:
							print "Thread stop error in _stop"

			t = TimeLimited()
			t.setDaemon(True)
			t.start()
			t.join(timeout)

			if isinstance(t._error, TimeoutException):
				t._stop()
				raise TimeoutException('timeout for %s' % (repr(function)))

			if t.isAlive():
				t._stop()
				raise TimeoutException('timeout for %s' % (repr(function)))

			if t._error is None:
				return t.result

		return decorator2
	return decorator


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