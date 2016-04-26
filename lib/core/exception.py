# coding=utf-8
"""
这个文件中定义异常类
"""


class SqliBaseException(Exception):
    pass


class SqliDataException(SqliBaseException):
    pass


class SqliSystemException(SqliBaseException):
    pass


class SqliConnectException(SqliBaseException):
    pass

class TimeoutException(Exception):
    pass