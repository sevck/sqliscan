# coding=utf-8


class PluginPOCBase(object):
	def __init__(self):
		"""
		poc_info dict POC的信息
		scan_result dict 扫描结果
		"""

		self.poc_info = {
			"id": "",
			"author": "",
			"name": "",
			"vulType": "",
			"references": "",
			"appName": "" ,
			"appVersion": "",
			"desc": "",
			"createDate": "",
			"level": ""
		}
		self.scan_result = {
			"type": "",
			"status": "",
			"appName": "",
			"url": "",
			"method": "",
			"payload": "",
			"pocInfo": None,
			"attackInfo": None
		}

	def audit(self, target):
		pass

	def attack(self, target):
		pass



