# coding=utf-8


class GeneralPOCBase(object):
	def __init__(self):
		"""
		setting dict POC相关设置
		poc_info poc的相关信息
		scan_result poc扫描需要返回的结果
		"""
		self.setting = {
			"place": {
				"cookie": 0,
				"params": 1,
				"ua": 0,
				"url_rewrite": 0,
				"headers": 0
			},
		}

		self.poc_info = {
			"author": "",
			"name": "",
			"vulType": "",
			"desc": "",
			"createDate": "",
			"level": ""
		}
		self.scan_result = {
			"type": "",
			"appName": "",
			"url": "",
			"method": "",
			"payload": "",
			"pocInfo": None,
			"attackInfo": None
		}

	def audit(self, target, body=None, cookies=None):
		pass

	def attack(self, target):
		pass



