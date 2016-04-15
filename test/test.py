# coding=utf-8
"""
对扫描误报的注入进行测试
"""
import time
import xlrd
from SqliScanPlugin import SqliScanPlugin
from lib.core.data import conf


def load_data():
	f = open("res.txt", "a")
	tdata = open('tdata.txt', 'a')
	data = xlrd.open_workbook('false_positive.xlsx')
	table = data.sheets()[0]
	for i in xrange(table.nrows):
		row = table.row_values(i)
		stype = row[10]
		if stype == "sql":
			post_data = row[3]
			url = row[4]
			print "testing : ", url, post_data
			tdata.write("%s\t%s\n" % (url, post_data))
	f.close()
	tdata.close()


def main():
	f = open('tdata.txt', 'r')
	wf = open('res.txt', 'a')
	lines = f.readlines()
	i = 0
	start = time.time()
	# 7-55
	for line in lines[56:]:
		if not line:
			continue
		line = line.replace('\n', "").split("\t")
		print line
		post_data = None
		if len(line) == 2:
			url = line[0].strip()
			post_data = (line[1]).strip()
		else:
			url = line[0].replace('\n', "")
		print "For No. %d testing : %s%s" % (i, url, post_data)
		i += 1
		if not post_data:
			scanner = SqliScanPlugin()
			scanner.audit(url)
		else:
			scanner = SqliScanPlugin()
			scanner.audit(url, post_data)
		if conf.hint_payloads:
			wf.write(str(conf.hint_payloads) + "\n")
		print conf.hint_payloads
		print scanner.scan_result
	f.close()
	wf.close()
	print "Time OUT PER TASK：%d" % (float(time.time() - start) / 12)

if __name__ == '__main__':
	main()