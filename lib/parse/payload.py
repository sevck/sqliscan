# coding=utf-8

import os

from xml.etree import ElementTree as et
from lib.core.data import paths
from lib.core.data import conf
from lib.core.data import AttribDict
from lib.core.exception import SqliSystemException


def cleanup_vals(text, tag):
    if tag in ("clause", "where"):
        text = text.split(',')

    if isinstance(text, basestring):
        text = int(text) if text.isdigit() else text

    elif isinstance(text, list):
        count = 0

        for _ in text:
            text[count] = int(_) if _.isdigit() else _
            count += 1

        if len(text) == 1 and tag not in ("clause", "where"):
            text = text[0]

    return text


def parse_xml_node(node):
    """
    对边界策略文件和payload文件进行解析
    使用conf.boundaries和conf.tests表示
    """
    for element in node.getiterator('boundary'):
        boundary = AttribDict()

        for child in element.getchildren():
            if child.text:
                values = cleanup_vals(child.text, child.tag)
                boundary[child.tag] = values
            else:
                boundary[child.tag] = None
        conf.boundaries.append(boundary)

    for element in node.getiterator('test'):
        test = AttribDict()

        for child in element.getchildren():
            if child.text and child.text.strip():
                values = cleanup_vals(child.text, child.tag)
                test[child.tag] = values
            else:
                if len(child.getchildren()) == 0:
                    test[child.tag] = None
                    continue
                else:
                    test[child.tag] = AttribDict()

                for gchild in child.getchildren():
                    if gchild.tag in test[child.tag]:
                        prevtext = test[child.tag][gchild.tag]
                        test[child.tag][gchild.tag] = [prevtext, gchild.text]
                    else:
                        test[child.tag][gchild.tag] = gchild.text

        conf.tests.append(test)

    for element in node.getiterator('dbms'):
        for child in element.getchildren():
            reg = child.get('regexp')
            conf.errors.append(reg)

def load_boundaries():
    try:
        doc = et.parse(paths.BOUNDARIES_XML)
    except Exception, ex:
        err_msg = "something seems to be wrong with "
        err_msg += "the file '%s'. Please make " % paths.BOUNDARIES_XML
        err_msg += "sure that you haven't made any changes to it"
        raise SqliSystemException(err_msg)
    root = doc.getroot()
    parse_xml_node(root)


def load_payloads():
    payloadFiles = os.listdir(paths.PAYLOADS_PATH)
    payloadFiles.sort()

    for payloadFile in payloadFiles:
        payloadFilePath = os.path.join(paths.PAYLOADS_PATH, payloadFile)
        try:
            doc = et.parse(payloadFilePath)
        except Exception, ex:
            errMsg = "something seems to be wrong with "
            errMsg += "the file '%s'. Please make " % payloadFilePath
            errMsg += "sure that you haven't made any changes to it"
            raise SqliSystemException(errMsg)
        root = doc.getroot()
        parse_xml_node(root)


def load_errors():
    try:
        doc = et.parse(paths.ERRORS)
    except Exception, ex:
        errMsg = "something seems to be wrong with "
        errMsg += "the file '%s'. Please make " % paths.ERRORS
        errMsg += "sure that you haven't made any changes to it"
        raise SqliSystemException(errMsg)
    root = doc.getroot()
    parse_xml_node(root)


if __name__ == '__main__':
    conf.boundaries = []
    conf.tests = []
    paths.BOUNDARIES_XML = "D:/codes/sqlidemo/xml/boundary.xml"
    paths.PAYLOADS_PATH = "D:/codes/sqlidemo/xml/payloads"
    paths.ERRORS = "D:/codes/sqlidemo/xml/errors.xml"
    load_boundaries()
    load_payloads()
    load_errors()
    # print conf.boundaries
    # print conf.tests
    print conf.errors