# -*- coding: utf-8 -*-
import base64
import binascii
import hashlib
import inspect
import json
import os
import platform
import random
import re
import socket
import string
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta
import pyDes
import copy
# import yaml
from common.logLib import logLib
logger = logLib(__name__)


# region Data conversion and search methods


# 获取json数据
def loadJsonData(source, bAssert=True):
    '''
        convert string to json, default assert it
        :param string source
        :param boolean bAssert
        :return json data
    '''
    resp = None
    try:
        resp = json.loads(source)
    except:
        msg = "not found JSON object, return data %s is not correct" % (source)
        logger.error(msg)
        if bAssert:
            assert False, msg
    return resp


# MD5加密字符串
def md5String(source):
    '''
        encrypt string by md5
        :param string source
        :return string targ
    '''
    logger.info(source)
    if not isinstance(source, str):
        source = repr(source)
    targ = hashlib.md5(source.encode("utf-8")).hexdigest()

    return targ
    # if not isinstance(source, str):
    #     source = repr(source)
    # target = hashlib.md5()
    # target.update(source)
    # targ = target.hexdigest()
    # logger.info(targ)
    #
    # return targ


# 转换成十六进制字符串
def desString(key, source):
    '''
        encrypt string by des
        :param string key
        :param string source
        :return target
    '''
    try:
        logger.info('[DES] try to get DES from key: %s and source: %s' % (key, source))
        k = pyDes.des(key, pyDes.CBC, key, pad=None, padmode=pyDes.PAD_PKCS5)
        target = k.encrypt(source)
        target = binascii.hexlify(target)
        logger.info('[DES] get DES encode string: %s' % (target))
    except Exception as e:
        logger.error('%s: %s' % (e, str(e)))
        assert False, '[DES] get DES encode failed: %s' % (str(e))
    return target


# hash加密字符串，加密方式：sha1
def sha1String(source):
    '''
        encrypt string by sha1
        :param string source
        :return target
    '''
    if not isinstance(source, str):
        source = repr(source)
    target = hashlib.sha1(source).hexdigest()
    return target


# 返回字符串
def toStr(strItem):
    '''
        convert object to str if can, else return raw data
        :param object strItem
        :return string
    '''
    try:
        return str(strItem)
    except:
        return strItem


# 返回int整型
def toInt(item):
    '''
        convert object to int if can, else return raw data
        :param object item
        :return int
    '''
    try:
        return int(item)
    except:
        return item


# 字符串base64加密
def encodeToBase64(path):
    '''
        encode file to base64
        :return None
    '''
    sourceFile = open(path, 'rb')
    bytesTarget = base64.b64encode(sourceFile.read())
    sourceFile.close()
    return str(bytesTarget)


# 分割字符串并返回数组source为分割对象，separator为分割符号，例：
# source = "www.cctalk.com" ，separator = '.' 。 即 source.split('.')
# 返回为： ['www', 'cctalk', 'com']
def convertStringToList(source, separator):
    '''
        convert string to list according to specified separator
        :param string source
        :param string separator
        :return list targetList
    '''
    targetList = []
    tarList = source.split(separator)

    for target in tarList:
        # delete blank space
        target = target.strip(" ")
        targetList.append(target.encode("utf-8"))

    logger.debug(targetList)
    return targetList


# 将字符串时间转换为unix时间
def convertStrTimeToUnixTime(strTime):
    '''
        convert timeString to unixTime
        :param string strTime: like "2015-02-09T09:03:19.123" or "2015-02-09 09:03:19.1" or "2015-02-09 09:03:19"
        :return float unixTime
    '''
    logger.info("convert time from string to unixTime...")
    if len(strTime) > 20:
        strTime = strTime[0:19]

    if "T" in strTime:
        unixTime = time.mktime(time.strptime(strTime, '%Y-%m-%dT%H:%M:%S'))
    else:
        unixTime = time.mktime(time.strptime(strTime, '%Y-%m-%d %H:%M:%S'))

    return unixTime


# 将字符串时间转换为指定格式的字符串时间
def convertStrTimeToDateTime(strTime, formatD='%Y-%m-%dT%H:%M:%S'):
    '''
        convert date string to datetime.
        :param strTime: string, date time string
        :param formatD: string, date time format
    '''
    try:
        date = datetime.strptime(strTime, formatD)
        return date
    except:
        assert False, "strTime: %s, format: %s" % (strTime, formatD)


# 将列表转换为以逗号分隔的字符串
def convertListToStrWithComma(srcList):
    '''
        convert list to string with split by comma
        :param list srcList
        :return string srcStr
    '''
    logger.info("convert list to string with split by comma...")
    srcStr = ""

    for item in srcList:
        srcStr = srcStr + str(item) + ','

    listStr = srcStr[0:-1]
    return listStr


# base64加密或者解密
def base64DecodeAndEncode(data, baseType="encode"):
    '''
        encrypt and decrypted by base64
        :param string data
        :param boolean baseType
        :return string
    '''

    data1 = data.encode(encoding="utf-8")
    if baseType == "encode":
        # base64加
        return base64.b64encode(data1)
    else:
        # base64解
        return base64.b64decode(data1)


# 根据规则从结果中查找字符串
def searchResultfromString(rule, sourceString):
    '''
        find special string from source string according to special rule
        :param string rule
        :param string sourceString
        :return list rsList
    '''
    try:
        regex = re.compile(rule)
        rsList = regex.findall(sourceString)
    except:
        assert False, "find string failed"

    return rsList


# 去除返回中的无效字符
def stripInvalidForResponse(respDict):
    for key, value in list(respDict.items()):
        valueNew = _stripNull(value)
        if 'ip_' in key and "." not in str(valueNew):
            respDict = _convertIp(respDict)
        respDict[key] = valueNew
    return respDict


# 查找'ip_'，并将结果以"."返回
def _convertIp(respDict):
    ipHex = hex(getValue(respDict, 'ip_'))
    tmpList1 = re.findall(r'(.{2})', str(ipHex).replace('0x', ''))
    tmpList2 = tmpList1[-1::-1]
    ipNew = ".".join([str(int(o, 16)) for o in tmpList2])
    respDict.update({'ip_': ipNew})
    return respDict


# 去除首尾空格（看不见的字符串"\x00"）
def _stripNull(value):
    if isinstance(value, str) and "\x00" in value:
        value = value.replace('\x00', '')
    return value


# endregion
# 检查返回结果中有关键字
# region Assert and check methods
def checkKeysInDict(keys, actualDict):
    '''
        check key is not in dict
        :param keys is a list
        :param dict actualDict
    '''
    notFoundKeys = [k for k in keys if k not in actualDict]
    assert len(notFoundKeys) == 0, "the keys: {0} not found in {1}".format(str(notFoundKeys),
                                                                           str(list(actualDict.keys())))


# 检查返回结果中没有关键字
def checkKeysNotInDict(keys, actualDict):
    '''
        check key is not in dict
        :param keys is a list
        :param dict actualDict
    '''
    FoundKeys = [k for k in keys if k in actualDict]
    assert len(FoundKeys) == 0, "the keys: {0} found in {1}".format(str(FoundKeys), str(list(actualDict.keys())))


# 检查返回结果与期望结果相等（assert凹函数只在结果为真时正常，如果为假则触发异常）
def checkResultEqual(actual, expected, msg=None):
    '''
        check actual result does match expected or not
        :param string/list actual
        :param string/list expected
        :param string msg
    '''

    if msg is None:
        msg = "the actual result is %s but the expected is %s" % (actual, expected)

    # eq_(actual, expected, msg)
    assert actual == expected, msg


# 检查返回结果与期望结果在排序后相等
def checkSortedLists(actual_list, expected_list):
    actual_list.sort()
    expected_list.sort()
    checkEqual(actual_list, expected_list)


# 检查返回结果与期望结果相等（相等返回True，不等返回False）
def checkEqual(actualVal, expectedVal, errMsg=None, onlyLogError=False):
    '''
        check actual result does match expected or not
        :param string/list actualVal
        :param string/list expectedVal
        :param string errMsg
        :param boolean onlyLogError
    '''
    logger.info("Check the value '%s' with '%s'" % (toStr(actualVal), toStr(expectedVal)))

    if errMsg is None:
        errMsg = "Expected <font color='red'>'%s'</font> is not as actual " \
                 "<font color='red'>'%s'</font>" % (toStr(expectedVal), toStr(actualVal))

    if actualVal != expectedVal:
        logger.error(errMsg)
        if onlyLogError:
            return False
        else:
            raise AssertionError(errMsg)
    return True


# 检查项item在返回的列表中
def checkItemInList(list, item, errMsg=None, onlyLogError=False):
    '''
        check item does in list or not
        :param list list
        :param object item
        :param string errMsg
        :param boolean onlyLogError
    '''
    logger.info("Check the item '%s' is in list '%s'" % (toStr(item), toStr(list)))

    if errMsg is None:
        errMsg = "Item <font color='red'>'%s'</font> is not in " \
                 "<font color='red'>'%s'</font>" % (toStr(item), toStr(list))

    if item not in list:
        logger.error(errMsg)
        if onlyLogError:
            return False
        else:
            raise AssertionError(errMsg)
    return True


# 检查返字符串相等 （支持模糊匹配）
def checkMatch(strItem, pattern, bCheck=True):
    '''
        check strItem is match pattern or not
        :param string strItem
        :param string pattern
        :param boolean bCheck
        :return boolean
    '''
    logger.info("Check the pattern '%s' is match the item '%s'" % (toStr(pattern), toStr(strItem)))

    if strItem == pattern:
        return True

    strPattern = re.sub(r'\s', '', toStr(pattern))
    strItem = re.sub(r'\s', '', toStr(strItem))
    errMsg = "Pattern <font color='red'>'%s'</font> is not match as <font color='red'>'%s'</font>" % \
             (strPattern, strItem)

    if not re.match(strPattern, strItem):
        logger.error(errMsg)
        if bCheck:
            assert False, errMsg
        return False
    return True


# 检查列表相等
def checkListEqual(actList, expList):
    '''
        check actual list does match expected list or not
        :param list actual
        :param list expected
    '''
    logger.info("check actual list length is equal to expected...")
    lenAct = len(actList)
    lenExp = len(expList)
    checkResultEqual(lenAct, lenExp)
    # if resExp is not null, it means to actual list is equal to expected
    resExp = set(expList) - set(actList)
    # if resAct is not null, it means to expected list is not in actual list
    resAct = set(actList) - set(expList)
    checkResultEqual(resAct, resExp)


# 检查字典相等
def checkTwoDicts(bodyData, expected_data):
    '''
        check two dict is equal or not
        :param dict bodyData
        :param dict expected_data
    '''
    logger.info("Check the dict %s is as expected as dict %s" % (json.dumps(bodyData, ensure_ascii=False),
                                                                 json.dumps(expected_data, ensure_ascii=False),))

    msg = "<font color='red'>the json message should be %s , but the actual is: %s</font>" \
          % (json.dumps(expected_data, ensure_ascii=False), json.dumps(bodyData, ensure_ascii=False))
    if not bodyData == expected_data:
        logger.assertErr(False, msg)


# 检查字典中指定字段的值与期望相等
def checkValueInDict(dict, name, expected, msg=None):
    '''
        check value in dict by key is equal to expected or not
        :param dict dict
        :param string name
        :param object exepected
        :param string msg
    '''

    logger.info("Check the '%s' value in source %s as '%s'" % (name, toStr(dict), toStr(expected)))

    resAct = getValue(dict, name)
    messageStr = " message: %s" % (dict.get("message")) if dict.get("message", "") != "" else ""
    msg = "the actual result is %s but the expected is %s." % (resAct, expected) if msg is None else msg
    msg = "<font color='red'>%s%s</font>" % (msg, messageStr)

    checkEqual(resAct, expected, msg)


# check the length of comments list data when pageT
# 检查列表的长度（index mode）
def _checkDataLengthWithStartLimit(start, limit, lenAct, totalCount, limitD, initialIndex):
    '''
        check the length of comments list data when pageT
        :param int start
        :param int limit
        :param int lenAct
        :param int totalCount
        :param int limitD
        :param int initialIndex
    '''
    logger.info("check the data length of response by index mode")
    if limit == None or limit == "":
        limit = limitD  # default limit value is 10
    if limit <= 0:
        limit = 0
    logger.info("Total count:%s, Limit count:%s, Actual count:%s, Start:%s" \
                % (totalCount, limit, lenAct, start))
    if start > totalCount:
        msg = "start大于totalCount,期望返回数目:0条，实际返回的数目为%d" % (lenAct)
        assert lenAct == 0, msg
    else:
        lenExp = min(limit, totalCount - start + initialIndex)
        msg = "期望返回数目:%s，实际返回的数目为%s" % (lenExp, lenAct)
        assert lenAct == lenExp, msg


# check the length of comments list data when page
# 检查列表的长度（page mode）
def _checkDataLengthWithPageType(start, limit, lenAct, totalCount, limitD, limitMax):
    '''
        check the length of comments list data when page
        :param int start
        :param int limit
        :param int lenAct
        :param int totalCount
        :param int limitD
        :param int initialIndex
    '''
    logger.info("check the data length of response when page type")
    if limit is None or limit == "":
        limit = limitD  # default limit value is 1
    elif limit < 0:
        limit = 0

    start = 1 if start is None or start == "" or start < 0 else start
    limit = min(limit, limitMax) if isinstance(limitMax, int) else limit
    logger.info("TotalCount:%s, Start:%s, Limit:%s, Actual Data count:%s" % (totalCount, start, limit, lenAct))

    if limit > 0 and start <= totalCount / limit:
        assert lenAct == limit, "期望返回数据长度为%s,实际返回数据长度%s" % (limit, lenAct)
    elif limit > 0 and start == totalCount / limit + 1:
        assert lenAct == totalCount % limit, "期望返回数据长度为%s,实际返回数据长度%s" % (totalCount % limit, lenAct)
    else:
        assert lenAct == 0, "期望返回数据长度为0,实际返回数据长度%s" % (lenAct)


# 检查数据长度
def checkDataLength(start, limit, lenAct, totalCount, pageType=0, limitD=30, startD=1, initialIndex=1,
                    limitMax=None):
    '''
        check the order of data list...
        :param int start
        :param int limit
        :param int lenAct
        :param int totalCount
        :param int pageType:0 -- indexMode;1 -- pageMode
        :param int limitD: default value of limit
        :param int startD: default value of start(normal is 1)
        :param int initialIndex: first index of data
        :param int limitMax: max limit
    '''

    logger.info(
        "[checkDataLength] start:%s, limit:%s, lenAct:%s, totalCount:%s, pageType:%s, limitD:%s, startD:%s, initIndex:%s, limitMax:%s" \
        % (start, limit, lenAct, totalCount, pageType, limitD, startD, initialIndex, limitMax))
    start = startD if start is None or start < 0 else start
    limit = limitD if isinstance(limit, int) is False or limit < 0 else limit

    if totalCount < start:
        logger.info("Total:%s, Limit:%s, Actual:%s, Start:%s" % (totalCount, limit, lenAct, start))
        assert lenAct == 0, "The data should be null when start %s larger than totalCount %s,Actual dataLength :%s" % (
            start, totalCount, lenAct)
    elif pageType == 0 or (
                isinstance(pageType, str) and (pageType.lower() == "index" or pageType == "" or pageType == None)):
        logger.info("The data is show by index mode")
        _checkDataLengthWithStartLimit(start, limit, lenAct, totalCount, limitD, initialIndex)
    else:
        logger.info("The data is show by page mode")
        _checkDataLengthWithPageType(start, limit, lenAct, totalCount, limitD, limitMax)


# 检查数据列表的顺序
def checkDataOrder(dataAct, order, orderKey):
    '''
        check the order of data list...
        :param list dataAct
        :param int order: 1-increase;0-decrease
        :param string orderKey
    '''
    logger.info("check the order of response data.")
    if not isinstance(dataAct, list):
        assert False, "Expect input dataAct is list,Actual is %s" % (dataAct)
    keyValueList = []
    logger.info("the data is ordered by %s" % (orderKey))
    for data in dataAct:
        keyValue = getValue(data, orderKey)
        # 以时间作为排序依据时,需要转换时间格式
        if "date" in orderKey.lower():
            t0 = str(convertStrTimeToUnixTime(keyValue)).replace(".0", ".")
            tmp = re.split("\.|\+", keyValue)
            if len(tmp) <= 1:
                ms = "0"
            else:
                ms = tmp[1]
            # 当毫秒级为0时
            if ":" in ms:
                ms = "0"
            # 当毫秒级为0时
            result = eval(t0 + ms)
        else:
            result = keyValue
        keyValueList.append(result)
    indexL = [i for i in range(len(keyValueList))]
    combDataList0 = list(zip(indexL, keyValueList))
    if order == 1:
        combDataList1 = sorted(list(dict(combDataList0).items()), key=lambda d: d[1], reverse=False)
        msg = "Expect response data sorted in ascending order,Actual response:%s" % (combDataList0)
    else:
        combDataList1 = sorted(list(dict(combDataList0).items()), key=lambda d: d[1], reverse=True)
        msg = "Expect response data sorted in descending order,Actual response:%s" % (combDataList0)
    assert combDataList0 == combDataList1, msg


# 检查数据字典
def checkDictionary(expectedDict, actualDict, root=None, bCheck=True):
    '''
        assert expectedDic with actualDic according to expectedDict's keys.
        :param expectedDict: dict
        :param actualDict: dict
        :param root: string message
    '''
    logger.info("Check the dict %s is in dict %s" % (json.dumps(expectedDict, ensure_ascii=False),
                                                     json.dumps(actualDict, ensure_ascii=False),))
    bResult = True
    if root == None:
        logger.info(" check the dictionary value according to expected dictionary's keys:")

    for item in list(expectedDict.items()):
        expected = item[1]
        actual = getValue(actualDict, item[0])
        if isinstance(expected, dict) and isinstance(actual, dict):
            if root != None:
                root += ("=>%s" % (item[0]))
            else:
                root = item[0]
            bResult = trackResult(bResult, checkDictionary(expected, actual, root, False))
        elif isinstance(expected, list):
            for i in range(len(expected)):
                bResult = trackResult(bResult, checkDictionary(expected[i], actual[i], root, False))
        elif isinstance(expected, float) and isinstance(actual, float):
            logger.info(" check %s=>%s(float): actual=%s, expected=%s" % (root, item[0], actual, expected))
            actualValue = "{0:4.4f}".format(actual)
            expectedValue = "{0:4.4f}".format(expected)
            if actualValue != expectedValue:
                logger.error("check %s=>%s: the actual is %s, but expected is %s" % (
                    root, item[0], actualValue, expectedValue))
                bResult = False
        else:
            logger.info(" check %s=>%s: actual=%s, expected=%s" % (root, item[0], actual, expected))
            if actual != expected:
                logger.error("the actual %s value is %s, but expected is %s" % (item[0], actual, expected))
                bResult = False
    if bCheck:
        assert bResult, "Check the dict %s is not in dict %s" % (json.dumps(expectedDict, ensure_ascii=False),
                                                                 json.dumps(actualDict, ensure_ascii=False),)
    return bResult


# 替换result
def trackResult(result, newResult):
    if result:
        result = newResult
    return result


# 检查结果在字典中（bCheck=True完全匹配，bMatch=True模糊匹配）
def checkPartInDict(expectedDict, actualDict, bMatch=False, bCheck=True):
    '''
        check expected dict is in actual dict or not, if bMatch call checkMatch method, if bCheck use assert
        :param dict expectedDict
        :param dict actualDict
        :param boolean bMatch
        :param boolean bCheck
    '''

    logger.info("Check the dict %s is in dict %s" % (json.dumps(expectedDict, ensure_ascii=False),
                                                     json.dumps(actualDict, ensure_ascii=False),))
    bResult = True
    for item in list(expectedDict.items()):
        expected = item[1]
        actual = getValue(actualDict, item[0])
        if isinstance(expected, dict) and isinstance(actual, dict):
            bResult = trackResult(bResult, checkPartInDict(expected, actual, bMatch, False))
        elif isinstance(expected, list) and expected:
            for i in range(len(expected)):
                if isinstance(expected[i], dict):
                    bResult = trackResult(bResult, checkPartInDict(expected[i], actual[i], bMatch, False))
                else:
                    bResult = trackResult(bResult, checkEqual(actual[i], expected[i], False))
        elif not expected:
            bResult = trackResult(bResult, checkEqual(actual, expected))
        elif isinstance(expected, float) and isinstance(actual, float):
            logger.info(" check %s(float): actual=%s, expected=%s" % (item[0], actual, expected))
            actualValue = "{0:4.4f}".format(actual)
            expectedValue = "{0:4.4f}".format(expected)
            if actualValue != expectedValue:
                logger.error("check %s: the actual is %s, but expected is %s" % (
                    item[0], actualValue, expectedValue))
                bResult = False
        else:
            logger.info("check %s: actual=%s, expected=%s" % (item[0], actual, expected))
            if bMatch:
                bResult = trackResult(bResult, checkMatch(actual, expected, False))
            elif actual != expected:
                logger.error("the actual %s value is %s, but expected is %s" % (item[0], actual, expected))
                bResult = False
    if bCheck:
        assert bResult, "Check the dict %s is not in dict %s" % (json.dumps(expectedDict, ensure_ascii=False),
                                                                 json.dumps(actualDict, ensure_ascii=False),)
    return bResult


# 检查是否包含重复的项
def checkListHasDuplicateItem(srcList):
    '''
        check list has duplicateItem, if has duplicate,it will fail
        :param list srcList
    '''

    logger.info("check source list has duplicate item or not...")
    dupList = []
    for item in srcList:
        countItem = srcList.count(item)
        if countItem > 1:
            dupList.append(item)
    logger.info(len(dupList))
    logger.info(dupList)
    assert dupList == [], "The actual eventIdList has duplicated %s item list %s" % (len(dupList), dupList)


# endregion

# region Time methods
# 获取当前时间
def currentTime(fmt='%Y%m%d%H%M'):
    '''
        get current time by the specified format
        :param string fmt
        return datetime
    '''
    currentTime = time.strftime(fmt, time.localtime(time.time()))
    return currentTime


# 获取当前时间（指定格式的）
def currentDateTime(fmt='%Y-%m-%d %H:%M:%S.%f'):
    '''
        get current date time by the specified format
        :param string fmt
        return datetime
    '''

    return datetime.strftime(datetime.now(), fmt)


# 从主机ID、序列号和当前时间获取UUID
def getUUidByTimeStamp():
    '''
        get uuid by time stamp
        :return string uuidResult
    '''

    uuidResult = str(uuid.uuid1())
    return uuidResult


# 根据当前时间，获取指定时间差的信息时间（diffType：时间差类型，diff：时间差值，flag：时间差前移后移标记，plus表示将来时间，用+）
def getNewDiffTimeForCurrent(diffType, diff, flag='plus', currentTime=None, dateFormat=None):
    '''
        get the new time that current time + or - [%diffType%]=diff
        :param string diffType: like days, hours...
        :param int diff: like 1,10
        :param string flag: "plus" or "sub"
        :param string currentTime
        :param string dateFormat
        :return datetime newTime or string newTimeToString
    '''
    logger.info("get the new time according to date format...")
    if dateFormat == None or dateFormat == "":
        dateFormat = '%Y-%m-%d %H:%M:%S'

    if currentTime == None:
        currentTime = datetime.now()
    else:
        currentTime = datetime.strptime(currentTime, dateFormat)

    if flag.lower() == "plus":
        if diffType == "days":
            newTime = currentTime + timedelta(days=diff)
        if diffType == "hours":
            newTime = currentTime + timedelta(hours=diff)
        if diffType == "minutes":
            newTime = currentTime + timedelta(minutes=diff)
        if diffType == "seconds":
            newTime = currentTime + timedelta(seconds=diff)
    else:
        if diffType == "days":
            newTime = currentTime - timedelta(days=diff)
        if diffType == "hours":
            newTime = currentTime - timedelta(hours=diff)
        if diffType == "minutes":
            newTime = currentTime - timedelta(minutes=diff)
        if diffType == "seconds":
            newTime = currentTime - timedelta(seconds=diff)
    if currentTime == None:
        logger.debug(newTime)
        return newTime
    else:
        logger.debug(newTime)
        newTimeToString = datetime.strftime(newTime, dateFormat)
        return newTimeToString


# 判断时间是否相等
def isValueDate(strDate, formatD='%Y-%m-%dT%H:%M:%S'):
    '''
        check is the string date is match the format when convert it to datetime
        :param string strDate
        :param string formatD
        :return boolean
    '''

    if formatD == None:
        formatD = '%Y-%m-%dT%H:%M:%S'
    try:
        time.strptime(strDate, formatD)
        return True
    except:
        return False


# 判断是否是是闰年
def isLeapYear(year):
    '''
        check the year is leap year or not
        :param int year
        :return boolean
    '''
    year = int(year)
    if (year % 4) == 0:
        if (year % 100) == 0:
            if (year % 400) == 0:
                return True
            else:
                return False
        else:
            return False
    else:
        return False


# endregion

# region Get value methods

# 获取AppKey
def getAppKey(source, start=3, end=-6):
    '''
        get App Key
        :param string source
        :return string target
    '''

    target = base64.decodebytes(bytes(source[start:end] + "=", "utf8")).decode('utf8')
    return target


# 检查结果不为空
def checkResultIsNotNone(actValue, msg=None):
    '''
        check the value is not None
        :param object actValue
        :param string msg
    '''
    logger.info("check result is not None...")
    if actValue == None or actValue == "" or actValue == [] or actValue == {}:
        if msg == None:
            msg = "The actValue should be not null"
        assert False, msg


# 返回指定键的值，如果值不在字典中返回默认值
def getValue(source, name, msg=None):
    '''
        get dict key-value
        :param dict source
        :param string name: dict key
        :return string/int/boolean value: dict value
    '''
    try:
        valueMsg = "Not found (%s) in source %s" % (name, source)
        value = source.get(name, valueMsg)
        if value == valueMsg:
            logger.error(valueMsg)
            assert False, valueMsg
    except:
        if msg == None:
            msg = "cannot found name %s in source %s" % (name, source)
        logger.error(msg)
        assert False, msg

    return value


# 检查指定值在字典中
def getValueInDict(dict, name, msg=None):
    logger.info("Get the value '%s' in dict %s" % (name, str(dict)))

    for item in name.split('.'):
        try:
            dict = dict[toInt(item)]
        except:
            if msg is None:
                msg = "Cannot find the key '%s' in dict %s" % (item, str(dict))
            logger.assertErr(False, msg)
    return dict


# 根据环境配置获取对应的环境的值
# def get_value_from_env_data_dict(data_dict, env_map_dict=None, use_default_mapping=False):
#     '''
#         :param dict data_dict: envEnum.qa2: 159892, envEnum.yz: 159893
#         :param dict env_map_dict: env mapping, .i.e {"qa3": "qa2"}
#     '''
#     cur_env = envEnum.curEnv
#     if env_map_dict and cur_env in env_map_dict:
#         cur_env = env_map_dict[cur_env]
#     elif use_default_mapping:
#         cur_env = {
#             envEnum.qa: envEnum.qa,
#             envEnum.qa1: envEnum.qa,
#             envEnum.qa2: envEnum.qa,
#             envEnum.qa3: envEnum.qa,
#             envEnum.qa4: envEnum.qa,
#             envEnum.qa5: envEnum.qa,
#             envEnum.qa6: envEnum.qa,
#             envEnum.yz: envEnum.prod,
#             envEnum.pre: envEnum.prod,
#             envEnum.prod: envEnum.prod,
#             envEnum.ci: envEnum.ci,
#             envEnum.pt: envEnum.qa
#         }[cur_env]
#     return getValue(data_dict, cur_env)

# 根据环境配置获取对应的环境的值
# 环境数据对应关系如下：
# qa、qa1、qa2、qa3、qa4、qa5、qa6 都取 qa 的数据
# prod、yz 都取 prod 的数据
# def get_value_from_env_data_dict_for_data(data_dict, env_map_dict=None, use_default_mapping=True):
#     '''
#         :param dict data_dict: envEnum.qa2: 159892, envEnum.yz: 159893
#         :param dict env_map_dict: env mapping, .i.e {"qa3": "qa2"}
#     '''
#     cur_env = envEnum.curEnv
#     if env_map_dict and cur_env in env_map_dict:
#         cur_env = env_map_dict[cur_env]
#     elif use_default_mapping:
#         cur_env = {
#             envEnum.qa: envEnum.qa,
#             envEnum.qa1: envEnum.qa,
#             envEnum.qa2: envEnum.qa,
#             envEnum.qa3: envEnum.qa,
#             envEnum.qa4: envEnum.qa,
#             envEnum.qa5: envEnum.qa,
#             envEnum.qa6: envEnum.qa,
#             envEnum.yz: envEnum.prod,
#             envEnum.pre: envEnum.prod,
#             envEnum.prod: envEnum.prod,
#             envEnum.ci: envEnum.ci,
#             envEnum.pt: envEnum.qa
#         }[cur_env]
#     return getValue(data_dict, cur_env)


# 从a-z生成随机字符串返回用户名
def getUserName():
    '''
        Combine a userName for register
        :return string userName
    '''

    letters = "abcdefghijklmnopqrstuvwxyz"
    head = getRandomElem(letters)
    middle = str(time.time())
    letters = letters + "_"
    tail = getRandomElem(letters)
    userName = head + middle[1:10] + tail
    return userName


# 根据长度生成字符串
def getRandomContentByLength(length):
    '''
        get random length of content
        :param int length
        :return string
    '''

    letters = string.ascii_letters + string.digits + " ._!@#$%^&*()_+=?/<>,中国沪江上海北京浦软大厦张江"
    content = ""
    i = 0
    while i < length:
        content += random.choice(letters)
        i += 1

    return content


# 根据提供的source生成随机字符串
def getRandomElem(source):
    '''
        random one element from source
        :param string/list source
        :return string elem
    '''

    elem = random.choice(source)

    return elem


# 根据区间生成随机数
def randNumber(start, end):
    '''
        get random number between start and end
        :param int start
        :param int end
        :return int
    '''
    randNumber = str(random.randint(start, end))
    return randNumber


# 拆分object属性
def split_object_attributes(name):
    '''
    return the object name and index
    :param self:
    :param name:
    :return:
    '''
    if isinstance(name, str):
        if name.find(",index=") > -1:
            objectarr = name.split(",index=")
            name = objectarr[0]
            other = objectarr[1]
            index = int(other)
            return (name, index)
        else:
            index = 0
            return (name, index)
    else:
        index = 0
        return (name, index)


'''
    generate random string from letters and digit
    :param int length
'''


# 生成指定长度的随机字符串
def getRandomString(length, prefix='', type=None):
    '''
    generate random string from letters and digit
    :param int length
    '''
    prefix = str(prefix)
    if length <= len(prefix): return prefix
    length = length - len(prefix)

    if str(type).lower() == 's':
        asciiString = string.ascii_letters
    elif str(type).lower() == 'd':
        asciiString = string.digits
    else:
        asciiString = string.ascii_letters + string.digits

    asciiLen = len(asciiString)
    randomString = ''

    if length <= asciiLen:
        randomString = randomString.join(random.sample(asciiString, length))
    else:
        count = length / asciiLen
        remainder = length % asciiLen

        randomString = randomString.join(random.sample(asciiString, remainder))
        while count > 0:
            randomString = randomString + ''.join(random.sample(asciiString, asciiLen))
            count = count - 1

    return prefix + randomString


# 合并列表
def getIntersectionOfCoupleList(list01, list02):
    '''
        get intersection of couple list
        :param list list01
        :param list list02
    '''
    mixList = [item for item in list02 if item in list01]
    return mixList


# 获取文件的MD5校验码
def getMd5ForFile(absPath):
    '''
        get md5 for file
        :param string absPath
        :return string
    '''

    if os.path.exists(absPath):
        fObj = open(absPath, 'rb')
        m = hashlib.md5()
        m.update(fObj.read())
        fileMd5 = m.hexdigest()
        logger.info("MD5 for File: {}".format(fileMd5))
        print("~~~file md5~~~")
        print(fileMd5)
        fObj.close()
        return fileMd5
    else:
        assert False, "The file is not exist"


# 生成abs路径
def genAbsPath(*args):
    '''
        generate abs path
        :param args:
        :return:
    '''

    if len(args) == 0:
        assert False, "Haven't give relative path"
    relPath = ''
    for item in args:
        if item.startswith('\\') or item.startswith('/'):
            item = item.replace('\\', '/', )
            item = item.replace('/', '', 1)
        relPath = os.path.join(relPath, item)
    absPath = os.path.join(os.getcwd(), relPath)
    absPath = absPath.replace('\\', '/')
    return absPath


# 获取时间戳
def getTimestamp():
    '''
        get timestamp.
        :return string timestamp
    '''

    base = datetime(1, 1, 1)
    now = datetime.utcnow()
    result = "{0:.0f}".format((now - base).total_seconds() * 1e7)
    return result


# 获取本机IP
def getLocalIpAddress():
    '''
        get local ip address
        :return string
    '''

    name = socket.getfqdn(socket.gethostname())
    return socket.gethostbyname(name)


# 获取本机mac地址
def getMacAddress():
    '''
        get random mac address
        :return string
    '''
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])


# 获取多个结果
def getResultMultiLevel(keyList, valueList):
    resultList = []
    for i, keys in enumerate(keyList):
        if i >= len(valueList):
            break
        values = valueList[i]
        values = _stripNull(values)
        respDict = dict(list(zip(keys, values)))
        if 'ip_' in respDict and "." not in str(respDict['ip_']):
            respDict = _convertIp(respDict)
        resultList.append(respDict)
    return resultList


# 获取单个结果
def getResultSingleLevel(keyList, valueList):
    values = _stripNull(valueList)
    respDict = dict(list(zip(keyList, values)))
    if 'ip_' in respDict and "." not in str(respDict['ip_']):
        _convertIp(respDict)
    return respDict


# 获取当前方法名
def geCurrentfunctionName():
    '''
        get current function name
        :return string
    '''
    return inspect.stack()[1][3]


# 获取路径下文件列表
def getListFiles(path):
    '''
        get file list in path
        :return list
    '''

    ret = []
    for root, dirs, files in os.walk(path):
        for filespath in files:
            ret.append(os.path.join(root, filespath))
    return ret


# 获取指定格式时间戳（可指定偏移量timeDelta）
def get_formatteddate_with_delta(dateTime=datetime.now(), timeDelta=None, formatter="%Y-%m-%d %H:%M:%S"):
    '''
        get datetime by delta with the specified format
        :param datetime datetime
        :param timeDelta timeDelta
        :param string formatter
        :return datetime
    '''
    if not isinstance(dateTime, datetime):
        return None
    if timeDelta is not None and not isinstance(timeDelta, timedelta):
        return None
    if timeDelta is None:
        timeDelta = timedelta(days=0)
    return (dateTime + timeDelta).strftime(formatter)


# 获取指定格式时间戳
def get_currenttime_as_timestamp(formatter="%Y%m%d%H%M%S"):
    '''
        get current time by the specified format
        :param string formatter
        return datetime
    '''
    return datetime.now().strftime(formatter)


# 获取随机RGB颜色
def get_random_color_hex():
    '''
        get random color with hex format
        :return string
    '''

    return "#%s" % str(hex(random.randint(257, 16777215))).replace('0x', '')


# 获取URL中参数的值（忽略大小写）
def get_url_parameter_ignore_case(url, key):
    '''
        get value of parameter in url with ignore case
        :param string url
        :param string key
        :return string
    '''
    url = url.lower()
    key = key.lower()
    try:
        parsed = urllib.parse.urlparse(url)
        querys = urllib.parse.parse_qs(parsed.query)
        value = querys[key][0]
        return value
    except Exception:
        return None


# 获取参数的值
def __getParaValues(args, index, paraValues, paraValue, kwargs):
    for item in args[index]:
        if len(args) == index + 1:
            itemValue = copy.copy(paraValue)
            itemValue.append(item)
            if "mustValue" in kwargs:
                if kwargs['mustValue'] in itemValue:
                    paraValues.append(itemValue)
            else:
                paraValues.append(itemValue)
        else:
            if index == 0:
                paraValue = []
            itemValue = copy.copy(paraValue)
            itemValue.append(item)
            __getParaValues(args, index + 1, paraValues, itemValue, kwargs)


# 获取所有参数的值
def getAllParameterizedValues(*args, **kwargs):
    logger.info("get all possible parameterized values %s" % str(args))

    paraValues = []
    __getParaValues(args, 0, paraValues, [], kwargs)
    return paraValues


# 获取随机参数的值
def getRandomParameterizedValues(randCount, *args, **kwargs):
    logger.info("get %d random possible parameterized values %s" % (randCount, str(args)))

    paraValues = []
    iCount = 1
    for arg in args:
        iCount *= len(arg)
    if randCount > iCount:
        logger.assertErr(False, 'randCount %d cannot be larger than possible count %d' % (randCount, iCount))

    while len(paraValues) < randCount:
        paraValue = []
        for arg in args:
            paraValue.append(arg[random.randint(0, len(arg) - 1)])
        if not paraValue in paraValues:
            if "mustValue" in kwargs:
                if kwargs['mustValue'] in paraValue:
                    paraValues.append(paraValue)
            else:
                paraValues.append(paraValue)
    return paraValues


# 根据数据类型返回数据（如果是整数，返回int类型的数据；否则返回float类型的数据）
def getValueTryRemoveTailZero(float_num):
    """
        try to remove .0 from an float number, 2.00 -> 2
        keep other float as it was, 2.02 -> 2.02
        :param float float_num
        :return float/int
    """

    int_num = int(float_num)
    if int_num == float_num:
        return int_num
    return float_num


# 转化为金钱表示法：小数部分保留两位小数，整数部分每隔三位使用一个“，”分隔
def getMoneyFormatNumber(int_float_num):
    """
        return the value as money format, 12345 -> 12,345
        :param int/float int_float_num
        :return string
    """

    if isinstance(int_float_num, int):
        return '{:,}'.format(int(int_float_num))
    elif isinstance(int_float_num, float):
        return '{:,}'.format(float(int_float_num))


# 获取编码格式
def getCodingFormat(strInput):
    '''
    获取编码格式
    '''
    if isinstance(strInput, str):
        return "unicode"
    try:
        strInput.decode("utf8")
        return 'utf8'
    except:
        pass
    try:
        strInput.decode("gbk")
        return 'gbk'
    except:
        pass


# endregion

# region Action methods

# 根据参数运行指定方法？
def runBatchTests(func, funcParams, paramList, apiMsg):
    """
        :param func: pint, function point.
        :param funcParams: tuple or list, function parameter list.
        :param paramList: list, tuple list
        :param apiMsg: string, test api message.
    """
    logger.info("======== Start to run batch tests for api: %s ========" % (apiMsg))
    print("======== Start to run batch tests for api: %s ========" % (apiMsg))
    if paramList is not None and len(paramList) > 0:
        result = {"index": 0, "failCount": 0, "passCount": 0, "errorCount": 0}

        msgList = []
        failMsgList = []
        for params in paramList:
            result["index"] += 1
            msg = "====>[%s] [Test: %s] " % (apiMsg, result["index"])
            try:
                func(*params)
                result["passCount"] += 1
                msg = "%s Pass" % (msg)
            except Exception as e:
                if isinstance(e, AssertionError):
                    result["failCount"] += 1
                    msg = "%s Fail:\t%s" % (msg, e)
                else:
                    result["errorCount"] += 1
                    msg = "%s Error:\t%s" % (msg, e)
                failMsgList.append(msg)
            logger.info(msg)
            print(msg)
            msgList.append(msg)

        sResult = "======== End test for api: %s => Total: %s, Pass: %s, Fail: %s, Error: %s" % (apiMsg,
                                                                                                 result["index"],
                                                                                                 result["passCount"],
                                                                                                 result["failCount"],
                                                                                                 result["errorCount"])
        sResult += ("\n" + "\n".join(failMsgList)) if len(failMsgList) > 0 else ""
        logger.info(sResult)
        print(sResult)
        assert len(failMsgList) == 0, "[Result] test API: %s => FAIL\n%s" % (apiMsg, "\n".join(failMsgList))
    else:
        print("[Error] parameter inputList length should greater than 1.")


# 从yaml路径返回对象
# def loadDataFromYaml(yamlPath):
#     '''
#         get data from yaml
#         :param string yamlPath
#         :return object
#     '''
#
#     yamlPath = os.path.join(os.getcwd(), yamlPath).replace('\\', '/')
#     return yaml.load(open(yamlPath))


# 根据名称杀掉线程
def killProcessByName(processName):
    '''
        kill process by process name at windows platform
        :param string processName
    '''

    logger.info("Kill the pcocess '%s'" % processName)

    try:
        if platform.system() == "Windows":
            os.system("taskkill /f /im %s.exe" % processName)
        else:
            os.system("killall %s" % processName)
    except:
        pass


# endregion

def __end_of_file():
    pass
