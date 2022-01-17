# -*- coding: utf-8 -*-

from datetime import datetime
import inspect
import json
import os
import re
import threading
import time
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import requests
from multiprocessing import Pool
from lxml import etree
import common.commonBase as commonBase
from common.logLib import logLib
from common import globalVariables
from requests_toolbelt import MultipartEncoder
import codecs

try:
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning

    urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass


class baseRequest(object):
    # region Variables
    method = None
    url = None
    data = None
    headers = None
    cookies = None
    files = None
    multipartEncodedContent = None
    logger = logLib(__name__)

    # endregion

    def __init__(self, method='post', url=None, data=None, headers=None, cookies=None, files=None,
                 multipartEncodedContent=None, timeout=30):
        self.method = method
        self.url = url
        self.data = data
        self.headers = headers
        self.cookies = cookies
        self.files = files
        self.multipartEncodedContent = multipartEncodedContent

        self.srcList = []
        self.failedUrlList = []
        self.bChecking = False
        self.timeout = timeout

    # region Methods for requests
    def appendApiLog(self, url, method='Get', request_info=None):
        try:
            filePath = os.getcwd() + "/data/api_log.txt"
            if os.path.exists(globalVariables.tempLogDir):
                filePath = globalVariables.tempLogDir + "/api_log.txt"
            url = url.replace("http://", "").replace("https://", "").replace('//', '/')
            if len(url) > 255:
                url = url[:254]

            tcName = ""
            caseName = ""
            module = ""
            stacks = inspect.stack()
            tcStack = None
            for stack in stacks:
                if stack[1].find("\\testcase\\") > 0 or stack[1].find("/testcase/") > 0:
                    tcStack = stack
            if tcStack is not None:
                module = tcStack[1].replace('\\', '.').replace('/', '.').replace('.py', '')
                module = module[module.find('hujiang.'):]
                caseName = str(tcStack[3])
                tcName = module + "$" + caseName + "$"
            file = codecs.open(filePath, 'a', 'utf-8')
            file.write("%s$%s%s$%s\r\n" % (str(datetime.now()), tcName, urllib.parse.quote(url), method.upper()))
            file.close()

            globalVariables.apiLogs.append({
                'case_module': module,
                'case_name': caseName,
                'case_guid': globalVariables.case_guid,
                'url': urllib.parse.quote(url),
                'method': method.upper(),
                'request_info': request_info,
                'date_time': str(datetime.now())
            })
        except:
            pass

    def get_request_info(self, resp, start_time):
        request_info = {
            "time_span": (datetime.now() - start_time).total_seconds(),
            "request_header": self.headers,
            "body": commonBase.toStr(self.data)[:1000],
        }
        try:
            request_info.update({
                "http_code": resp.status_code,
                "response_header": commonBase.toStr(resp.headers)[:1000],
                "response_content": resp.content[:2000].decode("utf-8")
            })
        except:
            request_info.update({
                "http_code": '',
                "response_header": '',
                "response_content": ''
            })
        try:
            request_info.update({
                "detail_time": {
                    '1 connection_time': resp.validate_conn_time,
                    '2 first_buffer_time': resp.first_buffer_time.total_seconds(),
                    '3 receive_time': resp.receive_time.total_seconds(),
                    '4 request_other': round(resp.request_time.total_seconds() - resp.validate_conn_time -
                                             resp.first_buffer_time.total_seconds() - resp.receive_time.total_seconds(),
                                             3),
                    '5 other': round(request_info['time_span'] - resp.request_time.total_seconds(), 3)
                }
            })
        except Exception as e:
            request_info.update({
                "detail_time": {}
            })
        return request_info

    def sendJsonRequestReturnRawData(self, retry_num=3):
        """
        Send Json request with method post or get
        :param url, string
        :param data, dict
        :param method: string, current supports: get, post, put and delete.
        :param headers, dic
        :param cookies, dict
        :return resp: response object
        """
        self.url = self.replace_domain_to_hostip(self.url)
        self.logger.info("[Request]: %s %s" % (self.method.upper(), self.url))

        if self.headers is None or self.headers == "":
            self.headers = {'Content-Type': 'application/json', 'Accept': 'text/plain', 'User-Agent': 'hjqa'}
        elif 'hjqaAction' not in self.headers:
            keys = ','.join(list(self.headers.keys()))
            self.headers.update({'Content-Type': 'application/json'}) if re.match('Content-Type', keys,
                                                                                  re.I) is None else None
        self.headers.update(
            {'User-Agent': 'hjqa'}) if 'User-Agent' not in self.headers and 'user-agent' not in self.headers else None
        self.logger.info("[Request.headers]: %s" % (self.headers))
        self.logger.info('[Request.data]: %s' % (json.dumps(self.data, ensure_ascii=False))) \
            if self.data is not None else None
        self.logger.info('[Request.cookies]: %s' % (self.cookies)) if self.cookies is not None else None

        if self.data is not None and not type(self.data) in [str, int, float]:
            self.data = json.dumps(self.data)
        elif self.data == "":
            self.data = None
        start_time = datetime.now()
        resp = None

        for i in range(retry_num):
            try:
                bContinue = False
                # self.headers.update({'Connection': 'close'})
                if self.method.lower() == 'post':
                    if "https" in self.url:
                        resp = requests.post(self.url, data=self.data, headers=self.headers, stream=True,
                                             verify=False, cookies=self.cookies, timeout=self.timeout)
                    else:
                        resp = requests.post(self.url, data=self.data, headers=self.headers, stream=True,
                                             cookies=self.cookies, timeout=self.timeout)
                elif self.method.lower() == 'get':
                    if "https" in self.url:
                        resp = requests.get(self.url, headers=self.headers, verify=False, stream=True,
                                            cookies=self.cookies, timeout=self.timeout)
                    else:
                        resp = requests.get(self.url, headers=self.headers, cookies=self.cookies,
                                            stream=True, timeout=self.timeout)
                elif self.method.lower() == 'put':
                    if "https" in self.url:
                        resp = requests.put(self.url, data=self.data, headers=self.headers, stream=True,
                                            verify=False, cookies=self.cookies, timeout=self.timeout)
                    else:
                        resp = requests.put(self.url, data=self.data, headers=self.headers, stream=True,
                                            cookies=self.cookies, timeout=self.timeout)
                elif self.method.lower() == 'delete':
                    if "https" in self.url:
                        resp = requests.delete(self.url, data=self.data, headers=self.headers, stream=True,
                                               verify=False, cookies=self.cookies, timeout=self.timeout)
                    else:
                        resp = requests.delete(self.url, data=self.data, headers=self.headers, stream=True,
                                               cookies=self.cookies, timeout=self.timeout)
                elif self.method.lower() == "patch":
                    if "https" in self.url:
                        resp = requests.patch(self.url, data=self.data, headers=self.headers, verify=False,
                                              stream=True, cookies=self.cookies, timeout=self.timeout)
                    else:
                        resp = requests.patch(self.url, data=self.data, headers=self.headers,
                                              stream=True, cookies=self.cookies, timeout=self.timeout)
                else:
                    assert False, "The request method %s is not in ['post','get','put','delete']"
                break
            except Exception as e:
                print("[Request Exception] {0}: {1}".format(type(e), e))
                msg = "send request [%s] %s failed: %s" % (self.method, self.url, str(e))
                self.logger.info(e)
                self.logger.info(msg)
                try:
                    sock = resp.raw._connection.sock
                    self.logger.error("error url socket is {}".format(str(resp.raw._connection.sock)))
                    if sock:
                        self.logger.error("error ip and host is {}".format(sock.getpeername()))
                    else:
                        self.logger.error("has not socket!")
                except:
                    pass
                if (str(e).find('Max retries exceeded') > 0 or str(e).find('Read timed out') > 0 or
                    str(e).find('Connection aborted') > -1) and i + 1 < retry_num:
                    time.sleep(10)
                    bContinue = True
                    continue
                assert False, msg
            finally:
                if not bContinue:
                    request_info = self.get_request_info(resp, start_time)
                    self.appendApiLog(self.url, self.method, request_info)
        return resp

    def sendJsonRequest(self, httpStatusExp=200, bText=True):

        resp = self.sendJsonRequestReturnRawData()
        resp.encoding = 'UTF-8'

        try:
            respTxt = json.dumps(resp.json(), ensure_ascii=False)
        except:
            if bText:
                respTxt = resp.text
            else:
                respTxt = resp.content

        self.logger.info("[Response.status_code]: {0}".format(resp.status_code))
        self.logger.info("[Response.content]: {0}\n".format(respTxt))

        if httpStatusExp:
            commonBase.checkResultEqual(resp.status_code, httpStatusExp,
                                        '[Request] resp.status_code: %s is not %s' % (resp.status_code, httpStatusExp))
        return respTxt

    def sendJsonRequestReturnDict(self, httpStatusExp=200, statusExp=None, bText=True):
        self.logger.info("Send Json request and check the http status to '%s', then return dict" % httpStatusExp)

        respTxt = self.sendJsonRequest(httpStatusExp, bText)

        jsonResp = commonBase.loadJsonData(respTxt)

        if statusExp is not None:
            commonBase.checkValueInDict(jsonResp, "status", statusExp,
                                        "[Request] resp data['status'] does not match with %s" % str(statusExp))
        return jsonResp

    def sendSingleRequest(self, url):
        '''
        send single request
        :param string url
        :return dict resp
        '''
        self.logger.info("send single request...")
        url = self.replace_domain_to_hostip(url)
        try:
            headers = {'User-Agent': 'hjqa'}
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req)
            self.appendApiLog(url)
        except urllib.error.URLError as e:
            if 'api.site.hujiang.com' in url or 'portal.hjapi.com' in url:
                msg = str(e) + " URL:{}".format(url)
            else:
                msg = e
            assert False, msg

        try:
            self.logger.info("load JSON response...")
            resp = json.loads(response.read())
            self.debug("the actual response is: %s" % (resp))
        except:
            msg = "Not found JSON object, the return data format is not correct"
            if 'api.site.hujiang.com' in url or 'portal.hjapi.com' in url:
                msg = "Not found JSON object, the return data format is not correct. URL:{}".format(url)
            self.logger.info(msg)
            assert False, msg

        return resp

    def sendMultipartRequest(self, requireJson=True, bText=True, httpStatusExp=None, statusExp=None):
        '''
        Send Multipart request with method post or get
        '''
        self.url = self.replace_domain_to_hostip(self.url)
        resp = None
        if not isinstance(self.multipartEncodedContent, MultipartEncoder):
            raise RuntimeError("multipartEncodedContent invalid")
        self.headers = {} if not self.headers else self.headers
        self.headers.update({'User-Agent': 'hjqa', 'Content-Type': self.multipartEncodedContent.content_type})
        start_time = datetime.now()
        try:
            if self.method.lower() == "post":
                if "https" in self.url:
                    resp = requests.post(self.url, data=self.multipartEncodedContent, headers=self.headers,
                                         verify=False, cookies=self.cookies)
                else:
                    resp = requests.post(self.url, data=self.multipartEncodedContent, headers=self.headers,
                                         cookies=self.cookies)
            elif self.method.lower() == "put":
                if "https" in self.url:
                    resp = requests.put(self.url, data=self.multipartEncodedContent, headers=self.headers,
                                        verify=False, cookies=self.cookies)
                else:
                    resp = requests.put(self.url, data=self.multipartEncodedContent, headers=self.headers,
                                        cookies=self.cookies)
        except Exception as e:
            print("[Request Exception] {0}: {1}".format(type(e), e))
            msg = "send request {%s] %s failed: %s" % (self.method, self.url, str(e))
            self.logger.info(e)
            self.logger.info(msg)
            assert False, msg
        finally:
            request_info = self.get_request_info(resp, start_time)
            self.appendApiLog(self.url, self.method, request_info)

        if httpStatusExp:
            commonBase.checkResultEqual(resp.status_code, httpStatusExp,
                                        '[Request] resp.status_code: %s is not %s' % (resp.status_code, httpStatusExp))

        if requireJson:
            if bText:
                respText = resp.text
            else:
                respText = resp.content
            resp = commonBase.loadJsonData(respText)
            if statusExp:
                commonBase.checkValueInDict(resp, "status", statusExp,
                                            "[Request] resp data['status'] does not match with %s" % str(statusExp))

        return resp

    def encodeUrlParams(self, params, needencode=True):
        """
        encode request parameters dict to query string, like: param1=value1&param2=value2
        eg: {"param1": "value1", "param2": None, "param3": ""} => param1=value1&param3=
        :param params: dict, request query parameters.
        :return string, like "param1=&param3=value3"
        """
        if params is not None:
            for (key, value) in list(params.items()):
                if value is None:
                    params.pop(key)

            if len(params) > 0:
                if not needencode:
                    params_str_list = []
                    for (key, value) in list(params.items()):
                        params_str_list.append(key + "=" + str(value))
                    return '&'.join(params_str_list)
                return urllib.parse.urlencode(params)

        return ''

    def composeUrl(self, base_url, sub_url, para_dict=None, needencode=True):
        url = base_url.rstrip('/') + '/' + sub_url.lstrip('/')
        paraValue = request.encodeUrlParams(para_dict, needencode) if para_dict and isinstance(para_dict, dict) else ''
        paraStr = ('?' + paraValue) if paraValue else ''
        url += paraStr

        return url

    def replace_domain_to_hostip(self, url):
        try:
            host_ips = eval(os.environ['hosts_to_ip'])
            for domain, ip_port in list(host_ips.items()):
                if url.find(domain) > 0:
                    self.logger.infoGreen('Replace domain from {0} to {1}'.format(domain, ip_port))
                    url = url.replace(domain, ip_port)
                    return url
        except:
            return url
        return url

        # endregion

    def rebuildurl(self, url, parameter):
        if not parameter:
            return url
        return url + "?" + urllib.parse.urlencode(parameter)

    def http_check(self, method, url, body=None, resp_exp=None, headers=None, http_status_exp=200, form_data=None,
                   files=None):
        self.url = url
        self.method = method
        if body:
            if method.lower() == 'get':
                self.url = self.rebuildurl(url=self.url, parameter=body)
            else:
                self.data = body
        if headers:
            self.headers = headers

        if form_data:
            self.multipartEncodedContent = MultipartEncoder(form_data)
            response = self.sendMultipartRequest()
        elif files:
            self.data = None
            response = self.uploadFileApi(method, files)
        else:
            response = self.sendJsonRequestReturnDict(httpStatusExp=http_status_exp, bText=False)
            status_exp = commonBase.getValue(resp_exp, "status") if resp_exp and 'status' in resp_exp else 0
            for i in range(5):
                if 'message' in response and response['message'].find('操作太频繁，请2秒后重试') > -1:
                    time.sleep(2)
                    response = self.sendJsonRequestReturnDict(httpStatusExp=http_status_exp, bText=False)
                else:
                    break
            if resp_exp:
                commonBase.checkValueInDict(response, "status", status_exp,
                                            "[Request] resp data['status'] does not match with %s" % str(status_exp))
        # 跳过返回html的情况，该情况在监控环境无法复现
        if not isinstance(response, dict):
            commonBase.checkResultIsNotNone(True)
            return
        self.url, self.data, self.headers, self.method = None, None, None, None
        if resp_exp:
            commonBase.checkPartInDict(resp_exp, response, bMatch=True)
        return response

    # region Upload/download methods
    def uploadFileApi(self, method, fileList=None, files=None):
        """
        upload file with requests
        :param method, str post, put
        :param fileList, list
        """
        if self.headers is None or self.headers == "":
            self.headers = {'Content-Type': 'application/json', 'Accept': 'text/plain', 'User-Agent': 'hjqa'}
        elif len(list(self.headers.keys())) > 0:
            keys = ','.join(list(self.headers.keys()))
            self.headers.update({'Content-Type': 'application/json'}) if re.match('Content-Type', keys,
                                                                                  re.I) is None else None
            self.headers.update({'User-Agent': 'hjqa'}) if re.match('User-Agent', keys, re.I) is None else None
        else:
            self.headers = None

        if fileList is not None and len(fileList) > 0:
            try:
                files = []
                list(map(lambda f: files.append(('file', open(f, 'rb'))), fileList))
            except Exception as e:
                print(e)
                assert False, "[Request] open file failed: {0}".format(",".join(fileList))

        self.logger.info("[Request] Upload Uri: %s" % (self.url[self.url.find("/", self.url.find("//") + 2) + 1:]))
        self.logger.info("[Request] Headers: %s" % (self.headers))
        self.logger.info(
            "[Request] PostData: %s" % (json.dumps(self.data, ensure_ascii=False))) if self.data is not None else None
        self.logger.info("[Request] Files: %s" % (files))

        method = method.lower()
        start_time = datetime.now()
        resp = None
        try:
            if method == "post":
                if "https" in self.url:
                    resp = requests.post(self.url, data=self.data, headers=self.headers, files=files,
                                         cookies=self.cookies, verify=False)
                else:
                    resp = requests.post(self.url, data=self.data, headers=self.headers, files=files,
                                         cookies=self.cookies)
            elif method == "put":
                if "https" in self.url:
                    resp = requests.put(self.url, data=self.data, headers=self.headers, files=files,
                                        cookies=self.cookies, verify=False)
                else:
                    resp = requests.put(self.url, data=self.data, headers=self.headers, files=files,
                                        cookies=self.cookies)
            else:
                assert False, "The request method %s is not in ['post','put']"
        except Exception as e:
            # print("[Request Exception] {0}: {1}".format(type(e), e))
            msg = "send request {%s] %s failed: %s" % (method, self.url, str(e))
            self.logger.info(e)
            self.logger.info(msg)
            assert False, msg
        finally:
            request_info = self.get_request_info(resp, start_time)
            self.appendApiLog(self.url, self.method, request_info)

        respTxt = resp.text
        self.logger.info("\n[Response %s] %s" % (resp.status_code, respTxt))
        assert resp.status_code == 200, "[Request] Response status_code: %s is not 200(OK)" % (resp.status_code)
        return commonBase.loadJsonData(respTxt)

    times = 5

    def downloadFileApi(self, url, filename, headers=None, httpStatusExp=200):
        """
        :param str url:
        :param str filename:
        :param dict headers:
        :param int httpStatusExp: default 200
        :return:
        """
        headers = {} if headers is None else headers
        headers.update({'User-Agent': 'hjqa'}) if 'user-agent' not in ','.join(list(headers.keys())) else None
        kw = {"stream": True, "headers": headers}
        kw.update({"verify": False}) if url.startswith("https") else None

        self.logger.info("[Request] Upload Uri: %s\nheaders: %s" % (
            url[url.find("/", url.find("//") + 2) + 1:], json.dumps(headers, ensure_ascii=False)))
        try:
            resp = requests.get(url, **kw)
            self.appendApiLog(url)
        except Exception as e:
            msg = "send download %s failed: %s" % (url, str(e))
            self.logger.info("%s\n%s" % (e, msg))
            assert False, msg
        actCode = resp.status_code
        if actCode != httpStatusExp and self.times > 0:
            self.logger.info("======download failed, try again...")
            self.times -= 1
            time.sleep(1)
            self.downloadFileApi(url, filename, headers, httpStatusExp)

        with open(filename, "wb") as f:
            for chunk in resp.iter_content(1024 * 4):
                f.write(chunk)

    # endregion

    # region Get Methods

    def getXmlResFromRequest(self, url):
        '''
        send request then get XML response
        :param string url
        :return object xmlRes
        '''
        self.logger.info("send request %s" % (url))
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "hjqa")
            response = urllib.request.urlopen(req)
            self.appendApiLog(url)
        except urllib.error.URLError as e:
            print(e)
            msg = str(e) + "with URL %s" % (url)
            self.logger.info(msg)
            assert False, msg

        try:
            resData = response.read()
        except:
            assert False, "read response %s failed for URL %s " % (response, url)

        self.logger.info(resData)
        try:
            xmlRes = etree.fromstring(resData)
        except:
            assert False, "parse xml failed for URL %s" % (url)

        return xmlRes

    def getFailedUrlList(self, urlListSrc):
        '''
        send Failed URL and get the Failed again List
        :param list urlListSrc
        '''
        self.logger.info("check URL list response code...")
        urlFailedList = []
        for url in urlListSrc:
            flag, re_status = self.checkUrlRespCode(url)
            if flag == False:
                urlFailedList.append(url)
            time.sleep(0.5)
        return urlFailedList

    def getAccessTokenByUser(self, userName, pwd, smsCode=None, codeExp=0):
        self.logger.info("Get the access token by user '%s' and pwd '%s'" % (userName, pwd))

        pwdMd5 = commonBase.md5String(pwd)
        dataPost = {"account": userName, "login_type": 1000, "password": pwdMd5, "sms_code": smsCode, }
        dataPost.pop("sms_code") if smsCode is None or smsCode == "" else dataPost.pop("password")

        dataAct = self.sendHjAppApiRequest("/account/login", dataPost, "post", codeExp=codeExp)
        self.logger.info("get hj access token...")
        accessToken = commonBase.getValue(dataAct, "access_token",
                                          "get access_token value failed in data %s" % (dataAct))
        return accessToken

    _loginCookies = {}

    def __cookieDictFromWebCookies(self, webCookies):
        '''
        convert cookies from webdriver to dict cookie
        :param list webCookies
        '''
        nameL = []
        valueL = []
        for item in webCookies:
            name = item.get('name')
            value = item.get('value')
            nameL.append(name)
            valueL.append(value)
        return dict(list(zip(nameL, valueL)))

    def _convertSortDictData(self, data):
        self.logger.info("convert dictionary data to URL parameters...")
        dataStr = ""
        items = list(data.keys())
        items.sort()
        for key in items:
            dataStr = "%s%s=%s&" % (dataStr, key, data[key])
        dataParam = dataStr[0:-1]
        self.logger.info(dataParam)
        return dataParam

    # endregion

    # region Check methods
    def checkResponseCorrect(self, source, name, expected, msg=None, url=None, operator="=="):
        self.logger.info("get response %s then check..." % (name))

        resAct = commonBase.getValue(source, name)
        urlStr = " URL: %s" % (url) if url is not None else ""
        messageStr = " message: %s" % (source.get("message")) if source.get("message", "") != "" else ""
        msg = "the actual result is %s but the expected is %s with operator %s." % (
            resAct, expected, operator) if msg is None else msg
        msg = "%s%s%s" % (msg, urlStr, messageStr)

        cmpStr = "%s %s %s" % (resAct, operator, expected)
        if isinstance(resAct, str) and isinstance(expected, str):
            cmpStr = '"%s" %s "%s"' % (resAct, operator, expected)

        if not eval(cmpStr):
            self.logger.info(msg)
            assert False, msg
            # commonBase.checkResultEqual(resAct, expected, msg)

    def checkUrlRespCode(self, url, onlyLog=False, re_patternCode=r"[4-5]\d{2}", cookies=None):
        """
        send access URL request and return the response flag
        :param url: str
        :return flag: bool, return True if access URL correctly, otherwise return False
        """
        self.logger.info("check access URL response code...")
        headers = {"User-Agent": "hjqa"}
        try:
            if url.startswith("https:"):
                resp = requests.get(url, headers=headers, verify=False, cookies=cookies, timeout=30)
            else:
                resp = requests.get(url, headers=headers, cookies=cookies, timeout=30)
            resp_status = str(resp.status_code)
            flag = True if re.match(re_patternCode, resp_status) == None else False
            return flag, resp_status
        except Exception as e:
            msg = "check URL %s failed since %s" % (url, str(e))
            self.logger.warn(msg)
            if not onlyLog:
                assert False, msg
            return False, e

    def checkUrlStartWith(self, url, keyword):
        """
        check the URl is start with special keyword
        :param url: str
        :return flag: bool, return True if url start with keyword, otherwise return False
        """
        # self.logger.info("check access URL start with "+keyword)
        url = url.split(r"//")[1]
        keyword = keyword.lower()
        flag = True if url.startswith(keyword) else False
        return flag

    def doubleCheckUrlStartWith(self, url, keyword, msg=None, onlyLog=False):
        """
        double check URL started with specified keyword, none url request will be ignored
        :param string url
        :param keyword: environment like:qa.yz,pre
        """
        if url is None or len(str(url)) == 0 or not (
                url.find("http") == 0 or url.find("https") == 0 or url.find(r"//") == 0):
            self.logger.info("url check ignore none url request")
            return
        if 'hujiangcctalk' not in url:
            flag = True
            for i in range(2):
                flag = self.checkUrlStartWith(url, keyword)
                if flag is True:
                    break
            if not flag and onlyLog:
                self.logger.infoRed("double check url %s start with %s: Warning" % (url, keyword))
            else:
                self.logger.infoGreen("double check url %s start with %s: Pass" % (url, keyword))
                assert flag == True, msg
            return flag

    def doubleCheckUrlNotStartWith(self, url, msg=None, onlyLog=False):
        """
        double check URL started with specified keyword, none url request will be ignored
        :param string url
        :param keyword: environment like:qa.yz,pre
        """
        if url is None or len(str(url)) == 0 or not (
                url.find("http") == 0 or url.find("https") == 0 or url.find(r"//") == 0):
            self.logger.info("url check ignore none url request")
            return
        keyword = ['qa', 'yz', 'pre']
        flag = True
        if 'hujiangcctalk' not in url:
            for i in keyword:
                checker = self.checkUrlStartWith(url, i)
                if checker and onlyLog:
                    self.logger.infoRed("double check url %s not start with %s: Warning" % (url, i))
                    flag = False
                    break
                else:
                    self.logger.infoGreen("double check url %s not start with %s: Pass" % (url, i))
                    assert flag == True, msg
            return flag

    def doubleCheckUrlListWork(self, urlListSrc, msgExp=None):
        '''
        double check URLs work or not
        :param list urlListSrc
        :param string msgExp
        '''
        self.logger.info("double check URLs work...")
        urlFailedListAgain = []
        urlFailedList = self.getFailedUrlList(urlListSrc)
        if urlFailedList != []:
            self.logger.info("re-check failed URL list %s " % (urlFailedList))
            urlFailedListAgain = self.getFailedUrlList(urlFailedList)
        if msgExp == None:
            msgExp = "double check URLs %s do not work,please check" % (urlFailedListAgain)
        assert urlFailedListAgain == [], msgExp

        return len(urlFailedListAgain) == 0

    def doubleCheckUrlRespCode(self, url, msg=None, onlyLog=False, cookies=None):
        """
        double check URL works or not, none url request will be ignored
        :param string url
        """
        if url is None or len(str(url)) == 0 or not (
                url.find("http") == 0 or url.find("https") == 0 or url.find(r"//") == 0):
            self.logger.info("url check ignore none url request")
            return

        if 'hujiangcctalk' not in url:
            self.logger.info("double check response for url: %s" % (url))
            flag = True
            for i in range(2):
                flag, re_status = self.checkUrlRespCode(url, onlyLog, cookies=cookies)
                if flag is True:
                    break
            if not onlyLog:
                if not flag:
                    self.logger.info("double check response for url: %s failed status code is %s" % (url, re_status))
                else:
                    self.logger.infoGreen(
                        "double check response for url: %s passed, status code is %s" % (url, re_status))
            assert flag == True, msg

            return flag

    def __doubleCheckSrc(self, keyword='', onlyLog=True, cookies=None):
        while self.bChecking:
            if len(self.srcList) > 0:
                try:
                    url = self.srcList.pop(0)
                    try:
                        self.doubleCheckUrlRespCode(url, onlyLog=onlyLog, cookies=cookies)
                        if keyword != '':
                            if keyword != 'prod':
                                self.doubleCheckUrlStartWith(url, keyword, onlyLog=onlyLog)
                            else:
                                self.doubleCheckUrlNotStartWith(url, onlyLog=onlyLog)
                    finally:
                        self.srcCount -= 1
                except:
                    pass

    def doubleCheckSrcListWorkWithMultiThreads(self, srcList, keyword='', onlyLog=True, cookies=None):
        # Create 50 threads to deal with the urls
        if int(len(srcList) / 4) > 20:
            iThreadCount = 15
        else:
            iThreadCount = int(len(srcList) / 4)
        threads = []
        self.bChecking = True
        for i in range(iThreadCount):
            thread = threading.Thread(target=self.__doubleCheckSrc, args=(keyword, onlyLog, cookies))
            thread.setDaemon(True)
            thread.start()
            threads.append(thread)
        self.srcCount = len(srcList)
        self.srcList = srcList
        time1 = datetime.now()
        bZero = False
        while self.srcCount > 0:
            time.sleep(0.2)
            if len(self.srcList) == 0 and not bZero:
                bZero = True
                time1 = datetime.now()
            if bZero and (datetime.now() - time1).seconds > 30:
                break
        self.bChecking = False

    def doubleCheckSrcListWorkWithMultiProcess(self, srcList, keyword='', onlyLog=True, cookies=None):
        # Create 8 processes to deal with the urls
        p = Pool(8)
        for url in srcList:
            p.apply_async(self.doubleCheckUrlRespCode, args=(url, onlyLog, cookies))
        p.close()

    # endregion

    def __end_of_file(self):
        pass


request = baseRequest()
