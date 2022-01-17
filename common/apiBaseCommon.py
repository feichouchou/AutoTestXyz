# -*- coding: UTF-8 -*-

import time, logging, re
import common.commonBase as commonBase
from common.baseRequest import baseRequest



class baseCommon(baseRequest):
    logger = logging.getLogger(__name__)

    # 发送json报文并返回结果
    def send_json_data_return_result(self, method, url, send_data, headers=None,
                                     cookies=None, check_status=0,
                                     http_status=200, check_status_switch=1, **kwargs):
        """
        send json data and check http_status & status_code
        :param method: like "Post", 'Put'
        :param url: string, total http url
        :param send_data: json data
        :param headers: dict,like {'Content-Type': 'application/json'}
        :param cookies: dict
        :param check_status: int, default 0
        :param http_status: int, default 200
        :param check_status_switch: 0: do not check status code, 1: check status code
        :param kwargs:
        :return:
        """
        if headers is not None:
            headers.update({'Content-Type': 'application/json', "Accept": "application/json"})
        else:
            headers = {'Content-Type': 'application/json', "Accept": "application/json"}

        request_obj = baseRequest(method=method, url=url, headers=headers, data=send_data, cookies=cookies)
        resp_act = request_obj.sendJsonRequestReturnDict(http_status)
        if check_status_switch:
            request_obj.checkResponseCorrect(resp_act, "ret", check_status)
        return resp_act

    # 发送multi data报文并返回结果
    def send_multi_data_return_result(self, method, url, send_data, headers=None, cookies=None,
                                      check_status=0, http_status=200, check_status_switch=1, **kwargs):
        """
        发送: multipart格式数据
        返回: json格式结果
        检查: status和https_status
        """
        if headers is not None:
            headers.update({'Content-Type': 'multipart/form-data', "Accept": "*/*"})
        else:
            headers = {'Content-Type': 'multipart/form-data', "Accept": "*/*"}
        request_obj = baseRequest(method=method, url=url, multipartEncodedContent=send_data, headers=headers,
                                  cookies=cookies)
        resp_act = request_obj.sendMultipartRequest(http_status)
        if check_status_switch:
            request_obj.checkResponseCorrect(resp_act, "ret", check_status)
        return resp_act


    # 获取时间戳（带格式）
    def getTimestamp(self, dt=commonBase.currentDateTime(fmt='%Y-%m-%d %H:%M:%S')):
        """
        :param dt: format time like '%Y-%m-%d %H:%M:%S'
        :return: 10 bytes linux timestamp like '1876578900'
        """
        s = time.mktime(time.strptime(dt, '%Y-%m-%d %H:%M:%S'))
        return int(s)

    # 获取unix时间戳
    def getMsTimestamp(self):
        """
        :return: 12 bytes linux timestamp like '187657890012'
        """
        s = time.time()
        return str(s).replace(".", "")

    # 获取密钥Sign
    def getPubSecretKeySign(self, path, params_string, app_id="hjauto",
                            app_secret="CT-791FCEA7-5C8D-4128-9E1E-4B9C22F7980"):
        """
        :param path like "trade/v1/group/complete"
        :param params_string like "a=1&c=2&b=3"
        :param app_id
        :param app_secret
        :return secretKeySign
        """
        params_str = self.sort_string_param_by_ascii(params_string)
        sign = "%s?appkey=%s%s%s" % (path, app_id, app_secret, params_str)
        secretKey = commonBase.md5String(sign)
        return secretKey

    # ascii加密
    def sort_string_param_by_ascii(self, string_param):
        """
        :param string_param: like "a=1&c=2&b=3"
        :return: sorted string param by key's ascii code, like "a=1b=3c=2"
        """
        order_string = ""
        ste = re.findall("\w+=\w+", string_param)
        resp = sorted(ste, key=lambda item: re.match("(\w+)=\w+", item).group(0))
        for i in resp:
            order_string += i
        return order_string

apiBaseCommon = baseCommon()
