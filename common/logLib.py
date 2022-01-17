# -*- coding: UTF-8 -*-

import inspect
import os
import time
import logging
from lxml import etree as ET
from datetime import datetime
from unittest.case import TestCase

try:
    import globalVariables as gVars
except:
    from . import globalVariables as gVars


class logLib(object):
    # try:
    #     from robot.api import logger
    #     logger = logger
    # except:
    #     import logging
    #     logger = logging.getLogger('RobotFramework')
    logger = logging.getLogger('hjAuto')

    def __init__(self, name=None):
        if name is None:
            self.className = self.__class__.__name__
        else:
            self.className = name

    def get_current_function_name(self):
        return str(inspect.stack()[2][3])

    def assertErr(self, result, msg):
        if not result:
            self.error(msg)
            assert result, msg

    def __logInfo(self, msg):
        if str(self.logger).find('robot.api.logger') > 0:
            self.logger.info(msg, html=True)
        else:
            self.logger.info(msg)

    def __logWarn(self, msg):
        if str(self.logger).find('robot.api.logger') > 0:
            self.logger.warn(msg, html=True)
        else:
            self.logger.warn(msg)
        if gVars.logFileStep is not None:
            step = ET.Element("msg")
            step.set("timestamp", datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3])
            step.set("html", "yes")
            step.set("level", "WARN")
            step.text = msg
            gVars.logFileStep.append(step)

    def error(self, msg):
        errMsg = "[%s]<b>%s(%s)</b>   <font style='color:red;'>%s</font>" \
                 % (
                 datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.className, self.get_current_function_name(),
                 msg)
        stack_init = inspect.stack()[-1][1]
        if not (stack_init.lower().find("pycharm") > -1 or stack_init.lower().find("nosetests") > -1 or
                        stack_init.lower().find("apitester-script.py") > -1):
            raise BaseException(errMsg)
        else:
            self.logger.error(errMsg)
            # try:
            #     if errMsg.find(r'/undefined/') < 0:
            #         TestCase.errorList.append(errMsg)
            # except:
            #     pass

    def warn(self, msg):
        self.__logWarn(
            "[%s]<b>%s(%s)</b>   <font style='color:#f90;'>%s</font>"
            % (
            datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.className, self.get_current_function_name(), msg))

    def info(self, msg):
        self.__logInfo("[%s]<b>%s(%s)</b>   %s" % (
        datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.className, self.get_current_function_name(), msg))

    def debug(self, msg):
        self.logger.debug("[%s]<b>(%s)</b>   %s" % (
        datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.get_current_function_name(), msg))

    def infoStep(self, msg):
        self.logger.info("<b>[STEP] </b><font style='color:brown;'>{}</font>".format(msg))

    def infoBold(self, msg):
        self.__logInfo("[%s]<b>%s(%s)</b>   <font style='font-weight:bold;'>%s</font>"
                       % (datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.className,
                          self.get_current_function_name(), msg))

    def infoRed(self, msg):
        self.__logInfo("[%s]<b>%s(%s)</b>   <font style='color:red;'>%s</font>"
                       % (datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.className,
                          self.get_current_function_name(), msg))

    def infoGreen(self, msg):
        self.__logInfo("[%s]<b>%s(%s)</b>   <font style='color:green;'>%s</font>"
                       % (datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.className,
                          self.get_current_function_name(), msg))

    def infoBrown(self, msg):
        self.__logInfo("[%s]<b>%s(%s)</b>   <font style='color:brown;'>%s</font>"
                       % (datetime.now().strftime("%Y%m%d %H:%M:%S.%f")[:-3], self.className,
                          self.get_current_function_name(), msg))

    def logGen(self, logDir, logBaseName):
        logName = "{0}_{1}.html".format(logBaseName, time.strftime("%Y%m%d_%H%M%S", time.localtime()))
        logAsbName = os.path.join(logDir, logName)
        if not os.path.exists(logDir):
            os.makedirs(logDir)
        # Add html basic content in the log file
        logFile = open(logAsbName, 'w')
        htmlHead = '''
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        <html xmlns="http://www.w3.org/1999/xhtml">
        <head>
            <title>Test case log</title>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        </head>
        <body>
        '''
        logFile.write(htmlHead)
        logFile.flush()
        logFile.close()
        return logAsbName

    def infoCase(self):
        self.__logInfo("<font style='color:brown;'>Start to invoke %s.%s...</font>" %
                       (self.className, self.get_current_function_name()))


log = logLib()
