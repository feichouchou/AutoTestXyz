# -*- coding: utf-8 -*-

import uiautomator2 as u2
import time
import os
import pytest

d = u2.connect("6207bcf6")
# 打开debug模式，查看通讯流程
d.debug = True
# 查看简单的设备信息
print(d.info)
d.healthcheck()

os.system("adb install C:\\Users\\Lenovo\\Downloads\\apk\\v2.2.1--20211203-154705-release.apk")
d.app_start('com.maiya.xiangyu')
time.sleep(3)
d(text="同意并进入").click()
time.sleep(3)
d(text="始终允许").click()
time.sleep(3)
d(text="开启定位").click()
time.sleep(3)
d(text="本次运行允许").click()
time.sleep(3)
# d(resourceId="com.maiya.xiangyu:id/tt_insert_dislike_icon_img", className="android.widget.ImageView").click()
# time.sleep(5)
for i in range(0, 2):
    d.press("back")

d.app_start('com.maiya.xiangyu')
# d.disable_popups
# d.disable_popups(False)
# 相当于'am force-stop'强制停止应用
# d.app_stop('com.maiya.xiangyu')
# 相当于'pm clear' 清空App数据
# d.app_clear('com.maiya.xiangyu')
