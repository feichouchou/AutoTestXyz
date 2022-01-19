import csv
import os
import time
'''
测试步骤
1、usb连接adb
2、清除设备上电量历史记录
    adb shell dumpsys batterystats --enable full-wake-history
3、重置电量信息
    adb shell dumpsys batterystats --reset
4、以wifi网络连接adb
    adb tcpip 5555
    adb connect 手机ip:5555
5、安装相雨230客户端
6、安装后检查，相雨进程是否启动，启动则下一步，未启动则先启动
7、查看设备uid（如：u0_a345，去除下划线则为uid）
    adb shell ps |grep com.maiya.xiangyu 
8、控制台检查相雨电量已出现
    adb shell dumpsys batterystats com.maiya.xiangyu |grep uid
9、运行python脚本
10、将客户端所有授权全部允许并放置后台运行
11、打开快手app、查看视频
12、统计2小时电量数据，结束后把 battery.csv发我
13、结束后断开wifi模式下adb
    adb disconnect 172.21.17.163:5555

ps：该脚本也可用来测试cpu、memory等性能数据
'''

# 监控CPU资源信息
class MonitoringCPUResources(object):
    def __init__(self, count):
        self.counter = count
        self.alldata = [("timestamp", "powerconsumption（mAh）")]

    # 单次执行监控过程
    def monitoring(self):
        # result = os.popen("adb shell dumpsys meminfo | findstr com.maiya.xiangyu")
        result = os.popen("adb shell dumpsys batterystats com.maiya.xiangyu|findstr u0a135")
        # cpuinfo\battery\gfxinfo(帧率)\batterystats（耗电）
        # 不同指标的数据采集需要注意更改提取的数据样式
        # cpuvalue = result.readline().split(":")[1].strip()
        battery_value = result.readline().split()[2].strip()
        currenttime = self.getCurrentTime()
        print(currenttime, battery_value)
        self.alldata.append([currenttime, battery_value])

    # 多次执行监控过程
    def run(self):
        while self.counter > 0:
            self.monitoring()
            self.counter = self.counter - 1
            time.sleep(60)

    # 获取当前的时间戳
    def getCurrentTime(self):
        currentTime = time.strftime("%H:%M:%S", time.localtime())
        return currentTime

    # 数据的存储
    def SaveDataToCSV(self):
        csvfile = open('Battery.csv', mode='w')
        writer = csv.writer(csvfile)
        writer.writerows(self.alldata)
        csvfile.close()


if __name__ == "__main__":
    monitoringCPUResources = MonitoringCPUResources(120)
    monitoringCPUResources.run()
    monitoringCPUResources.SaveDataToCSV()

