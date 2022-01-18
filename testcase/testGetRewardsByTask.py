# -*- coding: UTF-8 -*-
import time
import json
from api.apiTaskCode import apiAutoTask
from requests_toolbelt import MultipartEncoder

# #########任务页领元宝任务参数##########
mp = "0"  # 红包值
isLast = "2"  # 是否最后一圈 1是2否
hp = "@012u9OUHNVLjbFGmGOiSPVMl9vYvn4qlPyQu3tMvcpGjx4GuwHoHbygvGUG0PVQu3tMvcpGf9vYvxtY03VnlNOIvcpGHiVQjiVzvGUG0nMdHbMAHNt9SPJMvcpGfB6UfK6G21=="  # cpm值
isVideo = "1"  # 是否是激励视频 1是2否
taskId = "4"  # 1首页宝箱2首页转圈红包3全都要4领元宝任务
token = "51a9edc40e1cc5f328aeb0494c205ab9"  # token
# #########全都要任务参数##########
n = 1
Sum_Bonus = 0
Sum_Diamonds = 0
while n <= 9:  # 设置任务完成数
    code = apiAutoTask.get_Diamonds_task_autocode()
    param = {
        "pub": "eyJ0aW1lem9uZSI6IjgiLCJzcmNwbGF0IjoibnVsbCIsImFwcHR5cGVpZCI6IjEwMDA5NiIsImFwcHZlcmludCI6IjAxMDAwMCIsImRldmljZWJyYW5kIjoiYmxhY2tzaGFyayIsImxhc3RzdGF0IjoiMy4wNTQyMzYzRS00fDAuMDA2MTg0ODI4NXwtMi4yOTA2NzcyRS00IiwiYXBwcWlkIjoiZ2YxMjIwMTA1IiwiYXBwdmVyIjoiMS4wLjAiLCJkZXZpY2UiOiJTSEFSSyBQUlMtQTAiLCJiYXNlc3RhdGlvbiI6IiIsInByb3ZpbmNlIjoi5LiK5rW3IiwicmVmcWlkIjoiIiwic3JjcWlkIjoibnVsbCIsImFwcGNxaWQiOiJnZjEiLCJhcHBpbmZvIjoie1wic3NpZFwiOlwiXHUwMDNjdW5rbm93biBzc2lkXHUwMDNlXCIsXCJic3NpZFwiOlwiMDI6MDA6MDA6MDA6MDA6MDBcIixcImlwQWRkcmVzc1wiOlwiMTcyLjIxLjE3LjE2M1wiLFwibG9jYXRpb25UeXBlXCI6XCJnYW9kZVwiLFwiZWxlXCI6XCI5NlwiLFwic3RhdGVcIjpcIjJcIixcInRlbXBlcmF0dXJlXCI6XCIzNVwiLFwiaW5zZXJ0c2ltXCI6XCIwXCIsXCJvcGVyYXRvcnR5cGVcIjowLFwiYnJpZ2h0bmVzc1wiOjExMzIsXCJ2b2x1bWVcIjpcIjgsMTIsMTIsMSwyMVwiLFwidXNiXCI6XCIxXCIsXCJjcHVcIjpcIlF1YWxjb21tIFRlY2hub2xvZ2llcywgSW5jIFNNODI1MFwiLFwibG9ja3NjcmVlblwiOjYwLFwiaW1hZ2Vjb3VudFwiOlwiXCIsXCJkZXZpY2VfcmVzdGFydFwiOlwiMjAyMi0wMS0wNFwiLFwib3Blbl9wYXNzd29yZFwiOlwiMFwiLFwic3RvcmFnZV9pbnRcIjpcIjExMzc1NTc3OTA3MlwiLFwic3RvcmFnZV9leFwiOlwiMTEzNzU1Nzc5MDcyXCIsXCJtZW1vcnlcIjpcIjc3OTcxNjBcIixcImJhdHRlcnlcIjpcIjQ1MDAuMFwiLFwiYm9hcmRcIjpcInBlbnJvc2VcIixcInNlcmlhbG51bWJlclwiOlwiXCIsXCJpbnNjcmliZWR2ZXJzaW9uXCI6XCI0LjE5LjExMy1wZXJmLWdmZTM0NWFkXCIsXCJzZW5zb3J0eXBlXCI6XCJhY2NlbGVyb21ldGVyX3VuY2FsaWJyYXRlZHxTVE1pY3JvQCNAYWNjZWxlcm9tZXRlcnxTVE1pY3JvQCNAZGV2aWNlX29yaWVudGF0aW9ufHhpYW9taUAjQGdhbWVfcm90YXRpb25fdmVjdG9yfHF1YWxjb21tQCNAZ2VvbWFnbmV0aWNfcm90YXRpb25fdmVjdG9yfHF1YWxjb21tQCNAZ3Jhdml0eXxxdWFsY29tbUAjQGd5cm9zY29wZV91bmNhbGlicmF0ZWR8U1RNaWNyb0AjQGd5cm9zY29wZXxTVE1pY3JvQCNAbGlnaHR8Um9obUAjQGxpbmVhcl9hY2NlbGVyYXRpb258cXVhbGNvbW1AI0BtYWduZXRpY19maWVsZF91bmNhbGlicmF0ZWR8YWttQCNAbWFnbmV0aWNfZmllbGR8YWttQCNAbW90aW9uX2RldGVjdHxxdWFsY29tbUAjQG9yaWVudGF0aW9ufHhpYW9taUAjQHByb3hpbWl0eXxFbGxpcHRpYyBMYWJzQCNAcXRpLnNlbnNvci5mYWxsX2Rpc3xxdWFsY29tbUAjQHF0aS5zZW5zb3IudG91Y2h8eGlhb21pQCNAcm90YXRpb25fdmVjdG9yfHF1YWxjb21tQCNAc2lnbmlmaWNhbnRfbW90aW9ufHF1YWxjb21tQCNAc3RhdGlvbmFyeV9kZXRlY3R8cXVhbGNvbW1AI0BzdGVwX2NvdW50ZXJ8cXVhbGNvbW1AI0BzdGVwX2RldGVjdG9yfHF1YWxjb21tQCNAdGlsdF9kZXRlY3RvcnxxdWFsY29tbUAjQHhpYW9taS5zZW5zb3IuM2Rfc2lnbmF0dXJlfFhpYW9NaUAjQHhpYW9taS5zZW5zb3IuYW1iaWVudGxpZ2h0LmZhY3Rvcnl8Um9obUAjQHhpYW9taS5zZW5zb3IuYW9kfFhpYW9NaUAjQHhpYW9taS5zZW5zb3IuZG91YmxlX3RhcHxTVE1pY3JvQCNAeGlhb21pLnNlbnNvci5mb2RfZGV0ZWN0b3J8WGlhb01pQCNAeGlhb21pLnNlbnNvci5rbnVja2xlfFhpYW9NaUAjQHhpYW9taS5zZW5zb3Iub2VtMTN8WGlhb01pQCNAeGlhb21pLnNlbnNvci5waWNrdXB8WGlhb01pQCNAeGlhb21pLnNlbnNvci5zdG1fZ2xhbmNlX2ZzbXxTVE1pY3JvXCIsXCJzZW5zb3JzXCI6XCIzMlwiLFwicHJvZHVjdGNvZGVcIjpcIlBSUy1BMFwiLFwiYmFzZWJhbmR2ZXJzaW9uXCI6XCJNUFNTLkhJLjIuMC5jNy0wMDIyMi0wOTIzXzIxNDNfMzk1ZDJkNSxNUFNTLkhJLjIuMC5jNy0wMDIyMi0wOTIzXzIxNDNfMzk1ZDJkNVwiLFwiZGV2aWNlbmFtZVwiOlwicGVucm9zZVwiLFwiY3B1YWJpXCI6XCJhcm02NC12OGFcIn0iLCJ1c2VyaW5mbyI6IntcImhtb3N2ZXJcIjpcIlwiLFwiYmRcIjpcIlwiLFwicmVndHNcIjpcIlwiLFwibGFzdGluc3RhbGxcIjpcIjE2NDE0Mzk2MzBcIixcInNleFwiOlwiXCIsXCJ1c2VydHlwZVwiOlwiXCIsXCJobW9zXCI6XCJcIixcImFwcHN1YmlkXCI6XCJcIn0iLCJvYmF0Y2hpZCI6IjAyYjc4Mjg4ZmU4ZTc4MmYiLCJvcyI6IkFuZHJvaWQiLCJ0cyI6IjE2NDE2Mjk1ODMiLCJtYWMiOiIwNDMzODU2NWUwMzgiLCJhYWlkIjoiYTI1ZDJlMzMtNTU4Yy00MDVjLWI4M2UtZTQwODAwNmIyOTZhIiwiY2l0eSI6IuS4iua1tyIsIm9haWQiOiJmNmQ3ZjczYmI2YTQ5NzYzIiwicGl4ZWwiOiIxMDgwKjIyNzYiLCJvc3ZlcnNpb24iOiIxMSIsInN0YXJ0aW5ndGltZSI6IjE2NDE0Mzk2MzgiLCJzbWRldmljZWlkIjoiMjAyMjAxMDQxNTU0NDc5OTM0NWUzNDg1Njc2ODBjNjM4YmU0YjA2NjEzZGExZTAxOTI3ZWY4OTUzNmQ0NGQiLCJpc3RvdXJpc3QiOiIwIiwiY291bnRyeSI6Ium7hOa1puWMuiIsImRldmljZWlkIjoiN2ZmZjM0NTNiOGM1NTIzZCIsInRoaXNzdGF0IjoiLTguMzk5MTVFLTR8LTAuMDA1OTU1NzYxfC0wLjAwMTc1NjE4NTkiLCJuZXR3b3JrIjoid2lmaSIsImlzeXVleXUiOiIwIiwiaW5zdGFsbHRpbWUiOiIyMDIyLTAxLTA1In0=",
        "params": {"authcode": code, "mp": mp, "isLast": isLast, "hp": hp,
                   "isVideo": isVideo, "taskId": taskId, "token": token,
                   "cust_client_time": ""}}
    data = apiAutoTask.data_encode(json.dumps(param))
    # print("我是最新的参数啊啊啊啊：", data)
    send_data = MultipartEncoder(
        fields={
            "ts": "",
            "service": "App.Active.GetRewardsByTask",
            "sign": "",
            "data": data
        }
    )
    resp = apiAutoTask.get_rewards_bytask(send_data)
    Bonus = int(resp["data"]["data"]["rewardBonus"])
    Diamonds = int(resp["data"]["data"]["rewardDiamonds"])
    Sum_Bonus += Bonus
    Sum_Diamonds += Diamonds
    print("第%d次完成任务:" % n, resp)
    print("当前累计红包数量：", Sum_Bonus)
    print("当前累计元宝数量：", Sum_Diamonds)

    n += 1
    time.sleep(1)
