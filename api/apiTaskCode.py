# -*- coding: UTF-8 -*-
from common.apiBaseCommon import baseCommon
from requests_toolbelt import MultipartEncoder
import requests


class apiAutoTask(baseCommon):

    # 任务完成接口(任务类型1、2、3)
    def get_rewards_bytop(self, send_data, statusExp=200):
        url = "http://test-api.xss.91xunyue.cn/?service=App.Active.GetRewardsByTop"
        resp = self.send_multi_data_return_result(method="POST", url=url, send_data=send_data, headers=None,
                                                  cookies=None, check_status=statusExp)
        return resp

    # 获取服务端任务auto_code
    def get_autocode(self, statusExp=200):
        url = "http://test-api.xss.91xunyue.cn/?service=App.Active.GetRewardsByTop"
        send_data = MultipartEncoder(
            fields={
                "ts": "",
                "service": "App.Active.GetRewardsByTop",
                "sign": "",
                # 全都要任务
                "data": "REVNWDVCTEVYU0RRYkRLQXFGNEQ5RU1DbkJMRVhQVGdERzk5UEk3bmhXTWZzT2RKdURnZ2pUdGRFTVpmMlR2dkZWdUZzSGY4Q1VkMWhVTHZTWHZENktQSnVSUVV3U3JaS0o3RERRZzdSSXNnYklTay1YcnQ4TTRMS1ZOZnFLT3hyVHlJQlFkcGJYN254VTlIQUZjaFBHVGNHTDc5dlA1REZYdGZrTWV0SlJTc2pRY1ZDYTZiVElQbkFTZTVPTVN3eFU4Y3Fac2ZkTXRUd1FQaHVTd2dtWTlaYklhPTJVOVg5RThoUFJ5Z0dZS0p2UEtITlpOdnhPUGwzS3Y3cFRiSjVaNXJBTE1ERU4tWVZKd01DSDd4UVpjSEpWTUx3THRObUNnMHpTdWRLUVkyc05QZnVTTmg5R2pZY1B0cGpPN2ZyVk9pcE9QZHlRZ2d3Tk1KNUk1YmxZdmZRTzhGY1BDd1BZTGRpWGJiSlBzTHVMLWxtUVFzOE1kbFNTcWZzUk1ETVNNNU9JaE1NTExSTFFjYi1QT1BqTFBOMkxBQWlON0ZDVzZiVU9mcmFFdEZOUEFZbFhkQmhPNFBGVk5mcUtPMW5VU0RzUWU1YVg1dm9OUGptU0xSeFFRbnVXY1VyTzdielZQSGtOZXhJTHlza01OaG5XNWJsWXZmYUVzbFBPeFlsVXJkaVhiYmVXZVRxUWNKdVN3Z21MZVZiTlp2MFRPWElTTTVPSWkwVFViTmhQcERHVj1IPUlmOUhSUmt2TU5oblc3S3RZdmZhRXMxVk1nVXdVTDFrWmJiVU4tUHVMTU56UWlNUUhPQmFYNGF2VGZmNVdlSVhSQ29STThOdlA1SEtXLWI2S1BKOUd3a2lTcUZHWXFmQ1l2ZkdUPVpPSlFNQ0hidDhNNFBKTTktdExNTm1EZ3c5S0tSRk5wPWZOUGZ2UXNoU1JEWUtQc0JqVWJyU1pmR29WdWgwUkRZaU5NSmJhNW5tTlFiRFNjUVlKQ2stR2JzcFpiYklNZ1hnUWNZZVFoZ1JPZTVhSUlMUlVPYjVUOWRvSVBVUktyaG1TNlMxVnVqTlZ1aHhIallpUWNWd1hxWD1OTVRQSXNnYUppc3dVTHAtWmJiZkh1RGZSOFo3T3dnalc5RkJXSmZmTlBmdlFzaFRLaXNiUTdCa1VickNIPUxQS2V0OUd3ZnZRN0ZCYUp2U1l2ZkRKZlpPT1JYdVljaFFPSTNmSGZyck84SnVEaGM4TU9WUU1aYnZSOUhCVmVKc0xqZ1NROEJ1VWJ2T0lQSC1OZUp1UWk0d043UnZXNmJxTmc3UkVlY1ZPaXdQWWRFcFpiYkxWZFB2TFBsdVN4YzhNYUJhSU1XdFRlWE5Rc2hQU0NJQ1VkVnJQNkhGWHR2TEtQSnlLell5Tk1Sdlc1bkNZdmZiTzgxT01BSUNIY1o3TzhYVUx0ZnFPOEp2UWlJQlBkRkJXTTNmTlByOUVOaDhVQ2tiR2E5c081UE9XLWVwUz1SSENqY3ZRYUJrWHJEMVl2WEtOclJQSVFVSE5iMThPNDdKTWdYZ0w4VmNRU0VBSU5oWkladm1UdnZOVC1GUlR5Z0lVY2R2UHBQelZQPU9FT2Q9Q2hValNhRk9aN0hDWXZmR1Q9Wk9NQUlDV3NaN09MaldSLWpuT0xGN1BpSW1QZWhjTlpQMVU5VHVTTTVSVHlnR1ViOXhQN2FzWXR2S0U9WnpIallpTjdSdlc3LXZMZnJaVDdoY01SY0hZZElxSzhiV01nWGdMdXRjUVF3PVh0ZEVOTVRsVHNISlZlSlNIaTBUUGFkb1VMdk9UdGZoVS1KdVFnUXhOT2hiSTV2UVRzSEdOOEFZSlNzd1VMcC1aYmJmSHVEdFF1eHJSaGtQSU5wZE5NVGxPdnJ1U014NUhUa0hZY01wUE1mZklOdjdRdmg5R3dnc1E3RkNacWZUSFFUYVRldElJU2twU3JkaVVZRExRPUh2TGVsbk93Z2lZOUZCWDVma1U5YkpULUpUUkNJQ1VlNWJPN2ZOSE52N0lQUnlIallpTjdSdlc2YnBKUGJhVE5GSUlTa3BTcmRtTUxuZVdkanRRckY3T3dnaVk5RkJYSnZvVHZ2alMtRnNEUEFiUHJoa1VibnpWTjNqVnVoOUd3Z3NRN0ZDWXI9cU9mamFUT3RPTWhZTEdjaFFPTWZkUXNmc084SnVEaGM4TUs1RVdKS3hPPWo4Vzh4ZUNUWVRRN2hsUHFUZ1dPakxMTDl6THdVa1E3RkJZYVg9TmdqUk5yUmZPZklERzlOUU1MblVMdGV0TzhKdlFCZnJOZHBhTmFQMVRjQ29ULU5zTGpnUkdzUnRTND1DWHY9T0tmaC1NQkVsUWJad1JxUEJIUTdRRXNsYktRSUhLTWRQUExmV1F3YmpRdXdlVEJrUk9kcGJYTVhRUWRPb1U5Z1lJalVLS3J4NVNKVFNIZj1PTGV0OUNmZ3lTTVZPWjdIRE1jN1lOcmhhUGdjaFc4ZFBLOEhkUU49aE1NWkpRQ0VRUGRSYlg0YXNST2JKVS1FWERTVWRWTVJpVnBTMVpQVD1KYkItTHpjalNhQXBacTc9T2Q9UkVkVmJPaFk9VmRCbFJJM2RRdHpkUXV3ZUNCZ1JPZTVhSUlMaVU9dk5TZU5zRVRnZk03UXBTNlQwVmZDcEVQTjJHdzA2UWFGQ1dySHBXODdjTz1kZFBCWT1Xc2NxSzhIZVFOPWhNTVpKRFNJbUlPaFJJSWJ6UmVTd0VPRlNKaWNiTHRwaFVickNILWpPTWJkNkNSRUhTTVZHYTctc0xQaklKdU1hT3l2eVljY3FLOFRXUkFiTE5jUVdTQmZzTWVSSk1adjlUZFhqVGVCdEtmY09WS2RuVUtMOVZlPS1XPTlIUlJVaFN0b3hXcWF1T2ZyWkp0VmVNUmNMVzlBcUo0WGZSLVRmUWNaelRpRVFHTDlCSXA9d1JPWGJWTmw5S2o4U0dLZGxVNlRTWHVqOUdMQkhSUTBoU2JWa1c3RHBNYzdSTnRFZE1SWXRYODk3UEo3ZVF0VGxRZXg3Q0NBUU5kUlNYN25vVGRYSkc5aDhURE1LS3J4NVVLUzFIPT1PR1BSOUNoRWxUN1ZPV0xIRVpBYmJOc1ZZTVBEeVg5Qk5NN2ZOTXNmd1FOWjdUU01BTGE1WlJZYnhVZGJmVTloOEVUTWFQTDlpUTVYLVpQQ3FTPTlITHlycFRNWndOTD1EWkE3YUs5RlZNVGc3Tk1kUE9NZk5MdHo0UXRkM1NBc25OZHBhWEp2eVR2ZXNUTmg4VURJUkdjQm9VWUQwWj1MT0pmSi1DZmd0U2NONVdLN0VNYzdZTXJSZk1oWHVZZEFyTzhMZ01zZW9PTEZORUNRQVY5WmFJSTdzUE5IRklPSlNFUDhTUThCb1VJLXhVZkxrTmVsSkh2Z3lUYlotSTZiVFo9alpFYkJaS1FJSEtORXFYcnZlV1Bya1FOWnpRQ0VuT2RSYVJZYXNUT1d3Vk9WdEhmQVNQdVppVUktdFktPTZMY0JJQ3hFaFQ3VmtaTD1wTWdmY05iaFFNaGNMVjhjclFJWGZSLVRmUWNaelRpRVFHTDlCSXA9MlU5WE5WdGNYSmpVZFBxTW9TS1hHSj1IUE5lZEhIdzB2U2NVcE01YXNMZ2piSnRWY009RUxWOUo9UkxmZ01zZndSY2RyQ1JnUVk5aGFJSTd3UE5IRklPTnNSRElkTGFkalNLWE9XLWVxTWZWSVJqY3hUOFYtWWFhdUpRTFpOTUJQS1FjaFc4ZFBLOEhkUHNQeE9kWWFVaURzTU9ORklLPWlUc0RqVGVGU0hmOGRRN2hrVkpQa1gtZk9HTTFHTFFBak9MWmdZcWJUSlFMWU1yUmZNaFh1WWRBck84TFZRcz1nUU5aN1RTTUFZLTVTSUxXc089dlJTOWdZS2pVY1Zkb3dSN3ExV3ZETUlPbDJJQ2NwUU1VeFpyN1BJUWpSTnJSZk9mSUNYTWRQSzdqaU1mYm5PTlllSmlBT0tOaEpPclhzUk9Xd1YtQjREVGtUUHFOeVVJREZZT2otR0xCLVJUY2xRNkZLV3JERVotTE5KTEJWTVBJRFhjOTdQSjdoTXZyZlFiRVdTQXNuTmRwYVhKdnlUdmVzVE9FWEtpVVRMc1FvU0tUS0g9Q3FLYmQ4SHlzaFNhNHBZcTc9T2Q9Y0p1dE5PZkRxVzdwbVBMbmVXZHp0UXVnYVNpRW5QZGhaSU1Yb1VkVGZVOWg4RVEwYVBMOWlRNVhrWC1mT0dQTkdLdlF6UWNVdGFMLXZOUVBaRWRWWkpSTUhJOFY9WHJYZUg4PW5NTUp6R1NRQVY5WmFJSTdzTz16RlQtRlRKalVjVUtOdlU2VEtYZkxQSWJkOEh5c2hTYTRwWXE3PU9kPWNKdXROT2ZEcVc3cG1QTG5lV2R6dFF1Z2FVaU1BR05SU0lNWGtUZnZGVDljWE1qa2JRLVpNUkpLdFgtZXFLZlY5R3dnc1E3RkNhS2ZUSVFqWkVzbGZNQUlDSGNaN084ZkpXQVhnTDhWY1FTSUJNZVJTT3FQbVU5WEZWZGxzTGlJQ1VlNWJPN24tUHVQd0VNRnlIallpTjdSdlc2YnBNZ2pSTnNsTk9pd0xHY2hRT01mZFFzZnNPOEp1RGhjOE1ieE5OSnZRTz1uZktjdFBJVFFHS3FOaVBNYXNZdHY3S1BoeVFQOHdOc0pCYUtYMk5RYkZKODFMSlRra0dNaDhPTGpLUHdiRk5NVnpMQXNrVTdoRVdKYnhPTkdzU2MxZUNEWUdMN2R4UDdhc1l0M0xLUGw5VWdneE5iSkdWSnIyVnM9Uko4bFFKaFV3VUxwLVpiYldNdVNwUU5aelJDRW1MZUpTUk1UbE92cnVTT0pzTGpRY1ZLZHlTS1B6Vk5yOVZ1aC1Dd0RxUU1WQ1lxWD1OTVRQSXNsTk95dnBHYng3STQ9TE10VGFLTzBWUVFzOE1hOWJJS1AxVE9Xc1RPRmVJUFVDVmVKYk83cmtZPUNxTGJGPU1Ba2NNTmhvVVpib1l2ZkRKZlpPTVN3TFNyZGlZckRGV0FYZ0w4VmNRU0ltUGR4Y09wdmZOUGpuUXNoUlR5Z0ZMZVZoVUpUQ1pmTC1UPVJJQ3hFaFNiVndVWmJtWD1IQVNjUVhKZ00tRzd0eVdZPUpaZERhS09oZE93Z25OZHBkTk1UbE92cnVTTmRvSVRJUktyZ3BVWT1TWlBMPVQ9Wj1MallpTnRwdlc2WD1OUUhQSXNsVU9oWHlZY1o3TzRQVUx0amFLT2hkT3dnbUxlVmJPcHV0UlB2alN0ZG9JUFVSS3JoYk83dXNWTnI2S2ZWLVJRVHBRS0JnWXFmPU5NVEFTY0JlTVNrY0g3dGlWWUhXV09Pck9kTklEQXdtUU5kRU1aZnlUd2ZBRmNoUUhqUVRNN2h1VTZUTlZOcjZLYjlJVVFmdk1OaDlJSnZBTU1ERVNlb1dKd01HVUxwN09NSFZRdHZnTHVodVR3MDlOT2hITnFLdU9lWE1Wc3hmUHlnRktyaGdTNlRvVnRmaFR1aC1MQWZxUWJKQ1hwcjJPUUxGTjlRWk1UZnBHN3Q4UkxmSVF0ZXJMTEY2VEJrTk9PVkhOcDd6T2Z2QVdNNTVNaWNDVU9WaFM0PW9IPVBLS0xWdVRSSHRVT05aSThIMU5RSEFUTGhOT1JZS1VMMWhPTHJLV08tcU9lbElVaGdtTUtCUlJxNnhPZ2pRV2NoT1R5Z2NMdG9zU0tUelZOM2dLUGR5SENZd010aEJhNXYyUlBmRElzbGJPdklUVjlGbVBNM2VIY0xnTHVodVVBd01NT0ZCWEp1c1JPYkJFLUI4RFMwZEx0cHNTS0RGSWRmaEpMRnpIQVBwTk9oaklKcjJVdmZESXNsZk9oWUxWOUpsWHJmV1F2cmlLT2xVUVF3aktPZEZXSjcwT05MSVc4MTVMUDhITDlFdFBhSEpIOXpPTlBsekhDWHFOZGhiSUp6QUxmakZTY3daTVN3T0c4ZGlNND1LVmRQeE9jWnFVQmtOS09aSFJwYXZSZVhRRjg1NUxUa0hWTThvUEpUTlZOcjZLZjlJQ3hFdlQ4WkNZckN2UFBmR1NNaGNJU2d3VU1jcUs0N2VXZUR3Uk5KdURnZ3VWS1ZnUGI2dFhBUE9MUFJPSVRJQ1ZNQmtWcnJvVmVqT1QtcHVRaTRpTmFCU1g2Zm1PTTdGTjgxT0p3WUdHTHhNTzhmV0x0ZnFLTzEzUnlBUk5laGNOWk9zTlBqbVNNdDVQelFHWWRrdFA2SFNNZHJMTWJkeExBQXVOTEo1STV6UVFNPUZXZGhkUGdIcFhycGlNOFRKUT1Hb0xlbHFEQTBOVXRkRU1aZnhSZWJKRXVFWUlqRUNVZDFoVm89b1dQPUtLUEp1UlNzelRNWk9YckxVUVBmR1NNaGNJU2d3VU45UEo4ZmdNdFRxUWNkM1NDRVFQTmRIVzViMU9OTEFXTXQ1R1RjRlA3OHBPN3VzRU1IN0JMRVg9UEU4REtBb0Y0LXVYPT1wUU94WT1QRHJES0Y1RjQtc0VNWDVCTEVYT1RRdFU5Rm5WcktoSGNDY0VzQUtDZjdlR2FBdEpZLXNVYzZ0UWJkR0RpUHhUYU1xVTRLekl2S3dFLUFZQ3lIdVNkRXFWSS13SHNhY0ViRUtDZ0hlR2E0ZElJPXBYN09wRWFRWUdPUHJHNU1xSUlLc0g4NmNFYkVLQ2dIZUdhNGRJST1sWHRyWVV2TUtDZkRlR3I4ZElJMmhIY0NwQkxFWD1QRThES0FvRjQtdVZBNmNFYkVLQ3c9ZUdhNGRJSS10SDg2bkU2UVhDZVByS3BNcUluS3VIZmZxTmVoSlBTM2VHYUFkSVo2aEhjNmNFYkVXPVBEckRLQjdGNC1zRU1DcFYtQllRd2dkREtBcUY0RDlFTUNuQkxFWEN1UHJHWk1xTVhLdUg3T3BFZk5VUXlRbkRLQXFGNEQ5RU1DbkJMRVhEUEFhSU5OY1VZR3NVTT1hUXJSTEN2RHhTTk5hSW9HMUk9R3BFN1JHT2ZmZUdhQWRJSkNoSGM2Y0ViRklUVEl0UnRGa1c3THFZLTNyU094Sz1QRHJES0Y1RjQtc0VNQ3BCTEVYPVBZOURLVjhKbzNUVFB6NFNzaHBKaFR0V05sRVpWMTc="
                # 转圈红包任务
                # "data": "WVdnc1FFa0M9cFdqZGFOVj1ZaElTRGdWQm5TMkVyemM3TzRYdmVEbXJqUTI4cGtFPVAwYXhldjJ0ZmpFVVlISFZoeWplaXZtOWx5SWFIeHk1ZlN1SGVSVERPM2ZXcER6b2locXdoVGs5U0RDN3JSaTlmZ29YVjE9RmdqZjh1dUNHaGxJYVZpVzduQkdtbnk0bE40Zm1pQ2ptalEyOHBqZy1ZVHVvYWlpMGxoc1Vabj1HZm1iRXNSdTFuQklqWXplV2ZlU0Ruek0zVDN6anBGWER2Qml4a0ZjRVR4cEVhUmFCcUQwYUxGajFsRHY5dkFTa2prZ2dVaDI5a2g2PXJoRTRMb2JhaVRqa2stYVhwVUlaS3dXcGs9MmpnRDBYWlZyM2Rtakl2T3lBaGt3alZUZThwQjZVaEJ6RU5ucmJma1RSamUtV2d5RWtQa3hBZWZHOWZrY1hXa2ZIbHpyUmRmMmtzRWdnVWh5SmhQZURwQjA4TDRmdlpFM3JwZ0NicVNnN1ZEeXhwZ3F0bHhjWFhGZjdmMT1Wc2VtOWx5SWFIeHk4Yk9XY2VFczNPVkhYcjFib2todXVrREE2TkR5WnJSaVJyVWNYVm9YMmprdjl1dnhBZzE4cktCeEZnUkdlb2hFaE5vSFdvam55cHVxNXNqay1JVHllb1A1eG15Y1hYRmY2ZTJyZWo9MjVuRTBlVWhLNGdpbWVpRXdCTm5mRW5sVENpaDJtbFNFSVNEQ2xyUmlCb1Q0b1BGZURmbDM4ck8tUWh4QTBHeW1JbVF0dm9qWUhOa1RXbzJmZWpRQzFzVURFTndXcGs9NmRmajQtVEZmNXFGekhpaHEybmlYQ1h6WkFyeDJKb1VzM1JWSFhianprdXd5bWxTRUlUVENsc1Jkc29Va3lMRmVEZmxDd2RRV1VzRWdkS0IyRmtSR0FaU3pBVlk3bmREeXhqUTJmcGkwbFNFdWRhZkZyZ2hnZ1YxdlVlMTdJc1BpMmlTSWJYemFJZ09xRG5Cb0RSMWJYcTFUU2xReVpmQ2tFUWl1Z29QT2pmMGt5UUliQWZsenlyUVdVY2swYVV6SzRtaEtRcERZUk5vSFdvaVRqblJ5V2N5ZzdLZ09lb2ZHMGdENDFIbDMzamlUS3J2aUVpRWtlSFJ5NHJ4MlRpQm8tUjFIV2F6em9pUnlia0RBS1F5ZWNzZkNPaWdVZE1GdkJnemY4ZFB5R2JrZ2dMUkc3aEF1UFpSRVNVSVhhZVUza2tRMjRiemdrTWthWXBQS3FtUnc1VmwzMmYyamZteHVBaGtnSVVqU21hUkNiaEJ6RU5udUNabFhDdXd5WmZDa0ZUU3E3b3Yya29EMHdXMlRBbHpiRXR1eTZka2N5UENTNGh4MkVvaEk3UGtIbm4xYjFuUUNXYnpnbE9naWRzZzIwZmowRlZtZmtnMTNjbXZTMmlFZ2FZaTJUaE9hVWVDWTRPMkxtWkREb21OaWJweVFKTmlwRGFRZW1lMDRYVm9YMmxEcm5lPTJrc0VnZ1VoeUhoUGlocUI4NE5vZmJyMHpray1hWHBrSS1MMGlwZnUyMGx6RVVZV2pnZmluRXJPeUFoa3diWWl5bWJSLWNaQkhBUjJiWHIxVFNmUmlXcDA0Nk1qeUdvUlp0Z3dZb1JWakhsa3EwdU95M3FFZ2VQUmk0aD1lRXJ6Z1ZNNGZ4ZUY9d25kYWZyVUVvUGp5ZW9QMnlnejRmWlZ6UmdpakpyZUJCaGtnSVVqU1dmaTZjZUEwOFRtV0JuakxralJxV3BsWTZUVENsc1Jkc29Vb3dWbGVEZmwzQXVPQ1FjVmthVWtxNG11WnJuQzRtUjQ3bVowbnJuZWFXY3lnN01rcWNvZjJ4Z2lnUEhWdmhpaVRKaT1SQWlETThZeEdUamhDSHJ5VENPMkxtWkRIbHF4cW10emdMTkJxWnA9S0Jma3NjVjJmRmdpWE5yLUNra2xZZVBUNkloZWFRb2hNU1ZFPWFyMDNta2VlZnBDZzZYRHl5ZnUyMGxpd2dYWEM9YVZ6S3JPeTJpU0liV1RaQmtpZVRpRGdJVGxYNXFEemxzd3lhZkNnRU1qQzdzaGlCYmdVeFduckhtVGJFZWV5NmNoQXpMRXE0aD1lRW56WEJRNFB4ZlQyd2pRMjhwa0U9UDBheGV2MnRmaklnVlhINm1WPWZpZHg9bHpjYll6U21jU21EbnpNM09uam1uaj0tamc2bmxUa0JRZ1dscUE2OWZnb1hWM0w2ajFEVXZlR1JrbGtxVXp1NWhnaVByaERBUG5mWmREMnJwT3E1dDBIRU96dXpldjF3ZmpEREhuRFVyU3Zkc2ZtQW55Y0pYamVtc0NlRG5rczNUM3ZqWlZldGZSeXV0aWZITWpHenFBNm5uRDBhTEZqOWxDYm5kUDJscVJBYVV6SzRoUGVEcEIwN1dZUHdaRVhqcGVxRmJVQW9Hai1Zb2hPamdqNFBabHYyWldySWx0T0ZpakliSWZoQmFkbHNkPWpBSDQ3dXAxVG90c2g9YndQRUtmaEdlZGxzWnpVRFlYYndvRmZnYU5WPVloSVNEZ1ZCY08xcWF6ZkdUblM5bTFteWV0YXhja0hJSHpoPWFCbWNhamJGVDBQd2JsaXdkdHRBWWhERERnV1NYT1pzb2tQekgwQ3laRFNnZGRWOVloREREZ1dTWE9ac25rY2FUb0hCV2lXdGFOYU9ZaERER2ZoQmFkbHNkPWpBSDNiOVdpV3RhTmFPWWhERERnVkJYT2E5V2dYQVZvSGpubGZnc3NoPWJ3UEVLZmhCYWVaZlp3WHpIMUd5WnlYdnBSYTRoa0wyR3dWMGF2VmZad1hBRWtDPVdpWC1hTlY9c1U0OFRqRjBhZVpmWkJUekgwQz1iaU95cWRSQmJCSElTemRGYmVwdWFqa3dVME9EYWxtdGZOWj1iRUUzU2ZoQmFkbHNkPWpBSDNIQ3BHZmFwdy0yb2swRlJFZTRwUmxmWndYekhGLXlaeVdzZWRkPWNSPURIUU5HWE9ac1dnc1NFa1hSYVNQU3BRR09wQ2dWTnlsRHFSLUdxOU9O"
                # 元宝视频任务
                # "data": "TjVFT0k2RE96T0hYVDVFNTQ2RFRDN1RLakpJV1FQV1R1Rm5mVEJsSjJER3Z3TVdMZkZZLW9Ca3IwRVczM05uLU9GVGJrRDFiaEdWLVAtVXJyRFhmLUIxMTdFV3JLTzBuZUJZT3BEMXZ0SzIzZE5IQ0pERGZLTWtIcERGQ0hPazc2RVhQNkxHNnlLMjd0TWxySUNZV2ZHamJzRVdyZ0tHV3pQMm5hLW5UcklGT01QR0w2RVhQNkxJU3VKalRUUW1UNEJVeVBMV0RxS203SE1uNk9QM2JsSDNqa0pWTjc5R1BJUDJuOUFsYXVKa25EUUdISUVIV1ZMRXZ2SW1yMk9GbXdCSG5PSEVYYUQxLVFMMlRKQ2pMTEcxV3ZFbXJLUUV6YkFJR1RQRXIwRVczREwzQ3pNMnZiRzBtbkNIaVVERkxYRWt6NkJWNlpHSHF5Q2szMENJLVBNRHI3S2tmSDhXYWRPbXJRTVVuckRGLVBOa3J2Q25uVDhtYTJKVzdQTkVuYkxuV29NVmYwS2tQNk1sVzBEVzNiTmtiaEdWLVAtVXJ1PVRIVEJvT3ZFMFRMUW1QZURZU25HbExxRjJuN05IQ2RQM1RLTVhmYUdHU0lPbHEwRG5ETEFsVjhERzdsTlUzRUNJLVBNRWY0SzBmZE5HYXo9MnJRTVVxb0pXLVBOa3J1RG5mVUMyYXlKbT1PTVU9YUNZR3FHbm4wRVdub0tIMk5DWHZhSUVMb0lubWNPR1hJTkdyTEVsVjhER3ZDTVV6MENVMnA5VmY2S1ZlbUxINj1ERGZLTm5UVUNIbXVPMk8wRmpMTEcxYXBER3Z4SzBuZE5uV1NDWGpxS1VlaU5YOTNPbXJRTkhmYUcxLVE9RXJxUDJuS0cxNjlLMjdYUVdPakw0R3FCa3EzRVcybThINk5PbXJOQzBybkdIbU05MXF6TUhETEFsVjhER3ZHLWs9SUdYU2dDa3I2SVdyVThtYUtMbnZQLWxIYUQxLVFPV1Q2RVRiNktsSzdIVW5MUG1ISUVIV1NCa3YwSVZqQ0tGdXZEWGJsSDNqa0NIVzlMR1BJPVc3NktYdXZKVz1YTzJMMENJLVBNRExwSVhuNjlWV3dCREhRTWszckRuYXQ5RURySVRIQUttRzlFbXZPPUVuYU5uV2ZHa2Z4SWtQNjlWV3pDSHJQSDFIcUdXQ1RQVTNWSFRIQUJsbTZFVVhDLVZucThIV1ZDMD10RkZmRzgxbUtLbmpPREZyYURIYXg5VnJVRVhQNkxGcTJLMG5zTVU9YUNZR3FHbm4wRVdub0tIMmQ5RzNpRzBtbkNIbDc5R1BJUDJuOUFsYTZLMWp0TTBuYkxuV29NVmYwS2tQNk1sV3o9R25pSDFIYURuV1FNRT11R1RQTEtYLUFIRzdLLWxuRkVFR1VQVnI3RVdub0tHV2RFV3ZpSDFIYURuV1BQRnZGRlRMTEJtNndFVlhhLTAzZUZFR1VMVWI1RlZlbDhHLXlDWHZLTVhmYUlsT3ktMXZZUDJuQUtGVy1FRVhvUDB2YkNJV1VQVnJxRkVQN0tILXpDWGJiRHpucklYbU1PMXZVRVRiNktGVzVERzdMUVZuSTlIZW85ay16SWxqN09YMmQ9SGJLTW09YUNIVzlMR08wRmpMTEcxYUFKRmk2UFVuYkxuV1RHMGJxRkVQN09YQ05DWHJsRDJ6bUdVLVlOMlBZSFduQUtGVy1FV3ZTUUU3MURFR1VMVTYxRVdub0tIMk5DWHZqRHpuZklHTjZMRURxRVhmNktJT3ZLMjdYUVdPakw0S29MRXEzRVdyMk5GbUotM3ZLTVhmYUlrNTNMbHZaSW5ESzhXSzJIVVRLPWtuYkNJT1RMVXI0RlZUeTgxbWFHRExQREZHa0RtQ3hQVT1GSG16LU9XMTZFVlhhLTA3YkpvT2ZQVnI3RjBmN0wxcU5ESGpQTWxucERFNllMMDdZSFhmLUYzZT1FVFBYTlU9MUtrMlRQVnZzRmtUREtsV3ZPbXJrRHpucklHU1lOMk96PUduQUtGV3ZFMFRMT0dPakdZLWZHbVg3S1VmZE5sV3dNbXJPQzBua0NIbXlQV1hJQVRIVUxIaUFLMFRLPWtuZTlFMm9DbmpxRkVQN0tYNTVHWGJsRUVxbUNIYTFMR1B2SG5QVEFsVzVERz1UTUdQZUozaXFDVHF6SWxqN09YMmQ9SGJLTW09YURIYWZMRTNFRW12TEcyYTJIRFBYT0ZyMENFS1BMV1h1SW0zS09WcUtHSHZhTW1qYkRXQ2JQRTZ6R1duOUFsWjJKRWp0UW1Pa0VYU3FCa3EzRVcybThINk5Qem5qTmxia0lWUy1PR1hZUUhQNktJT3ZKVzdYLUdTai1JV25QRXEzRVc3Vk0yYXpMbXJOQzByaElrLXk5RnZaTkRINktYdXZFRVRLTzBuZUw0R3A5bFBwS2tmcDgzMmQ5RzNLTW09YURIYUhQRTdxLUhmLUVreS1FRlRMQVNXajhURjRCaWF6LW5EU01YMnpOaWF6LWlXa0FERjlCU2F6LW1IbU4zU3BNbVhtN1RLajVFLUg2RE96N1RLajVFNko2RE96TlhDVzhVNXI5a0ttLWpLaDVFNTQ2RFBFN1RLaktJLVNKSFQxN1RLajVFLUg2RE96LWlXajhURjRCaWF6LW1qaDVFNTQ2RFRDN1RLajVFQjI5eksyLTJHbU1sLXVHVkxESDBuYk8zWjdDRlg3SG1XcElGcTFFV1haSWpqci1JMTVCRURtRmpERUtWNnVLR3UwSFVPbkFtTj1Paz1yTzJyOU9XSzM5a0xRTFU2aEVuYU9KRT13Rm16QUxsaUhHV1c1TURYNERVeVpMVVRHSG5IekJHS1dFV3YwTWt6VkpIS0pHbWJrQzJqQUlHQ0FGV2JQLUZQYkMzZU1GRW5zRkdyVEJURjVDeWEwRENXajhURjRCaWF6LW1ua0ZYV3FLR0NtLWpLVzhsMXI5VE95N1RLajVFNko2RE96UEdIa0tsV3E2RE96N1RQeTVFNTQ5Q2F6LWlXakFqRjQ5WFh3TTJYZjVFNTQ2RFRDN1RLajhVVjItbWV5PURPazluNnEtVGUzPURYV0lYSjctVGJuLWptazhVLW9LV0ttLWpLVzhWOXI5VFBrUFhQbEhuLXlMR2J2UEY9bEtIbXI2RE96N1RQeTVFNTQ5RGUxLWpTajlVTjItaWF6LWlXb0J6RjlDeld4SDJIZkFIZVBDMD1YPUhIY0Q0TkY="
}
        )
        resp = self.send_multi_data_return_result(method="POST", url=url, headers=None, send_data=send_data,
                                                  cookies=None, check_status=statusExp)
        auth_code = resp["data"]["authcode"]
        return auth_code

    # 任务页领取元宝任务（任务类型4）
    def get_rewards_bytask(self, send_data, statusExp=200):
        url = "http://test-api.xss.91xunyue.cn/?service=App.Active.GetRewardsByTask"
        resp = self.send_multi_data_return_result(method="POST", url=url, send_data=send_data, headers=None,
                                                  cookies=None, check_status=statusExp)
        return resp

    # 获取任务页领元宝任务auto_code
    def get_Diamonds_task_autocode(self, statusExp=200):
        url = "http://test-api.xss.91xunyue.cn/?service=App.Active.GetRewardsByTask"
        send_data = MultipartEncoder(
            fields={
                "ts": "",
                "service": "App.Active.GetRewardsByTask",
                "sign": "",
                "data": "NTA9OGR6Qm1QSHowOXpCbVAwPXNjekJtUEVERWxJVXJLLVQ4OTdpMk45Q0lLRUVuTEFUczk2aURROUNVaEhrcmw9UDAtN2ozTkJRc2szU0RIOEQ4bzd5aVMtU0VrR2lESzhUOC04ekhKRGlVSEhFdmc5PTRrRVNqVi1Bd2NIaVRXOURza0ZEbkpFeVVIRVRIMDlURTA9aHpJOUNJS0VEREtKeUEwMlZ2WERBOGhJRWpXOURza0ZGPUZEZnN0SVV2azhQZ2tFVWJHLUFyUEhpVGhCREFvNzA2Ti1USWsyVTNoN0Qwbzd5elgtVElzMnlUaEI9Z0I3eWpTLUF3Y0lTWEhCPWtvNzA3WC1TRWtHaURLOFQ4LTh5M05CUXNrM1NES0V5VW89eURXLUF3Z0l5Ymc5RHNrRkMzVURnQTFGMHJHOT00a0VTelMtQXJQSVNER0lpRTE3ajJQREI4cEZ5REhHaUV3MjA9ZkFDTU9EanpqOVJ3bj1DelU5Q0VTRUVtUS1UczFBekhKRFFzazNTREgtRDhrRUY3R0RnQWxIVXZLR3owMDJUekctaUVsSEV2MEp6c2tFRjdHRGlVeEZFcjBHeU1rRVViR0RTWXhHa25nOURza0ZTWFdCPXNoR3pIZzk9NGtGQnlPRFE4U0VDUGc5U0EtOHluSERoOEhFaURIR2lFMTJURFY5Q0VTRUREMTdUODg9aHpLRFRFazNTRExJeXNrRkJqRkI9a1NFQ2JKSWlFOUZUM1FEUTRTRUNQaklpRS0yaVhOQlE0U0VDYkpJaUV6OHp6VS1Bd3BFVXYwNERvOUZCQ1FEU0VkSVVxUEd5TXo4enpVLUF3cEZ6PWc5RHN6NmlIR0Rmc3BHekhqSWlFcUYxN0ctQXdrM1NUaDc9NG83eWlULUF3YzNTVGg3PTRvN3luQTlDRVRDaURLR3o4cz1qbklEaVV4SVVxT0lpRXFGMTdHLUJ3LUlDUEg5REFuRVN5US15SWcyU1NPSWlFbjdWN0dEUTdVRVREMT1UZzkyUnp5RUJBZEZ6PWc5PTR6NmlITEJCN1VFakh6SWlFbjdWN0dEUThoMno9Zzk9NHo2aUhTRXg4VEdqPWc5RHN6NmlIUURTVT1DaURISHlza0ZCeU9EUThUQ2lER0p5c2tGRDNRQlI0U0VDYkpJaUVvPXlqVUJ3c2tHaj1nOVRJPTdpMk5CUjRTRUNiSklpRW8yRjdHLXc0U0VFdmtBVHctN2ozV0JCQXQyRXJLQVNza0VWZkE5Q0lvMkQ9ZzlEc3o2aUhORFNZcEYwckw9VEk4PWhqQTlDSUxDaURIN1Nza0VGPUE5Q1RVSGpIMTlTQT03aERXRXdBSEhqSHpJaUVxRVNqUUJ3c2xFRXJLR3lZODh6blNCUkFwSVQ9Zzk9NG89eURWLWdzVENpRExCVDQ5OHozUkJSNFNFQ2JKSWlFcTZsN1YtQ0VTSXlUR0lqQW43eURWQndza0dqPWc5UGstMlNIQTlDSUxDaURIOFNza0VGPUE5Q1VwSGt2eklpRXFGMTdHQUJBeEUwbmstVDQ5PWhmRUFROHhFVWprNEQ0OTdoRExEQjh4SVNQZzdRSTlGQ1RFQT1mTDN5VEhBRDh6NmlEUUJ3c2xHa21QLVRvLTJTWFdCUjh4SEQ9Zzk9NHBFU2pVLXc0U0VEREs4VEkxQXlXTkJCQXRHMG1QNENza0VWZkE5Q1RRMkVua0p5c2tFRj1BOUNVSEh6RDBFeVEwMlJDT0RTWXRDaURISHlza0VVcU9Cd3NrR2o9ZzlTTTFBekhOQj1veERVcktBVEk9N2kzV0V3NFNFQ2JKSWlFb0VTalctQ0RMSGlUdzN6QXE3VjdHLXc0U0VFbVE3U1E5RnhEVUJCQXBJVXVQNURFMTdWN0ctaVFTRUNUaklpRW43VjdHRGZzdEhVcks4U1kxPVJETkRTWXRDaURIR2pBbz15U1EtUnd3MmlYWEZqOHBJU0RRQndzbElVdms1REUwPWt2SkJ2b3gzej1nOT00bz15elgtVEl3MkNYWERmMG83MHJXLXc0U0VFbjBBVHc5MmlHU0J3c2szU1hYRGYwcElTeVAtQXNUQ2lESzlTQT04em5KRGlZSENpREhHZmdwPXlqVUVSc2tHaURLOFQ4LTh6SEpEaVlvRUNiRzlUMD09bD1ROUNFU0VFams4VEkwQXluVURpVXhIRXZrR3lJMS1pQ1Q5Q0ljRUNQZzlQay0yVDNXREI3UUZFblc5PTRrRlZ2QTlDVURIMG1RLVBvMUF5SEE5Q0lMQ2lESklpRW43VjdHREE3TUhVcU9JaUVxRjE3R0J3c2w0Q0RHSWlFMEF5blVFeVV4SUVxUEd6MD02aUNUOUNUUTJFbmtJaUVuNmlIVEJDVWgyekNQRnpnMTZpQ1Q5Q1UwMlRIeDg9Z283ajNHQlNJLUl5WFgtU1VvPXlERy13c2xIVXJXOT00a0VpM1NCUUFsSFVqMD1DRW42aUhRQkJBc0VDYkc5VDA9PWw9UTlDRVNFRW5rNENZa0VVYkdEU1l4R2tuZzlEc2tGQmpGQkRFazNTREg3PWdxRVNUWC1pSUMyQ2JIQj1rcUVqelUtaUlvM3lER0lpRTA9aTNOQlFzazNTREs4REVwPWpqV0JSd29JU1B4QT1rcTdpVFItUXdjMkREVzNDRXE3eVhKLXg4dzJ5VGhFajhvN3pIRy1DSUcyVER3OURza0ZDWE5Fd0FHRUNiRzlUMD09bD1ROUNFU0VFajAzQ1E4LWlDVDlDST1GREhLQkRJcDd6elhCQ0lERVNYeEFERW8yVGpHLXdzbEgwdjBHeU1rRVViR0RTWXhHa25nOURza0ZCREZEQjhzRUNiRzlTVXBGRGlRQlNJLUlUREs5PW8wPXppUy1USTBJU0RHSWlFMD1pWEhEQjhzRUNiRzlERTE3eVNQQlE4dEVTWHhCPXNvRkR5Uy1TSWdJeVQwNHZrdUZ5M1g5Q0VTRUVya0d2dzE9bDdHLWlFa0l5VGhFajhtRVNEVy1USTBFQ1BnOVNFLUZDM1NCUTdVSVVuSzhUdzEtaUNUOUNFa0dpREs5VEUwPWh6SURQc3AyVEgxOVRJOD1oRFM5Q0lLRUNER0lpRTkyaVdQQlJBbElVajA1RDBrRVViRy1Cd2dFQ1BnOVRJPTdpM1dFdzhISERHUT1UZzk9anpHLWlFa0l5WEg9REFwN3lTUy1TSW8zeURHSWlFODdpM1hEUTdVRlVqMDR5RXFFQ0RVOUNFU0VFdktBVEUtMlVQVERTRWszU0RIOEQwbzZodlg5Q0VTRUVxUDNDTTFBekhOQj1veEd6SGc5PTRrRVNEVS1DSWtIaVR4Nz1nbz16eU8tUXdzMmlieEZqSXA3ejNKLURJczN5WHhCPXNwRVU3VUJESTBJU2JrOVNRcDdpRFUtU0kwSXlTUD1TQW89anpVLUJ3R0lDV1BBU1VxNzBLTy1ESTFFaVhoPVNNa0VGN0dEZzdVSVVqMT1UZzkyUnZHLWlFa0VDUGc5VGctMlRIUUJCOD1JVWprR3o4a0VVYkctQXNrR2lES0d6ST03aENPRGlVSElVdmc5PTRrRkJ5T0RROFNFQ1BnOVNJOTJqM1NFd0FsM0NESEdpRTlGVDNRRFFza0dpREw9U0EtRkV2SkV3M1UyVEgxOVRJOD1oRFM5Q0lLRUNUSEJDRW42aUhJQlJBMUd6Q1BBVGcxNmlDVDlDST1GREhLQkRJcDd6elhCQ0lERVNYeEFERW8yVGpHLXdzbDIwamtHekktMmpuRkV3c2szU0RHM3pJbkVTaU8tUXdrSVNYSC1RNG49em1WLUJyUDJDVEhEakFvPTA3Vj1SckwyMDNnM3pBbkVUelctVElnSXliaDhRNG49empHLXdzbEhESDE9UHM5MmlIUDlDSUtFRXVQR3lVOC1pRFE5Q1VISVV6MUFTUUFBenpHLWlFa0hpREdJaUU4PWh6WEV3OGhHa25sPVRnOT1qekctaUVrSUNUaDlERW49eWpWLXh3ZzN5REwzdXpPN3d5UDNPek42Z3lQM1RnOEdVaktIZXpOMlF5UTctelM2UXlQM1NrUUgwPUFHaXdBekJtUDA9c2N6Qm1QRGY3UTNCbj1FPTg4M2hlUDU9azhDUi1TRGkzUTIwMlE1djNUMlVyQ0U9RFUzeHlVMD1uTnpCbmcwPW5ORkZlQzNQbkEyaWlDM1BuTHpCbVAwPW9lekJtUEZEc25DRnJSMD1uTnpCcmUwPW5OMlF5UDNPek42Z3lQM1NBTHpCbVAwPXNjekJtUDA9dkwyeGlQST1FcT1DPXJBUVFGQ1Mza0dBOHFFRHJ0QVFVSDRGMzJJU1hQR0VQdEpCa1EybHZxSVNzTDdrSFY0dzhRSGk9TTl5b1VEbDNrQUE3TC16M3VJPXNQOUYzQUh3OEI0RjMySVRBUEFCZVFBU1lIOVNibUlTc0w3aT1HQVJrRkVEM1hJUTh3N2hmTC1Dd2pDU1RlOXdZUDREcnQ5UVVSQ2xma0VRblI9RTNvNFE3TjJBeVE4dXpPN3d5UDNPek42Z3lQM1NFTz1VREJFQ2JBMlJtQzNnakEyUm1PMD1uTnpCbmcwPW5OSDBqUUZnRT16Qm1QMD1zY3pCbVA0dXpOMlF5UDdlek4yVnZNRmkwSnpCbVAwPXNjekJtUDQ9azg0RXpCRGZ2TERCakFEZjBCMmhtVkRDMDkyeHVXNHlyTjJ4ei1EUERBMlJtQzNRckEyUm5BSURzUEJrckpGQzBKSHpiUkZDVUF6Qm1QMD1zY3pCbVAzPTNQMlJ1VTRQak4yUXlQM096Uzd3eVU4dnZMPWtqTDdDTWs3eVh6NHprRzkxNmM="
            }
        )
        resp = self.send_multi_data_return_result(method="POST", url=url, headers=None, send_data=send_data,
                                                  cookies=None, check_status=statusExp)
        auth_code = resp["data"]["authcode"]
        return auth_code

    # 加密接口
    def data_encode(self, param):
        url = "http://152.136.129.218/tools/apiEncode.php?bpStr=%s" % param
        return requests.post(url).text

    # 解密接口
    def data_decode(self, param):
        url = "http://152.136.129.218/tools/apiDecode.php?bpStr=%s" % param
        return requests.post(url).text


apiAutoTask = apiAutoTask()
