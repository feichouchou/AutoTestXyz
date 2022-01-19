ECHO OFF
cls
color 02
ECHO.
ECHO.
ECHO.   ==============安装测试=============
ECHO.  
ECHO.       开始安装，请不要关闭本窗口...
ECHO.
ECHO.   =====================================
ECHO.  
@REM 将adb.exe添加到PATH中
ECHO 初始化…
@REM 无限循环的标签
:LOOP
ping -n 3 127.1 >nul
ECHO 等待您插入手机…
adb devices
adb wait-for-device

@REM 循环安装本目录下的APK文件
FOR %%i IN (*.apk) DO ( 
  ECHO 正在安装：%%i
  adb install "%%i"
  )
  
ECHO 全部安装好了，进行测试吧！！！
PAUSE

::重复安装开关，删除@rem 则会开启
@Rem GOTO LOOP
