ECHO OFF
cls
color 7C
ECHO.
ECHO.
ECHO.   ==============删除客户端=============
ECHO.  
ECHO.       开始删除，请不要关闭本窗口...
ECHO.
ECHO.   =====================================
ECHO.  

@REM 仅删除当前文件夹下的.apk文件
FOR %%i IN (*.apk) DO ( 
  ECHO 准备删除：%%i
  del /p "%%i" 
  @rem 如删除不需确认，请更换为该命令del /f "%%i"
  )
  
ECHO success！！！
PAUSE

