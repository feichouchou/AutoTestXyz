ECHO OFF
cls
color 7C
ECHO.
ECHO.
ECHO.   ==============ɾ���ͻ���=============
ECHO.  
ECHO.       ��ʼɾ�����벻Ҫ�رձ�����...
ECHO.
ECHO.   =====================================
ECHO.  

@REM ��ɾ����ǰ�ļ����µ�.apk�ļ�
FOR %%i IN (*.apk) DO ( 
  ECHO ׼��ɾ����%%i
  del /p "%%i" 
  @rem ��ɾ������ȷ�ϣ������Ϊ������del /f "%%i"
  )
  
ECHO success������
PAUSE

