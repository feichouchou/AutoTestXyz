ECHO OFF
cls
color 02
ECHO.
ECHO.
ECHO.   ==============��װ����=============
ECHO.  
ECHO.       ��ʼ��װ���벻Ҫ�رձ�����...
ECHO.
ECHO.   =====================================
ECHO.  
@REM ��adb.exe��ӵ�PATH��
ECHO ��ʼ����
@REM ����ѭ���ı�ǩ
:LOOP
ping -n 3 127.1 >nul
ECHO �ȴ��������ֻ���
adb devices
adb wait-for-device

@REM ѭ����װ��Ŀ¼�µ�APK�ļ�
FOR %%i IN (*.apk) DO ( 
  ECHO ���ڰ�װ��%%i
  adb install "%%i"
  )
  
ECHO ȫ����װ���ˣ����в��԰ɣ�����
PAUSE

::�ظ���װ���أ�ɾ��@rem ��Ὺ��
@Rem GOTO LOOP
