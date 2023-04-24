@echo off

IF not "%OS%"=="Windows_NT" (
	echo This system may be install only in Windows 2000 and higher
	goto end
)

IF not "%PROCESSOR_ARCHITECTURE%"=="x86" (
	echo This system may be install only for x86 system
	goto end
)

IF "%1"=="" (
	goto usage
)
IF "%2"=="" (
	goto usage
)
IF "%3"=="" (
	goto usage
)

IF NOT EXIST "KbdHookDll.dll" (
	echo File kbdhookdll.dll not found.
	echo hello world
	goto end
)

IF NOT EXIST "kbdhookmsgs.dll" (
	echo File kbdhookmsgs.dll not found.
	goto end
)

IF NOT EXIST "kbdhook.sys" (
	echo File kbdhook.sys not found.
	goto end
)

IF NOT EXIST "kbdhooksrv.exe" (
	echo File kbdhooksrv.exe not found.
	goto end
)

IF NOT EXIST "uninstall.cmd" (
	echo File uninstall.cmd not found.
	goto end
)

kbdhooksrv.exe /check_admin

IF "%ERRORLEVEL%"=="1" (
	echo You must be administrator for setup.
	goto end
) ELSE (
	echo Checking on administrator group is completed.
)

set TARGET_DIR="%ProgramFiles%\BGU Soft\kbdhooksrv"

IF EXIST %TARGET_DIR% (
	echo Program already installed
	goto end
)

mkdir %TARGET_DIR%

IF "%ERRORLEVEL%"=="0" (
	echo Making directory for files is completed.
) ELSE (
	echo Making directory for files is failed.
	goto end
)

copy %CD%\kbdhookdll.dll %TARGET_DIR%\kbdhookdll.dll
copy %CD%\kbdhookmsgs.dll %TARGET_DIR%\kbdhookmsgs.dll
copy %CD%\kbdhooksrv.exe %TARGET_DIR%\kbdhooksrv.exe
copy %CD%\uninstall.cmd %TARGET_DIR%\uninstall.cmd
copy %CD%\kbdhook.sys %SystemRoot%\System32\Drivers\kbdhook.sys

echo Copying of files is completed

kbdhooksrv.exe /install_driver

IF "%ERRORLEVEL%"=="1" (
	echo Error in install driver in your system.
	goto end
) ELSE (
	echo Installing driver in your system is completed.
)

kbdhooksrv.exe /install_service

IF "%ERRORLEVEL%"=="1" (
	echo Error in install service in your system.
	goto end
) ELSE (
	echo Installing service in your system is completed.
)

kbdhooksrv.exe /create_param %~1 %2 %3

IF "%ERRORLEVEL%"=="1" (
	echo Error in install parameters for service.
	goto end
) ELSE (
	echo Installing parameters for service is completed.
)

kbdhooksrv.exe /register_source

IF "%ERRORLEVEL%"=="1" (
	echo Error in register source for service.
	goto end
) ELSE (
	echo Registering source is completed.
)

echo All operations perform successfully
echo You must reboot computer
goto end
	
:usage
echo.
echo Keyboard Monitoring System Setup
echo Use: install.cmd LogFileName LogMode HideStatus
echo.
:end