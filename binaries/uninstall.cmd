@echo off

set TARGET_DIR="%ProgramFiles%\BGU Soft\kbdhooksrv"

IF NOT EXIST %TARGET_DIR% (
	echo Product not installed
	goto end
)

kbdhooksrv.exe /check_admin

IF "%ERRORLEVEL%"=="1" (
	echo You must be administrator for unsetup.
	goto end
) ELSE (
	echo Checking on administrator group is completed.
)

echo Try service removing...

kbdhooksrv.exe /remove_service

IF "%ERRORLEVEL%"=="1" (
	echo Service stopped failed.
	goto end
) ELSE (
	echo Service stopped successfull.
)

kbdhooksrv.exe /remove_driver

IF "%ERRORLEVEL%"=="1" (
	echo Removing driver is failed.
	goto end
) ELSE (
	echo Removing driver is completed.
)

del /Q %SystemRoot%\System32\Drivers\kbdhook.sys

kbdhooksrv.exe /unregister_source

IF "%ERRORLEVEL%"=="1" (
	echo Unregistering source is failed.
	goto end
) ELSE (
	echo Unregistering source is completed.
)

del /Q %TARGET_DIR%\kbdhooksrv.exe %TARGET_DIR%\kbdhookdll.dll

echo Cleanup success. 
echo All operations perform successfully

:end