@rem using _build ddk_path build_ver os_ver

set PROJECT_DIR=%CD%

call %1\bin\setenv.bat %1 %2 %3

cd /D %PROJECT_DIR%

cd ..\..\src

build

IF %DDKBUILDENV%==chk (
%DRIVERWORKS%\..\SoftICE\nmsym /TRANSLATE:package,source,always obj%BUILD_ALT_DIR%\i386\fsfltr.sys
)




