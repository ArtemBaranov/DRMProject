set PROJECT_DIR=%CD%

call %1\bin\setenv.bat %1 %2 %3

cd /D %PROJECT_DIR%

cd ..\..\src

build