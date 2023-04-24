cd ..\..\src
"%VS80COMNTOOLS%bin\mc.exe" -u -U kbdhookmsgs.mc -h "%CD%\..\inc" -r "%CD%\..\out" 
cd ..\out
"%VS80COMNTOOLS%bin\rc.exe" -r kbdhookmsgs.rc
"%VS80COMNTOOLS%..\..\VC\bin\link.exe" -dll -noentry -out:"%CD%\..\..\bin\kbdhookmsgs\kbdhookmsgs.dll" kbdhookmsgs.res