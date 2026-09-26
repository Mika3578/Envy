@echo off
rem %1 - $(ConfigurationName)
rem %2 - $(PlatformName)
setlocal EnableExtensions
if "%~1"=="" (
	echo error: PreBuild.cmd requires ConfigurationName
	exit /b 1
)
if "%~2"=="" (
	echo error: PreBuild.cmd requires PlatformName
	exit /b 1
)

if not exist "%~1 %~2" mkdir "%~1 %~2"

copy /b /y "..\HashLib\%1 %2\HashLib.dll" "%1 %2\"
copy /b /y "..\Services\zlib\%1 %2\zlibwapi.dll" "%1 %2\"
copy /b /y "..\Services\Bzlib\%1 %2\BZlib.dll" "%1 %2\"
copy /b /y "..\Services\SQLite\%1 %2\SQLite.dll" "%1 %2\"
copy /b /y "..\Services\MiniUPnP\%1 %2\MiniUPnPc.dll" "%1 %2\"

cscript.exe //E:jscript //nologo Revision.js
if /I "%~2"=="Win32" call "%~dp0CopyCrashpadHandler.cmd" %1 %2
exit /b %ERRORLEVEL%
