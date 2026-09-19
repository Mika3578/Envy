rem %1 - $(ConfigurationName)
rem %2 - $(PlatformName)

copy /b /y "..\HashLib\%1 %2\HashLib.dll" "%1 %2\"
copy /b /y "..\Services\zlib\%1 %2\zlibwapi.dll" "%1 %2\"
copy /b /y "..\Services\Bzlib\%1 %2\BZlib.dll" "%1 %2\"
copy /b /y "..\Services\SQLite\%1 %2\SQLite.dll" "%1 %2\"
copy /b /y "..\Services\MiniUPnP\%1 %2\MiniUPnPc.dll" "%1 %2\"

cscript.exe //E:jscript //nologo Revision.js
