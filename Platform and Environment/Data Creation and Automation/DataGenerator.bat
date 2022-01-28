cls
echo "Starting generation"
:start
START /B notepadActivity.vbs
timeout 5
procdump -ma notepad
timeout 5
START /B C:\"Program Files"\Google\Chrome\Application\chrome.exe
timeout 5
START /B C:\"Program Files"\"Mozilla Thunderbird"\thunderbird.exe
procdump -ma thunderbird
timeout 5
START /B C:\"Program Files"\LibreOffice\program\simpress.exe
timeout 5
procdump -ma simpress.exe
timeout 5
START /B C:\"Program Files"\LibreOffice\program\scalc.exe
timeout 5
procdump -ma scalc.exe
timeout 5
START /B C:\"Program Files"\LibreOffice\program\sdraw.exe
timeout 5
procdump -ma sdraw.exe
timeout 5
START /B C:\"Program Files"\LibreOffice\program\soffice.exe
timeout 5
procdump -ma soffice.exe
timeout 10
procdump -ma explorer.exe
timeout 10
procdump -ma explorer.exe
Timeout 5
START /B C:\Windows\system32\calc.exe
timeout 5
procdump -ma calc.exe
Timeout 5
Taskkill /IM sdraw.exe /F
Timeout 5
Taskkill /IM soffice.exe /F
Timeout 5
Taskkill /IM scalc.exe /F
Timeout 5
Taskkill /IM simpress.exe /F
Timeout 5
Taskkill /IM thunderbird.exe /F
Timeout 5
Taskkill /IM chrome.exe /F
Timeout 5
Taskkill /IM notepad.exe /F
Timeout 5
Taskkill /IM calc.exe /F
timeout 20
goto start
