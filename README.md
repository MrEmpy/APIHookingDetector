# 「⚙️」API Hooking Detector
Detect which native Windows API's (NtAPI) are being hooked

## Usage

```
PS C:> .\Detector.exe -o output.txt


    _   ___ ___   _  _          _   _             ___      _          _
   /_\ | _ \_ _| | || |___  ___| |_(_)_ _  __ _  |   \ ___| |_ ___ __| |_ ___ _ _
  / _ \|  _/| |  | __ / _ \/ _ \ / / | ' \/ _` | | |) / -_)  _/ -_) _|  _/ _ \ '_|
 /_/ \_\_| |___| |_||_\___/\___/_\_\_|_||_\__, | |___/\___|\__\___\__|\__\___/_|
                                          |___/

                                    [Coded by MrEmpy]

[*] NT API being hooked:
=========================================================================================
[-] NtGetTickCount [0xB8D18B4C != 0xFE0320B9]
[-] NtQuerySystemTime [0xB8D18B4C != 0xFD83EBE9]
[-] NtdllDefWindowProc_A [0xB8D18B4C != 0x42FA25FF]
[-] NtdllDefWindowProc_W [0xB8D18B4C != 0x43AA25FF]
[-] NtdllDialogWndProc_A [0xB8D18B4C != 0x426A25FF]
[-] NtdllDialogWndProc_W [0xB8D18B4C != 0x431A25FF]
=========================================================================================
```
