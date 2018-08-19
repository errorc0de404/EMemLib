using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EMemLib
{
    public class EMem
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr dwAddress, uint nSize, MemoryProtection flProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr dwAddress, uint nSize, AllocationType flAllocationType, MemoryProtection flProtect);

        // [DllImport("kernel32.dll")]
        //  public static extern bool VirtualAllocEx(IntPtr hProcess, IntPtr dwAddress, uint nSize, uint flAllocationType, uint flProtect)

        const int PAGE_NOACCESS = 0x01;

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [Flags]
        public enum STringEncoding
        {
            UTF8, ASCII, Unicode, ANSI
        }
      
        int PROCESS_ALL_ACCESS = (0x1F0FFF);

        Process pTarget;
        bool isOpened = false;

        /// <summary>
        /// Returns the base address of the module inputed.
        /// </summary>
        /// <param name="Modulename"></param>
        public IntPtr GetModuleBase(string Modulename)
        {
            IntPtr BaseAddress = new IntPtr();
            if (!isOpened) return new IntPtr(-2);
            try
            {
                foreach (System.Diagnostics.ProcessModule Module in pTarget.Modules)
                {
                    if (Module.ModuleName == Modulename)
                    {
                        BaseAddress = Module.BaseAddress;
                        return BaseAddress;
                    }
                }
                if (BaseAddress != IntPtr.Zero)
                {
                    return new IntPtr(-1);
                }
                return BaseAddress;
            }
            catch
            {
                return new IntPtr(-2);
            }
        }

        /// <summary>
        /// Changes the memory protection of the entered address, returns true if succeed.
        /// </summary>
        /// <param name="Startaddress"></param>
        public bool SetProtection(IntPtr start, uint size, MemoryProtection newprotection)
        {
            uint OldProtection = 0;
            return VirtualProtectEx(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), start, size, newprotection, out OldProtection);
        }

        /// <summary>
        /// Allocates memory to attatched process. Returns assigned address, or automatically assigned address if the address parameter is empty.
        /// </summary>
        public IntPtr AllocateMemory(IntPtr Address, uint size, AllocationType allocationtype, MemoryProtection protection)
        {
            return VirtualAllocEx(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, size, allocationtype, protection);
        }

        /// <summary>
        /// Attatches process to class for operation, returns true if succeed.
        /// </summary>
        public bool OpenProcess(string Procname)
        {
            try
            {
                pTarget = Process.GetProcessesByName(Procname)[0];
            }
            catch { isOpened = false; return false; }
            if (pTarget == null) return false;
            isOpened = true;
            return true;
        }

        /// <summary>
        /// Reads the value of the address entered, returns the type entered.
        /// </summary>
        /// <param name="Modulename"></param>
        public T Read<T>(IntPtr Address, int[] Offsets = null)
        {
            int bytesRead = 0;
            byte[] buffer = new byte[8];

            if (Offsets == null)
            {
                ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, buffer, buffer.Length, ref bytesRead);
                if (typeof(T) == (typeof(int)))
                    return (T)Convert.ChangeType(BitConverter.ToInt32(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(float)))
                    return (T)Convert.ChangeType(BitConverter.ToSingle(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(double)))
                    return (T)Convert.ChangeType(BitConverter.ToDouble(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(long)))
                    return (T)Convert.ChangeType(BitConverter.ToInt64(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(short)))
                    return (T)Convert.ChangeType(BitConverter.ToInt16(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(ushort)))
                    return (T)Convert.ChangeType(BitConverter.ToUInt16(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(ulong)))
                    return (T)Convert.ChangeType(BitConverter.ToUInt64(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(uint)))
                    return (T)Convert.ChangeType(BitConverter.ToUInt32(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(byte)))
                    return (T)Convert.ChangeType(buffer[0], typeof(T));
            }
            else
            {
                IntPtr TmpAddress = new IntPtr();
                ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, buffer, buffer.Length, ref bytesRead);
                for (int i = 0; i < Offsets.Length; i++)
                {
                    TmpAddress = new IntPtr(BitConverter.ToInt32(buffer, 0)) + Offsets[i];
                    ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, buffer, buffer.Length, ref bytesRead);
                }
                if (typeof(T) == (typeof(int)))
                    return (T)Convert.ChangeType(BitConverter.ToInt32(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(float)))
                    return (T)Convert.ChangeType(BitConverter.ToSingle(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(double)))
                    return (T)Convert.ChangeType(BitConverter.ToDouble(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(long)))
                    return (T)Convert.ChangeType(BitConverter.ToInt64(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(short)))
                    return (T)Convert.ChangeType(BitConverter.ToInt16(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(ushort)))
                    return (T)Convert.ChangeType(BitConverter.ToUInt16(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(ulong)))
                    return (T)Convert.ChangeType(BitConverter.ToUInt64(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(uint)))
                    return (T)Convert.ChangeType(BitConverter.ToUInt32(buffer, 0), typeof(T));
                if (typeof(T) == (typeof(byte)))
                    return (T)Convert.ChangeType(buffer[0], typeof(T));
            }
            return default(T);
        }

        /// <summary>
        /// Writes the value to address entered.
        /// </summary>
        /// <param name="Modulename"></param>
        public void Write<T>(IntPtr Address, T Data, int[] Offsets = null)
        {
            int bytesWritten = 0;

            if (Offsets == null)
            {
                if (typeof(T) == (typeof(int)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToInt32(Data)), 4, ref bytesWritten);
                if (typeof(T) == (typeof(float)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToSingle(Data)), 4, ref bytesWritten);
                if (typeof(T) == (typeof(double)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToDouble(Data)), 8, ref bytesWritten);
                if (typeof(T) == (typeof(long)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToInt64(Data)), 8, ref bytesWritten);
                if (typeof(T) == (typeof(short)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToInt16(Data)), 2, ref bytesWritten);
                if (typeof(T) == (typeof(ushort)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToUInt16(Data)), 2, ref bytesWritten);
                if (typeof(T) == (typeof(ulong)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToUInt64(Data)), 8, ref bytesWritten);
                if (typeof(T) == (typeof(uint)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToUInt32(Data)), 4, ref bytesWritten);
                if (typeof(T) == (typeof(byte)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, BitConverter.GetBytes(Convert.ToByte(Data)), 1, ref bytesWritten);
            }
            else
            {
                byte[] buffer = new byte[8];
                int bytesRead = 1;
                IntPtr TmpAddress = new IntPtr();
                ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, buffer, buffer.Length, ref bytesRead);
                for (int i = 0; i < Offsets.Length - 1; i++)
                {
                    TmpAddress = new IntPtr(BitConverter.ToInt32(buffer, 0)) + Offsets[i];
                    ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, buffer, buffer.Length, ref bytesRead);
                }
                TmpAddress = new IntPtr(BitConverter.ToInt32(buffer, 0)) + Offsets[Offsets.Length - 1];
                if (typeof(T) == (typeof(int)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToInt32(Data)), 4, ref bytesWritten);
                if (typeof(T) == (typeof(float)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToSingle(Data)), 4, ref bytesWritten);
                if (typeof(T) == (typeof(double)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToDouble(Data)), 8, ref bytesWritten);
                if (typeof(T) == (typeof(long)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToInt64(Data)), 8, ref bytesWritten);
                if (typeof(T) == (typeof(short)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToInt16(Data)), 2, ref bytesWritten);
                if (typeof(T) == (typeof(ushort)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToUInt16(Data)), 2, ref bytesWritten);
                if (typeof(T) == (typeof(ulong)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToUInt64(Data)), 8, ref bytesWritten);
                if (typeof(T) == (typeof(uint)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToUInt32(Data)), 4, ref bytesWritten);
                if (typeof(T) == (typeof(byte)))
                    WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, BitConverter.GetBytes(Convert.ToByte(Data)), 1, ref bytesWritten);
            }
        }

        /// <summary>
        /// Reads the string of the address entered. Returns the string of entered length.
        /// </summary>
        /// <param name="Modulename"></param>
        public string Readstring(IntPtr Address, uint stringlength, STringEncoding encoding, int[] Offsets = null)
        {
            int bytesRead = 1;
            byte[] buffer = new byte[stringlength * 2];
            string Retstr = "";
            if (Offsets == null)
            {
                ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, buffer, buffer.Length, ref bytesRead);
                switch (encoding) {
                    default:
                        Retstr = null;
                        break;
                    case STringEncoding.ANSI: 
                        Retstr = Encoding.Default.GetString(buffer);
                        break;
                    case STringEncoding.ASCII: 
                        Retstr = Encoding.ASCII.GetString(buffer);
                        break;
                    case STringEncoding.Unicode: 
                        Retstr = Encoding.Unicode.GetString(buffer);
                        break;
                    case STringEncoding.UTF8:
                        Retstr = Encoding.UTF8.GetString(buffer);
                        break;
                }
                return Retstr;
            }
            else
            {
                IntPtr TmpAddress = new IntPtr();
                ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), Address, buffer, buffer.Length, ref bytesRead);
                for (int i = 0; i < Offsets.Length; i++)
                {
                    TmpAddress = new IntPtr(BitConverter.ToInt32(buffer, 0)) + Offsets[i];
                    ReadProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pTarget.Id), TmpAddress, buffer, buffer.Length, ref bytesRead);
                }
                switch (encoding)
                {
                    default:
                        Retstr = null;
                        break;
                    case STringEncoding.ANSI:
                        Retstr = Encoding.Default.GetString(buffer);
                        break;
                    case STringEncoding.ASCII:
                        Retstr = Encoding.ASCII.GetString(buffer);
                        break;
                    case STringEncoding.Unicode:
                        Retstr = Encoding.Unicode.GetString(buffer);
                        break;
                    case STringEncoding.UTF8:
                        Retstr = Encoding.UTF8.GetString(buffer);
                        break;
                }
                return Retstr;
            }
        }
    }
}
