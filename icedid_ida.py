# Author: Ivan Pisarev

import idc
import idautils

FUNCTION_OFFSET = 0xDEADFACE


def get_addr_all_strings(func_addr):
    encrypting = []
    func_xrefs = XrefsTo(func_addr, flags=0)
    for xref in func_xrefs:
        instruction = idc.PrevHead(xref.frm, minea=0)
        while GetMnem(instruction).find('push') == -1:
            instruction = idc.PrevHead(instruction, minea=0)

        encrypting.append(GetOperandValue(instruction, 0))
    return encrypting


def decrypts_all_strings(offsets):
    result = []

    for offset in offsets:
        if offset != 0:
            key = idc.Dword(offset)
            size = idc.Word(offset) ^ idc.Word(offset + 4)
            plaintext = ''

            for index in range(size):
                key = ((key << 29) | (key >> 3)) + index
                key = key & 0xFFFFFFFF
                ciphersymbol = idc.Byte(offset + index + 6)
                plainsymbol = (key ^ ciphersymbol) & 0xFF
                plaintext += chr(plainsymbol)

            result.append([offset, plaintext])

    return result


print "[Decryptor] Base offset of function: %x" % FUNCTION_OFFSET

offsets = get_addr_all_strings(FUNCTION_OFFSET)
decypted = decrypts_all_strings(offsets)

print "Count of decrypted string: %s" % hex(len(decypted))

for val in decypted:
    print '\n------------------------------------'
    print 'Offset: %x' % val[0]
    print 'Plaintext: %s' % val[1]
    print '------------------------------------'
    MakeComm(val[0], val[1])
