# Author: Ivan Pisarev

import re
import struct
import gzip
import StringIO
import sys
import json
import argparse
from Crypto.Cipher import ARC4

class IcedIdHandler:
    def __init__(self):
        self.events = None
        self.seed = None

    def _get_sid_from_string(self,sid_str):
        res = re.search("S-1-[0-9]{1,2}-[0-9]{1,2}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{4,}",sid_str)
        if res:
            return res.group(0)
        return None

    def _get_based_on_sid(self, sid):
        sid_array = sid.split('-')

        s1 = int(sid_array[4])
        s2 = int(sid_array[5])
        s3 = int(sid_array[6])

        s4_2 = s1 & 0x00FF0000
        s4_2 = s4_2 >> 16
        s4_1 = s1 & 0xFF000000
        s4_1 = s4_1 >> 24
        s5_2 = s2 & 0x000000FF
        s5_1 = s2 & 0x0000FF00
        s5_1 = s5_1 >> 8

        data = [s4_2, s4_1, s5_2, s5_1]
        values = struct.unpack("I", str(bytearray(data)))
        rez = s3 + int(values[0])

        s6_2 = rez & 0x000000FF
        s6_1 = rez & 0x0000FF00
        s6_1 = s6_1 >> 8

        s6_3 = rez & 0xFF000000
        s6_3 = s6_3 >> 24
        s6_4 = rez & 0x00FF0000
        s6_4 = s6_4 >> 16

        add1 = [s1 & 0x000000FF, (s1 & 0x0000FF00) >> 8, s6_2, s6_1]
        values2 = struct.unpack("I", str(bytearray(add1)))

        add2 = [s6_4, s6_3, (s2 & 0x00FF0000) >> 16, (s2 & 0xFF000000) >> 24]
        values3 = struct.unpack("I", str(bytearray(add2)))

        based_on_sid = int(values2[0]) ^ int(values3[0])
        return based_on_sid

    def update_seed(self,sid_string):
        seed_int = self._get_sid_from_string(sid_string)
        if not seed_int:
            return False
        self.seed = self._get_based_on_sid(seed_int)
        return True

    def _ror(self,value):
        flag = value & 0x1
        value = value >> 1
        if flag:
            value = (value & 0xFFFFFFFF) | 0x80000000
        return value

    def _rol(self,value):
        flag = value & 0x80000000
        value = value << 1
        if flag:
            value = (value & 0xFFFFFFFF) | 0x1
        return value

    def _generate_key(self,str):
        v5 = 0

        for val in str:
            for i in range(13):
                v6 = self._ror(v5)
                v5 = v6
            v5 = (v6 + ord(val)) & 0xFFFFFFFF

        key = self.seed ^ v5

        return key

    def _make_seed(self,value):
        value = self._ror(value)
        value = self._ror(value ^ 0xFFFFFFFF)
        value = self._rol((value - 0x120) & 0xFFFFFFFF)
        value = ((value ^ 0xFFFFFFFF) - 0x9101) & 0xFFFFFFFF
        return value

    def _custom_decrypt(self,ciphertext, key):
        plaintext = ''

        for index in range(len(ciphertext)):
            key = self._make_seed(key)
            plainsymbol = key ^ ord(ciphertext[index])
            plaintext += chr(plainsymbol & 0xFF)

        return plaintext

    def _gzip_unpack(self,packed_data):
        if packed_data[0] != chr(0x1f) or packed_data[1] != chr(0x8b) or packed_data[2] != chr(0x8):
            packed_data = chr(0x1f) + chr(0x8b) + chr(8) + chr(0) * 7 + packed_data

        compressedFile = StringIO.StringIO()
        compressedFile.write(packed_data)

        decompressed_file = gzip.GzipFile(fileobj=compressedFile, mode='rb')
        compressedFile.seek(0)
        result = decompressed_file.read()

        return result

    def _split_strings(self,str):
        result = []
        while len(str):
            size = struct.unpack('B', str[0])[0]
            value = str[1:size]
            str = str[size + 1:]
            result.append(value)
        return result

    def _parse_cnc(self,str_cnc):
        if len(str_cnc) < 132:
            return None
        return self._split_strings(str_cnc[132:])

    def _parse_element(self, flag, element):
        if flag == 0x10:
            target = element[0]['value'][:-1]
            pattern_start = element[2]['value'][:-1]
            pattern_end = element[3]['value'][:-1]
            replace_to = element[4]['value'][:-1]
            return {'action': 'modify', 'url': target, 'start': pattern_start, 'end': pattern_end,
                    'replace': replace_to}
        if flag == 0x11 or flag == 0x13:
            target = element[0]['value'][:-1]
            pattern = element[2]['value'][:-1]
            replace_to = element[3]['value'][:-1]
            return {'action': 'modify', 'url': target, 'pattern': pattern, 'replace': replace_to}
        if flag == 0x12:
            target = element[0]['value'][:-1]
            replace_to = element[2]['value'][:-1]
            return {'action': 'modify', 'url': target, 'replace': replace_to}
        if flag == 0x20:
            target = element[0]['value'][:-1]
            start = element[2]['value'][:-1]
            end = element[3]['value'][:-1]
            return {'action': 'grab', 'url': target, 'start': start, 'end': end}
        if flag == 0x21:
            target = element[0]['value'][:-1]
            return {'action': 'grab_all', 'url': target}
        if flag == 0x22:
            target = element[0]['value'][:-1]
            value = element[2]['value'][:-1]
            return {'action': 'grab_regex', 'url': target, 'regex': value}
        if flag == 0x2E:
            target = element[0]['value'][:-1]
            return {'action': 'grab_search', 'url': target}
        if flag == 0x30:
            target = element[0]['value'][:-1]
            return {'action': 'block', 'url': target}
        if flag == 0x31:
            target = element[0]['value'][:-1]
            return {'action': 'screenshot', 'url': target}
        if flag == 0x32:
            target = element[0]['value'][:-1]
            redirect_to = element[2]['value'][:-1]
            param_string = element[3]['value'][:-1]
            if param_string.find('#') != -1 and param_string.find('front:/') != -1:
                reg_salt, request = param_string.split('#', 1)
                request = request.replace('front:/', '<%CnC%>')
                return {'action': 'redirect', 'url': target, 'to': redirect_to.replace('front:/', '<%CnC%>'),
                        'params': {'registry': reg_salt, 'request': request}}
            else:
                return {'action': 'redirect', 'url': target, 'to': redirect_to.replace('front:/', '<%CnC%>'),
                        'params': param_string}
        if flag == 0x33:
            target1 = element[0]['value'][:-1]
            target2 = element[2]['value'][:-1]
            redirect_to = element[3]['value'][:-1]
            param_string = element[4]['value'][:-1]
            if param_string.find('#') != -1 and param_string.find('front:/') != -1:
                reg_salt, request = param_string.split('#', 1)
                request = request.replace('front:/', '<%CnC%>')
                return {'action': 'redirect', 'url': target1, 'regex': target2,
                        'to': redirect_to.replace('front:/', '<%CnC%>'),
                        'params': {'registry': reg_salt, 'request': request}}
            else:
                return {'action': 'redirect', 'url': target1, 'regex': target2,
                        'to': redirect_to.replace('front:/', '<%CnC%>'), 'params': param_string}
        if flag == 0x34:
            target = element[0]['value'][:-1]
            replace_with = element[2]['value'][:-1]
            redirect_to = element[3]['value'][:-1]
            return {'action': 'redirect', 'url': target, 'redirect_with': replace_with,
                    'to': redirect_to.replace('front:/', '<%CnC%>')}
        if flag == 0x51:
            target = element[0]['value'][:-1]
            return {'action': 'ignore', 'url': target}
        if flag == 0x60:
            target = element[0]['value'][:-1]
            grab_var = element[2]['value'][:-1]
            return {'action': 'save', 'url': target, 'value': grab_var}
        if flag == 0x61:
            target = element[0]['value'][:-1]
            grab_var = element[2]['value'][:-1]
            return {'action': 'show', 'url': target, 'value': grab_var}
        if flag == 0x62:
            target = element[0]['value'][:-1]
            grab_var = element[2]['value'][:-1]
            return {'action': 'delete', 'url': target, 'value': grab_var}
        if flag == 0x63:
            target = element[0]['value'][:-1]
            grab_var = element[2]['value'][:-1]
            return {'action': 'start_command', 'url': target, 'value': grab_var}
        if flag == 0x64:
            target = element[0]['value'][:-1]
            return {'action': 'grab_body', 'url': target}
        if flag == 0x40 or flag == 0x41:
            interesting_strings = self._split_strings(element[0]['value'])
            return {'action': 'search', 'value': interesting_strings}
        return {'unknown_action': flag, 'elements': element}

    def _split_on_baseblocks(self,str_config):
        result = []
        while str_config:
            size = struct.unpack('I', str_config[:4])[0]
            block = str_config[4:size]
            str_config = str_config[size:]
            result.append(block)
        return result

    def _read_string(self, str_element):
        size = struct.unpack('I', str_element[:4])[0] & 0xFFFFFF
        type = struct.unpack('B', str_element[3])[0]
        str = str_element[4:4 + size]
        return type, str

    def _parse_baseblock(self,baseblock):
        flag = struct.unpack('B', baseblock[0])[0]
        elements = []
        elements_count = struct.unpack('B', baseblock[1])[0]
        baseblock = baseblock[2:]
        for i in range(elements_count):
            type, str = self._read_string(baseblock)
            baseblock = baseblock[4 + len(str):]
            elements.append({'type': type, 'value': str})
        return {'flag': flag, 'elements': elements}

    def _parse_config(self,str_config):
        result = []
        base_blocks = self._split_on_baseblocks(str_config[8:])
        for block in base_blocks:
            try:
                dirty = self._parse_baseblock(block)
                parsed = self._parse_element(dirty['flag'], dirty['elements'])
                result.append(parsed)
            except:
                result.append({'action': 'error', 'data': block})
        return result

    def decrypt_config(self,ciphertext):
        cfg_strings = ['*cfg0', '*cfg1', '*rtd', '*p*', '*bc*']
        for cfg_str in cfg_strings:
            custom_key = self._generate_key(cfg_str)
            custom_plaintext = self._custom_decrypt(ciphertext,custom_key)
            rc4_key = custom_plaintext[:8]
            rc4_encrypted = custom_plaintext[8:]
            rc4_provider = ARC4.new(rc4_key)
            rc4_payload = rc4_provider.encrypt(rc4_encrypted)

            if rc4_payload[:4] == 'zeus':
                compressed_data = rc4_payload[8:]
                try:
                    decompressed_data = self._gzip_unpack(compressed_data)
                    if 'cfg' in cfg_str:
                        return {cfg_str: self._parse_config(decompressed_data)}
                    elif 'rtd' in cfg_str:
                        return {'cnc': self._parse_cnc(decompressed_data)}
                    else:
                        return {cfg_str: decompressed_data}
                except:
                    continue
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='IcedID config decryptor and parser.')
    parser.add_argument('registry_value', help='registry key name that include SID of infected user')
    parser.add_argument('path_to_cipherfile', help='path to file with encrypted data (in binary representation)')
    parser.add_argument('path_to_result_file', help='path to the file in which the result will be saved')
    args = parser.parse_args(sys.argv[1:])

    handler = IcedIdHandler()
    if not (handler.update_seed(args.registry_value)):
        print "Error while compute seed. Did you pass the correct registry key?"
        exit()

    try:
        with open(args.path_to_cipherfile,'rb') as cipherfile:
            ciphertext = cipherfile.read()
    except:
        print "Error while read cipherfile: {}".format(args.path_to_cipherfile)
        exit()

    plaintext = handler.decrypt_config(ciphertext)
    if not plaintext:
        print 'Error while decrypting data.'
        exit()

    try:
        with open(args.path_to_result_file, 'wb') as resultfile:
            resultfile.write(json.dumps(plaintext, indent=4))
    except:
        print 'Error while write result in file: {}'.format(args.path_to_result_file)
