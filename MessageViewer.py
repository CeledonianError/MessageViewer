import re
import math

print("Please input the FULL and EXACT (case-sensitive) name of the Luminator MTU file you would like to parse.")
f = input('> ')
print("Would you like to print previews of the graphics? This will give you a better idea of what the messages look like, but it can make it harder to find specific codes. (Y/n)")
p = input('> ')

if p in 'nN':
    preview_graphics = False
else:
    preview_graphics = True

bit_list = (b'\x00', b'\x01', b'\x02', b'\x04', b'\x08', b'\x10', b'\x20', b'\x40')
# These will be populated when the parts list is parsed. Default values are here for debugging purposes :)
psigns = {
    b'\x00':'N/A_0',#'odkhex',
    b'\x01':'N/A_1',#'frnt160',
    b'\x02':'N/A_2',#'side96',
    b'\x04':'N/A_3',#'rear36',
    b'\x08':'N/A_4',#'frnt120',
    b'\x10':'N/A_5',#'rear48',
    b'\x20':'N/A_6',#'frnt200',
    b'\x40':'N/A_7'#'side112'
    }
psign_ind = {
    'N/A_0':0,
    'N/A_1':1,
    'N/A_2':2,
    'N/A_3':3,
    'N/A_4':4,
    'N/A_5':5,
    'N/A_6':6,
    'N/A_7':7
    }

control_chars = (
    b'\xf1',
    b'\xf3', # Signed position -> two bytes for each (ie. f3 XX XX YY YY)
    b'\xf4', # Unsigned position (following bytes = PosX, PosY) for both graphics and text
    b'\xf6', # Graphic index
    b'\xf5', # Basically odkhex position
    b'\xf7', # Font index
    b'\xf9', # Frame time
    b'\xfa'  # Scrolling (first byte = horizontal, second = vertical? Need to test vertical scrolling)
    )

# Known controls (combining my findings and Zhong-ba's) and number of bytes that follow them:
controls = {
    b'\xf0':1, # MAYBE: Vertical centering
    b'\xf1':1, # MAYBE: Horizontal centering
    #b'\xf2':4, # 0xF2 0xNN 0xNN 0xNN 0xNN - Non-seq msg code (32-bit)
    b'\xf3':5, # 0xF3 0xXX 0xXX 0xYY 0xYY - Signed position
    b'\xf4':3, # 0xF4 0xXX 0xYY - Unsigned position
    b'\xf5':3, # 0xF5 0xXX 0xYY - ODK position
    b'\xf6':3, # 0xF6 0xGG? 0xGG - Graphic ID
    b'\xf7':3, # 0xF7 0xNN? 0xNN - Font ID
    b'\xf8':3,
    b'\xf9':3, # 0xF9 0xTT? 0xTT - Frame time in tenths of a second
    b'\xfa':3
    # Below are handled elsewhere
    #b'\xfb':3, # 0xFB 0xNN 0xNN - Non-seq msg code (16-bit)
    #b'\xfc':3, # 0xFC 0x?? 0xPP - Psign index
    #b'\xfd':3, # 0x
    #b'\xfe':0, # 0xFE - Message delimiter, variable number of bytes that follow
    #b'\xff':3
    }

# Recently (aka like a day ago as I'm writing this comment), Zhong-ba on GitHub made their own MTU-to-IPS program:
# https://github.com/Zhong-ba/luminator_mtu_to_ips/blob/main/mtu_reverse.py
# From here-on, I will occasionally use their findings as reference; in particular their findings regarding the controls.
# Here is their findings that I did not have previously:
# 0xF1 - Horizontal centering (unconfirmed)
# 0xF0 - Vertical centering (unconfirmed)
# 0xF5 - Layout control
# 0xFA - Colour planes, opaque control, colour mask, colour intensity
#        --> Note: this may not be 100% accurate given my findings point towards this being for scrolling?
#            and ofc anything to do with colour is useless on monochrome displays like OC uses,
#            so why would I be finding it in their MTUs?

# From IPS.ips PhysicalSigns table
# Key = PSignPartNumber (as seen in MWMASTER.PRF)
# Tuple = (PSignName, PSignDescription)
# I've commented on which one OC uses for quick(er) reference
parts_info = {
    b'\x01\x00':('         ODK_1', 'ODK DECIMAL ENTRY'),
    b'\x01\x01':('         ODK_2', 'ODK HEXADECIMAL'),      # OC Transpo ODK4
    b'\x01\x02':('         ODK_3', 'DIRECT ENTRY DECIMAL'),
    b'\x01\x03':('         ODK_4', 'DIRECT ENTRY HEX'),
    b'\x01\x04':('         ODK_5', 'NEXT STOP DECIMAL'),
    b'\x01\x05':('         ODK_6', 'NEXT STOP HEX'),
    b'\x01\x06':('         ODK_7', 'NS DIR ENTRY DECIMAL'),
    b'\x01\x07':('         ODK_8', 'NS DIR ENTRY HEX'),
    b'\x02\x11':('        REAR_9', 'MAX 1 CHAR.'),
    b'\x02\x12':('       REAR_10', 'MAX 2 CHAR.'),
    b'\x02\x13':('       REAR_11', 'MAX 3 CHAR.'),
    b'\x02\x14':('       REAR_12', 'MAX 4 CHAR.'),
    b'\x02\x15':('       SIDE_13', 'MAX 5 CHAR.'),
    b'\x02\x1A':('      FRONT_14', 'MAX 10 CHAR.'),
    b'\x02\x1C':('      FRONT_15', 'MAX 12 CHAR.'),
    b'\x02\x1F':('      FRONT_16', 'MAX 15 CHAR.'),
    b'\x02\x22':('      ROUTE_17', '8" MAX 2 CHR TOP LIT'),
    b'\x02\x23':('      ROUTE_18', '8" MAX 3 CHR TOP LIT'),
    b'\x02\x24':('      ROUTE_19', '8" MAX 4 CHR TOP LIT'),
    b'\x02\x3A':('      FRONT_20', '10 CHAR. UPSIDE-DOWN'),
    b'\x02\x3F':('      FRONT_21', '15 CHAR. UPSIDE-DOWN'),
    b'\x02\x42':('      ROUTE_22', '8" 2 CHR BOTTOM LIT'),
    b'\x02\x43':('      ROUTE_23', '8" 3 CHR BOTTOM LIT'),
    b'\x02\x44':('      ROUTE_24', '8" 4 CHR BOTTOM LIT'),
    b'\x03\x03':('       REAR_25', 'CONVERSION 3 CHAR.'),
    b'\x03\x04':('       REAR_26', 'CONVERSION 4 CHAR.'),
    b'\x03\x0F':(' FRONT/SIDE_27', 'CONVERSION 15 CHAR.'),
    b'\x03\x1F':('      FRONT_28', 'LIDS INTERFACE FRONT'),
    b'\x03\x2F':('  SIDE/REAR_29', 'LIDS INTERFACE S/R'),
    b'\x04\x01':('      ROUTE_30', 'GTI 1 CHAR'),
    b'\x04\x03':('       REAR_31', 'GTI 3 CHAR'),
    b'\x04\x04':('       REAR_32', 'GTI 4 CHAR'),
    b'\x04\x0F':('      FRONT_33', 'GTI 15 CHAR.'),
    b'\x04\x12':('      FRONT_34', 'GTI 18 CHAR.'),
    b'\x04\x20':('      FRONT_35', 'GTI 7X90 MATRIX'),
    b'\x04\x21':('      FRONT_36', 'GTI 7X75 MATRIX'),
    b'\x04\x22':('       REAR_37', 'GTI 7X17 MATRIX'),
    b'\x04\x23':('       REAR_38', 'GTI 7X23 MATRIX'),
    b'\x04\x24':('      FRONT_39', 'GTI 14x28+7x75 MATRX'),
    b'\x04\x25':('      FRONT_40', 'GTI 7X120 MATRIX'),
    b'\x04\x26':('      ROUTE_41', 'GTI 7X30 MATRIX'),
    b'\x04\x27':('      FRONT_42', 'GTI 7X75 (30 + 3X15)'),
    b'\x04\x28':('      FRONT_43', 'GTI 16x28+7x75 MATRX'),
    b'\x04\x29':('       DASH_44', 'GTI 7X60 MATRIX'),
    b'\x04\x2A':('       SIDE_45', 'GTI 7X90 (45 + 45)'),
    b'\x04\x44':('      FRONT_46', 'GTI 16X98 MATRIX'),
    b'\x04\x45':('      FRONT_47', 'GTI 16X96 MATRIX'),
    b'\x04\x46':('      FRONT_48', 'GTI 16X112 MATRIX'),
    b'\x04\x47':('      FRONT_49', 'GTI 16X112 (4 x 28)'),
    b'\x04\x4C':('       REAR_99', 'GTI 16X28 MATRIX'),
    b'\x04\x4A':('       REAR_51', 'GTI 16X20 MATRIX'),
    b'\x04\x4B':('       REAR_52', 'GTI 16X42 MATRIX'),
    b'\x04\x60':('       REAR_53', 'GTI 14X28 MATRIX'),
    b'\x04\x61':('       REAR_54', 'GTI 10X23 MATRIX'),
    b'\x04\x62':('       REAR_55', 'GTI 10X30 MATRIX'),
    b'\x04\x63':('      FRONT_56', 'GTI 10X90 MATRIX'),
    b'\x04\x83':('       REAR_57', '8" GTI 3 CHAR'),
    b'\x08\x03':('      ROUTE_58', 'GTI, LCD 3 CHAR.'),
    b'\x08\x06':('      FRONT_59', 'GTI, LCD 6 CHAR.'),
    b'\x08\x08':('      FRONT_60', 'GTI, LCD 8 CHAR.'),
    b'\x08\x09':('      FRONT_61', 'GTI, LCD 9 CHAR.'),
    b'\x08\x0C':('      FRONT_62', 'GTI, LCD 12 CHAR.'),
    b'\x08\x0E':('      FRONT_63', 'GTI, LCD 14 CHAR.'),
    b'\x08\x0F':('      FRONT_64', 'GTI, LCD 15 CHAR.'),
    b'\x08\x10':('       LEFT_65', 'GTI, LCD 16 CHAR.'),
    b'\x08\x13':('      FRONT_66', 'GTI, LCD 19 CHAR.'),
    b'\x08\x14':('      FRONT_67', 'GTI, LCD 20 CHAR.'),
    b'\x08\x20':('       LEFT_68', 'GTI, LCD 32 CHAR.'),
    b'\x08\x31':('      FRONT_69', 'AEG LCD, 18 CHAR X 1'),
    b'\x08\x32':('      FRONT_70', 'AEG LCD, 18 CHAR X 2'),
    b'\x08\x4F':('      FRONT_71', 'GTI, LCD 7X75 MATRIX'),
    b'\x08\x52':('      FRONT_72', 'GTI, LCD 7X90 MATRIX'),
    b'\x08\x90':('       LEFT_73', 'LCD 2 LINES 16 CHAR.'),
    b'\x08\x93':('       LEFT_74', 'LCD 2 LINES 19 CHAR.'),
    b'\x08\xAF':('     INSIDE_76', 'GTI, ASCII 15 CHAR.'),
    b'\x08\xB4':('       SIDE_96', 'LED 8X96 MATRIX'),      # OC Transpo 8x96 "Horizon" (side)
    b'\x10\x00':('  ODK M2000_80', 'ODK M2000 DECIMAL'),
    b'\x10\x01':('  ODK M2000_81', 'ODK M2000 HEX'),
    b'\x10\x02':('  ODK M2000_82', 'ODK M2000 DIR DEC'),
    b'\x10\x03':('  ODK M2000_83', 'ODK M2000 DIR HEX'),
    b'\x10\x04':('  ODK M2000_84', 'ODK M2000 NS DEC'),
    b'\x10\x05':('  ODK M2000_85', 'ODK M2000 NS HEX'),
    b'\x10\x06':('  ODK M2000_86', 'ODK M2000 NS DIR DEC'),
    b'\x10\x07':('  ODK M2000_87', 'ODK M2000 NS DIR HEX'),
    b'\x30\x00':('SUNRISE LED_88', 'SUNRISE LED 16 J1708'),
    b'\x30\x01':('SUNRISE LED_89', 'SUNRISE LED 16 RS232'),
    b'\x30\x02':('        LVA_90', 'VOICE ANNUNCIATOR'),
    b'\x04\x4D':('      FRONT_91', 'GTI, 16x98 MATRIX'),
    b'\x04\x64':('      FRONT_92', 'GTI, 10x92 MATRIX'),
    b'\x08\xB1':('      FRONT_93', 'LED, 16x160 MATRIX'),   # OC Transpo 16x160 "Horizon" (front)
    b'\x04\x48':('       REAR_50', 'GTI 16X28 MATRIX'),
    b'\x08\xB0':('      FRONT_95', 'LED, 16x112 MATRIX'),
    b'\x08\xB2':('      FRONT_96', 'LED, 16x140 MATRIX'),
    b'\x08\xB3':('      FRONT_97', 'LED, 16x120 MATRIX'),   # OC Transpo 16x120 "Titan" (side) - originally used for 2601, now the XD60s
    b'\x08\xB5':('       REAR_98', 'LED, 16x48 MATRIX'),    # OC Transpo 16x48
    b'\x08\xB6':('      SIDE_100', 'LED, 8x80 MATRIX'),
    b'\x08\xB7':('      SIDE_101', 'LED, 8x64 MATRIX'),
    b'\x08\xB8':('      SIDE_102', 'LED, 14x112 MATRIX'),   # OC Transpo 14x112
    b'\x08\xB9':('      DASH_103', 'LED, 12x40 MATRIX'),
    b'\x08\xBA':('      REAR_104', 'LED, 16 x 36 MATRIX'),  # OC Transpo 16x36
    b'\x08\xBB':('     FRONT_105', 'LED, 16 x 108 MATRIX'),
    b'\x08\xBC':('     FRONT_106', 'LED, 16 x 72 MATRIX'),
    b'\x08\xBD':('     FRONT_107', 'LED, 16 x 80 MATRIX'),
    b'\x08\xE0':('     FRONT_108', 'MULTI COLOR 16 x 112'),
    b'\x08\xE1':('     FRONT_109', 'PARTMULTICOLOR 16x148'),
    b'\x08\xE2':('      SIDE_103', 'MULTI COLOR 14 x 96'),
    b'\x08\xBE':('     FRONT_110', 'LED, 24 x 200 MATRIX'), # OC Transpo 24x200 "Titan" (front)
    b'\x08\xE3':('      DASH_104', 'MULTI COLOR 14 x 32'),
    b'\x08\xE4':('      REAR_105', 'MULTI COLOR 16 x 48'),
    b'\x08\xE5':('      SIDE_104', 'MULTI COLOR 8 x 96'),
    b'\x08\xE6':('     FRONT_111', 'MULTI COLOR 16 x 84')
    }

def get_raw_table(m, s, l, e):
    # m = mtu, s = start, e = end, l = length of entries
    if e == 0:
        e = int.from_bytes(m[s:s+4], 'big') - 196608
    table = [m[s:e][i:i+l] for i in range(0, len(m[s:e]), l)]
    return table

def build_graphic(data, height):
    data_bin = ''.join(f'{byte:08b}' for byte in data)
    data_bin = data_bin.replace('1', '#')
    data_bin = data_bin.replace('0', '.')
    bits_per_col = int(math.ceil(height / 8)) * 8
    data_bin = [data_bin[i:i+bits_per_col] for i in range(0, len(data_bin), bits_per_col)]
    data_bin = list(zip(*data_bin))[::-1]
    graphic = []
    for i in range(len(data_bin))[:height]:
        graphic.append(''.join(data_bin[i]))
    return graphic

def split_frame(raw):
    # Now need to split the data into individual elements, aka the fun part...
    frame = []
    s = b''
    i = 0
    # Big fucking bandaid for the edge case wherein a frame does not start
    # with a control, then the first element to have controls in it has more than one
    first_control = True
    if raw[0:1] in controls:
        first_control = False
    # Let the hell truly begin
    while i < len(raw):
        c = raw[i:i+1]
        if c in controls:
            # Handle graphics specially because they're special little bitch babies
            if c == b'\xf6':
                s += raw[i:i+controls[c]]
                frame.append(s)
                s = b''
                i += controls[c]-1
            # Catch when the control set ends
            elif raw[i+controls[c]:i+controls[c]+1] not in controls:
                # I think something breaks if you touch this
                if len(frame) == 0 and first_control:
                    frame.append(s)
                    s = b''
                    first_control = False
                s += c
                i += 1
                # Go until you found another set of controls or the end
                while raw[i:i+1] not in controls and i < len(raw):
                    s += raw[i:i+1]
                    i += 1
                i -= 1
                frame.append(s)
                s = b''
                first_control = False
            # Big bandaid
            elif raw[i+controls[c]:i+controls[c]+1] in controls and first_control:
                if len(frame) == 0:
                    frame.append(s)
                    s = b''
                    i -= 1
                    first_control = False
            else:
                s += c
                first_control = False
        else:
            s += c
        i += 1
    return frame

class Font:
    def __init__(self, header):
        # Get header data
        self.addr = int.from_bytes(header[0:4], 'big') - 196608
        self.width = int.from_bytes(header[4:5], 'big')
        self.spacing = int.from_bytes(header[5:6], 'big')
        self.first = int.from_bytes(header[6:7], 'big') # First ASCII character
        last = int.from_bytes(header[7:8], 'big') # Last ASCII character
        self.total_glyphs = last - self.first + 2
        # Initialize non-header vars
        self.glyph_data = []
        self.data_len = 0

    def make_glyphs(self, mtu):
        raw_offsets = mtu[self.addr:self.addr + (self.total_glyphs * 2)]
        offsets = [int.from_bytes(raw_offsets[i:i+2], 'big') for i in range(0, len(raw_offsets), 2)]
        s = offsets[0]
        raw_glyphs = mtu[self.addr + s:self.addr + offsets[len(offsets)-1]]
        for j in range(len(offsets)-2):
            glyph = build_graphic(raw_glyphs[offsets[j]-s:offsets[j+1]-s], self.width)
            self.glyph_data.append(glyph)
        self.height = len(self.glyph_data[0])
        #print(self.glyph_data)
        #print(offsets)
        #print(raw_glyphs)
        #print('')

    def get_glyph(self, g):
        # g = ASCII character
        if ord(g)-self.first < len(self.glyph_data):
            return self.glyph_data[ord(g)-self.first]
        else:
            # Fail-safe in case a font is missing characters
            return ['-'*self.width]*self.height

class Graphic:
    def __init__(self, header):
        self.addr = int.from_bytes(header[0:4], 'big') - 196608
        self.height = int.from_bytes(header[4:5], 'big')
        # Prevent div by zero crashes
        if self.height == 0:
            self.height = 1
    def make_graphic(self, mtu):
        w = int.from_bytes(mtu[self.addr+3:self.addr+4], 'big')
        raw_data = mtu[self.addr+4:self.addr+w]
        self.width = int((w-4) / math.ceil(self.height / 8))
        self.graphic = build_graphic(raw_data, self.height)

class Element:
    def __init__(self, raw, p):
        self.raw = raw
        self.psign = p
        # Defaults
        self.vcenter = False
        self.hcenter = False
        self.pos_x = 0
        self.pos_y = 0
        self.is_txt = True
        self.ind = 0
        self.frame_time = 0
        self.text = ''

        # Now for the big fuck you parse time
        ### MAYBE: Centering
        # Vertical
        if b'\xf0' in raw:
            i = raw.index(b'\xf0')
            self.vcenter = True
            self.raw = self.raw.replace(raw[i:i+1], b'')
        # Horizontal
        if b'\xf1' in raw:
            i = raw.index(b'\xf1')
            self.hcenter = True
            self.raw = self.raw.replace(raw[i:i+1], b'')

        ### Positioning
        # Elements should have either 0xF3, 0xF4, or 0xF5 if they specify their position.
        # There should never be multiple position controls.
        # 0xF3 0xXX 0xXX 0xYY 0xYY - Signed position
        if b'\xf3' in raw:
            i = raw.index(b'\xf3')
            #self.signed_pos = True # Unsure if this will actually be needed
            self.pos_x = int.from_bytes(raw[i+1:i+3], 'big', signed=True)
            self.pos_y = int.from_bytes(raw[i+3:i+5], 'big', signed=True)
            self.raw = self.raw.replace(raw[i:i+5], b'')
        # 0xF4 0xXX 0xYY - Unsigned position
        elif b'\xf4' in raw:
            i = raw.index(b'\xf4')
            #self.signed_pos = False # Unsure if this will actually be needed
            self.pos_x = int.from_bytes(raw[i+1:i+2], 'big')
            self.pos_y = int.from_bytes(raw[i+2:i+3], 'big')
            self.raw = self.raw.replace(raw[i:i+3], b'')
        # 0xF5 0xXX 0xYY - Character-based position for char-only signs (eg. ODK)
        if b'\xf5' in raw:
            i = raw.index(b'\xf5')
            #self.signed_pos = False # Unsure if this will actually be needed
            self.pos_x = int.from_bytes(raw[i+1:i+2], 'big')
            self.pos_y = int.from_bytes(raw[i+2:i+3], 'big')
            self.raw = self.raw.replace(raw[i:i+3], b'')

        ### Graphics and Fonts
        # An element can either be text or graphic, never both.
        # 0xF6 0xGG? 0xGG - Graphic ID
        if b'\xf6' in raw:
            self.is_txt = False
            i = raw.index(b'\xf6')
            self.ind = int.from_bytes(raw[i+1:i+3], 'big')
            self.text = f'< Graphic #{self.ind} @ pos ({self.pos_x}, {self.pos_y}) >'
            self.raw = self.raw.replace(raw[i:i+3], b'')
        # 0xF7 0xNN? 0xNN - Font ID
        elif b'\xf7' in raw:
            i = raw.index(b'\xf7')
            self.ind = int.from_bytes(raw[i+1:i+3], 'big')
            self.raw = self.raw.replace(raw[i:i+3], b'')
        # Default for fonts
        else:
            global psign_table
            global psign_ind
            global psigns
            ps_index = psign_ind[psigns[p]]
            self.ind = psign_table[ps_index].default_font
            #self.ind = p

        # Zhong-ba has 0xF8 in their list, but it never appears elsewhere in their code?
        # I'm just going to omit it for now. If I ever add it, it will go here!

        ### Frame-time and effects
        if b'\xf9' in raw:
            i = raw.index(b'\xf9')
            self.frame_time = int.from_bytes(raw[i+1:i+3], 'big') / 10
            self.raw = self.raw.replace(raw[i:i+3], b'')
            #print(self.frame_time, 'seconds')

        # 0xFA is for colours according to Zhong-ba, but my research points to it being for scrolling,
        # Therefore I am also going to omit it until I can figure out how exactly it works.
        # Once I figure it out, it will go here.

        # In theory, all controls should be accounted for,
        # and we can safely convert to ASCII?
        if self.is_txt:
            try:
                self.text = self.raw.decode('windows-1250')
            except UnicodeDecodeError:
                print('Failed to decode bytestring:', raw)
                exit()
    # Add graphical (ie. font or graphic) data
    def add_data(self, graphical_data):
        # Build text string with font
        if self.is_txt:
            self.font = graphical_data
            text_glyphs = []
            for char in self.text:
                c = self.font.get_glyph(char)
                text_glyphs.append(c)
            self.data = []
            # Stitch everything together
            for gly in text_glyphs:
                for row in range(len(gly)):
                    if row > len(self.data)-1:
                        self.data.append(gly[row] + self.font.spacing*'.')
                    else:
                        self.data[row] += gly[row] + self.font.spacing*'.'
        # Get graphic
        else:
            self.data = graphical_data.graphic
    # Print element
    def print_ele(self, indent):
        for row in self.data:
            print(indent*' ', row)
        print('')

# Will put this to use when adding support for other agencies
class Physical_Sign:
    def __init__(self, raw):
        self.addr = int.from_bytes(raw[0:1], 'big')
        self.default_font = int.from_bytes(raw[3:4], 'big')
        self.line_timing = int.from_bytes(raw[4:5], 'big')
        self.blank_timing = int.from_bytes(raw[5:6], 'big')
        self.blank_before_pr = bool(int.from_bytes(raw[6:7], 'big'))
        self.blank_before_rpt = bool(int.from_bytes(raw[7:8], 'big'))
        self.emergency_msg_num = int.from_bytes(raw[9:10], 'big')
        # There is also a byte of unknown use at raw[12:13]

class Message_Class:
    def __init__(self, l, s, m):
        self.messages = {}
        self.name = l
        self.start = s
        self.raw = m

    def parse_msgs(self):
        ### Part 1 - Split raw msgs and get codes
        split = re.findall(b'(?<!\xff)(\xfe+[^\xfe]*)', self.raw)
        raw_msgs = {}
        code = 0
        for msg in split:
            # Regex spits out a bunch of blank messages, so check for that
            if len(msg) > 0:
                pass
            else:
                continue
            # Get msg code by either getting the code in the case of
            # non-sequential codes, or get the gap count in the case
            # of sequential codes
            if msg[0:2] == b'\xfe\xfb':
                code = int.from_bytes(msg[2:4], 'big')
                data = msg[4::]
            elif msg[0:4].count(b'\xfe') > 0:
                code += msg[0:4].count(b'\xfe')
                data = msg[msg[0:4].count(b'\xfe')::]
            else:
                # Fail-safe that should never be seen
                print('You should not be seeing this! Codes are broken :((')
                # TODO: Replace this exit() with proper error handling
                exit()
            msg_code = hex(int(code))[2::].upper()
            raw_msgs[msg_code] = data

        ### Part 2 - Split raw msgs by psign
        for code in raw_msgs:
            # Key = psign index
            msgs_by_psign = {}
            raw_frames = re.findall(b'(?<!\xff)([^\xfc\xfe]*)', raw_msgs[code])
            for frame in raw_frames:
                if len(frame) > 0:
                    cur_psign = 0
                    trim = 0
                    # 0xED indicates that multiple psigns are using the following data.
                    # Most common for ODK pairing up with other psigns.
                    if frame[0:1] == b'\xed':
                        cur_psign = []
                        n = int.from_bytes(frame[1:2], 'big')
                        temp = [frame[2:(n*3)][i:i+2] for i in range(0, len(frame[2:(n*3)]), 2)]
                        for p in temp:
                            if p[0:1] == b'\x00':
                                cur_psign.append(b'\x00')
                            else:
                                cur_psign.append(p[1:2])
                        trim = n*3
                    # As far as I can tell, this checks out
                    elif frame[0:1] == b'\x00':
                        cur_psign = [b'\x00']
                        trim = 2
                    else:
                        cur_psign = [frame[1:2]]
                        trim = 2
                    # Check for signs that share data (ie. their indices are merged)
                    for psign_id in cur_psign:
                        if psign_id not in psigns.keys():
                            bits = ''.join(f'{byte:08b}' for byte in psign_id)[::-1]
                            temp = []
                            for i in range(len(bits)):
                                if bits[i] == '1':
                                    temp.append(chr(2**i).encode())
                            cur_psign = temp
                    for p in cur_psign:
                        if p not in msgs_by_psign.keys():
                            msgs_by_psign[p] = [split_frame(frame[trim::])]
                        else:
                            msgs_by_psign[p].append(split_frame(frame[trim::]))

            ### Part 3 - Make Elements, final data structure:
            # self.messages = {
            #              msg_code:{
            #                  ps:[
            #                    frame = [
            #                        elements
            #               ]
            #           ]
            #       }
            #   }
            msg = {}
            for ps in msgs_by_psign:
                if ps not in msg:
                    msg[ps] = []
                frame_list = []
                for raw_frame in msgs_by_psign[ps]:
                    frame = []
                    for raw_ele in raw_frame:
                        e = Element(raw_ele, ps)
                        if e.is_txt:
                            e.add_data(font_table[e.ind])
                        else:
                            e.add_data(graphic_table[e.ind])
                        frame.append(e)
                    frame_list.append(frame)
                msg[ps] = frame_list
            self.messages[code] = msg


with open(f, 'rb') as mtu_stream:
    mtu = mtu_stream.read()
    # Loading file/housekeeping
    print('Attempting to read MTU file "'+f+'"')
    file_size = len(mtu)
    print('File is', file_size, 'bytes')
    print('')
    # MTUs start with the address at which the non-LOD data starts
    # All addresses have 0x030000 added to them for some reason
    start_data = int.from_bytes(mtu[0:4], 'big') - 196608
    # Unknown table 1
    partnum_start = int.from_bytes(mtu[start_data:start_data+4], 'big') - 196608
    # MWMASTER table, formerly unknown table 2
    mwmaster_start = int.from_bytes(mtu[start_data+4:start_data+8], 'big') - 196608
    # Fonts, graphics, psigns, class A, class B, class C
    ftable_start = int.from_bytes(mtu[start_data+8:start_data+12], 'big') - 196608
    gtable_start = int.from_bytes(mtu[start_data+12:start_data+16], 'big') - 196608
    pstable_start = int.from_bytes(mtu[start_data+16:start_data+20], 'big') - 196608

    ### "PSign part numbers"
    # Not 100% sure if this is what this actually is, but basically this "table"
    # appears to be just a list of part numbers used by that particular MTU.
    parts_table = get_raw_table(mtu, partnum_start, 2, mwmaster_start)
    present_parts = []
    for key in parts_table:
        if key in parts_info:
            present_parts.append(parts_info[key])
    # Set psigns
    for p in range(len(present_parts)):
        part_name = present_parts[p][0].lstrip() + ' (' + present_parts[p][1] + ')'
        psigns[bit_list[p]] = part_name
        psign_ind[part_name] = p

    ### "Font Table"
    # Get the end of the table by jumping to the first address in the table
    # AKA the address of the first font
    font_table_raw = get_raw_table(mtu, ftable_start, 8, 0)
    font_table = []
    for header in font_table_raw:
        font_table.append(Font(header))
    for i in range(len(font_table)):
        if i < len(font_table)-1:
            font_table[i].data_len = font_table[i+1].addr - font_table[i].addr
        else:
            font_table[i].data_len = font_table[i].addr - ftable_start
    for font_entry in font_table:
        font_entry.make_glyphs(mtu)
    ### Font table end


    ### "Graphic Table"
    graphic_table_raw = get_raw_table(mtu, gtable_start, 8, 0)
    graphic_table = []
    # The index of the data in graphics_table is how it will later be identified
    for header in graphic_table_raw:
        graphic_table.append(Graphic(header))
    # Now get the data which includes its length
    for g in graphic_table:
        g.make_graphic(mtu)
    ### Graphics table end

    ### "PSign Table"
    # Unlike fonts and graphics, the psign table is terminated with 0xFFFF,
    # hence why get_raw_table still takes 4 arguments lol
    psign_table_end = mtu.find(b'\xff\xff', pstable_start, file_size)
    psign_table_raw = get_raw_table(mtu, pstable_start, 16, psign_table_end)
    psign_table = []
    for entry in psign_table_raw:
        psign_table.append(Physical_Sign(entry))

    # Init message classes
    msg_classes = {}
    c = ' '*20
    c += 'A   B   C   D   E   F   G   H   I   J   K'
    # If a class is empty, it is not initiated with 0xFEFD; it instead just
    # consists of 0xFDFF, therefore we need to keep track of if, well,
    next_is_empty = False
    for i in range(20, 64, 4):
        start = int.from_bytes(mtu[start_data+i:start_data+i+4], 'big') - 196608
        if next_is_empty:
            raw_msgs = b''
            end += 2
        else:
            end = mtu.find(b'\xfe\xfd', start, file_size)
            raw_msgs = mtu[start:end]

        if mtu[end+2:end+4] == b'\xfd\xff':
            next_is_empty = True
        else:
            next_is_empty = False
        msg_classes[c[i]] = Message_Class(c[i], start, raw_msgs)
        if len(msg_classes[c[i]].raw) > 0:
            msg_classes[c[i]].parse_msgs()

### Output
print('Got start of non-LOD data', start_data, 'bytes into the file')
print('')
print('Got data table addresses:')
print('       Part numbers:', hex(partnum_start)) # Called "physical_config" by Zhong-ba
print('       MWMASTER.PRF:', hex(mwmaster_start)) # Called "configuration_records" by Zhong-ba
print('         Font table:', hex(ftable_start))
print('     Graphics table:', hex(gtable_start))
print('     Physical signs:', hex(pstable_start)) # Called "listing_config" by Zhong-ba
for m in msg_classes:
    print('   Class', m, 'messages:', hex(msg_classes[m].start))
# Total: 16 tables
print('')
print('Got the following parts:')
for part in present_parts:
    print('  ', part[0], '  ('+part[1]+')')
print('')
print(200*'=')
print('')
for c in msg_classes:
    print('Class:', c)
    print(30*'-')
    for code in msg_classes[c].messages:
        print(' Code:', code)
        for ps in msg_classes[c].messages[code]:
            print('  Psign:', psigns[ps])
            for frame in range(len(msg_classes[c].messages[code][ps])):
                print('   Frame:', frame)
                for ele in msg_classes[c].messages[code][ps][frame]:
                    if ele.frame_time != 0:
                        print(f'      Frame time: {ele.frame_time} seconds')
                    if ele.is_txt:
                        print(f'     "{ele.text}" using font #{ele.ind} @ pos ({ele.pos_x}, {ele.pos_y})')
                    else:
                        print('     ', ele.text)
                    if preview_graphics:
                        ele.print_ele(4)
                #print('')
            print('')
        print(100*'- ')
        print('')
    print('')
    print(200*'=')
    print('')
