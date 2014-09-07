#!/usr/bin/python

# This is a quick and dirty port of lnk-parse-1.0.pl found here:
#   https://code.google.com/p/revealertoolkit/source/browse/trunk/tools/lnk-parse-1.0.pl
#   Windows LNK file parser - Jacob Cunningham - jakec76@users.sourceforge.net
#   Based on the contents of the document:
#   http://www.i2s-lab.com/Papers/The_Windows_Shortcut_File_Format.pdf
#   v1.0
#

import sys, struct, datetime, binascii


# HASH of flag attributes
flag_hash = [["",""] for _ in xrange(7)]
flag_hash[0][1] = "HAS SHELLIDLIST"
flag_hash[0][0] = "NO SHELLIDLIST"
flag_hash[1][1] = "POINTS TO FILE/DIR"
flag_hash[1][0] = "NOT POINT TO FILE/DIR"
flag_hash[2][1] = "HAS DESCRIPTION"
flag_hash[2][0] = "NO DESCRIPTION"
flag_hash[3][1] = "HAS RELATIVE PATH STRING"
flag_hash[3][0] = "NO RELATIVE PATH STRING"
flag_hash[4][1] = "HAS WORKING DIRECTORY"
flag_hash[4][0] = "NO WORKING DIRECTORY"
flag_hash[5][1] = "HAS CMD LINE ARGS"
flag_hash[5][0] = "NO CMD LINE ARGS"
flag_hash[6][1] = "HAS CUSTOM ICON"
flag_hash[6][0] = "NO CUSTOM ICON"

# HASH of FileAttributes
file_hash = [["",""] for _ in xrange(13)]
file_hash[0][1] = "READ ONLY TARGET"
file_hash[1][1] = "HIDDEN TARGET"
file_hash[2][1] = "SYSTEM FILE TARGET"
file_hash[3][1] = "VOLUME LABEL TARGET (not possible)"
file_hash[4][1] = "DIRECTORY TARGET"
file_hash[5][1] = "ARCHIVE"
file_hash[6][1] = "NTFS EFS"
file_hash[7][1] = "NORMAL TARGET"
file_hash[8][1] = "TEMP. TARGET"
file_hash[9][1] = "SPARSE TARGET"
file_hash[10][1] = "REPARSE POINT DATA TARGET"
file_hash[11][1] = "COMPRESSED TARGET"
file_hash[12][1] = "TARGET OFFLINE"

#Hash of ShowWnd values
show_wnd_hash = [[""] for _ in xrange(11)]
show_wnd_hash[0] = "SW_HIDE"
show_wnd_hash[1] = "SW_NORMAL"
show_wnd_hash[2] = "SW_SHOWMINIMIZED"
show_wnd_hash[3] = "SW_SHOWMAXIMIZED"
show_wnd_hash[4] = "SW_SHOWNOACTIVE"
show_wnd_hash[5] = "SW_SHOW"
show_wnd_hash[6] = "SW_MINIMIZE"
show_wnd_hash[7] = "SW_SHOWMINNOACTIVE"
show_wnd_hash[8] = "SW_SHOWNA"
show_wnd_hash[9] = "SW_RESTORE"
show_wnd_hash[10] = "SW_SHOWDEFAULT"

# Hash for Volume types
vol_type_hash = [[""] for _ in xrange(7)]
vol_type_hash[0] = "Unknown"
vol_type_hash[1] = "No root directory"
vol_type_hash[2] = "Removable (Floppy,Zip,USB,etc.)"
vol_type_hash[3] = "Fixed (Hard Disk)"
vol_type_hash[4] = "Remote (Network Drive)"
vol_type_hash[5] = "CD-ROM"
vol_type_hash[6] = "RAM Drive"


def reverse_hex(HEXDATE):
    hexVals = [HEXDATE[i:i + 2] for i in xrange(0, 16, 2)]
    reversedHexVals = hexVals[::-1]
    return ''.join(reversedHexVals)


def assert_lnk_signature(f):
    f.seek(0)
    sig = f.read(4)
    guid = f.read(16)
    if sig != 'L\x00\x00\x00':
        raise Exception("This is not a .lnk file.")
    if guid != '\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F':
        raise Exception("Cannot read this kind of .lnk file.")


# read COUNT bytes at LOC and unpack into binary
def read_unpack_bin(f, loc, count):
    
    # jump to the specified location
    f.seek(loc)

    raw = f.read(count)
    result = ""

    for b in raw:
        result += ("{0:08b}".format(ord(b)))[::-1]

    return result


# read COUNT bytes at LOC and unpack into ascii
def read_unpack_ascii(f,loc,count):

    # jump to the specified location
    f.seek(loc)

    # should interpret as ascii automagically
    return f.read(count)


# read COUNT bytes at LOC
def read_unpack(f, loc, count):
    
    # jump to the specified location
    f.seek(loc)

    raw = f.read(count)
    result = ""

    for b in raw:
        result += binascii.hexlify(b)

    return result


# Read a null terminated string from the specified location.
def read_null_term(f, loc):
    
    # jump to the start position
    f.seek(loc)

    result = ""
    b = f.read(1)

    while b != "\x00":
        result += str(b)
        b = f.read(1)

    return result


# adapted from pylink.py
def ms_time_to_unix(windows_time):
    unix_time = windows_time / 10000000.0 - 11644473600
    return datetime.datetime.fromtimestamp(unix_time)


def add_info(f,loc):

    tmp_len_hex = reverse_hex(read_unpack(f,loc,1))
    tmp_len = 2 * int(tmp_len_hex, 16)

    loc += 1

    if (tmp_len != 0):
        tmp_string = read_unpack_ascii(f, loc, tmp_len)
        now_loc = f.tell()
        return (tmp_string, now_loc)
    else:
        now_loc = f.tell()
        return (None, now_loc)


def parse_lnk(filename):

    # read the file in binary module
    f = open(filename, 'rb')

    try:
        assert_lnk_signature(f)
    except Exception as e:
        return "[!] Exception: "+str(e)

    output = "Lnk File: " + filename + "\n"

    # get the flag bits
    flags = read_unpack_bin(f,20,1)
    flag_desc = list()

    # flags are only the first 7 bits
    for cnt in xrange(len(flags)-1):
        bit = int(flags[cnt])
        # grab the description for this bit
        flag_desc.append(flag_hash[cnt][bit])

    output += "Link Flags: " + " | ".join(flag_desc) + "\n"

    # File Attributes 4bytes@18h = 24d
    # Only a non-zero if "Flag bit 1" above is set to 1
    if flags[1]=="1":
        file_attrib = read_unpack_bin(f,24,2)
        output += "File Attributes: "+file_hash[file_attrib.index("1")][1] + "\n"

    # Create time 8bytes @ 1ch = 28
    create_time = reverse_hex(read_unpack(f,28,8))
    output += "Create Time:   "+str(ms_time_to_unix(int(create_time, 16))) + "\n"

    # Access time 8 bytes@ 0x24 = 36D
    access_time = reverse_hex(read_unpack(f,36,8))
    output += "Access Time:   "+str(ms_time_to_unix(int(access_time, 16))) + "\n"

    # Modified Time8b @ 0x2C = 44D
    modified_time = reverse_hex(read_unpack(f,44,8))
    output += "Modified Time: "+str(ms_time_to_unix(int(modified_time, 16))) + "\n"

    # Target File length starts @ 34h = 52d
    length_hex = reverse_hex(read_unpack(f,52,4))
    length = int(length_hex, 16)
    output += "Target length: "+str(length) + "\n"

    # Icon File info starts @ 38h = 56d
    icon_index_hex = reverse_hex(read_unpack(f,56,4))
    icon_index = int(icon_index_hex, 16)
    output += "Icon Index: "+str(icon_index) + "\n"

    # show windows starts @3Ch = 60d 
    show_wnd_hex = reverse_hex(read_unpack(f,60,1))
    show_wnd = int(show_wnd_hex, 16)
    output += "ShowWnd: "+str(show_wnd_hash[show_wnd]) + "\n"

    # hot key starts @40h = 64d 
    hotkey_hex = reverse_hex(read_unpack(f,64,4))
    hotkey = int(hotkey_hex, 16)
    output += "HotKey: "+str(hotkey) + "\n"

    #------------------------------------------------------------------------
    # End of Flag parsing
    #------------------------------------------------------------------------

    # get the number of items
    items_hex = reverse_hex(read_unpack(f,76,2))
    items = int(items_hex, 16)

    list_end = 78 + items

    struct_start = list_end
    first_off_off = struct_start + 4
    vol_flags_off = struct_start + 8
    local_vol_off = struct_start + 12
    base_path_off = struct_start + 16
    net_vol_off = struct_start + 20
    rem_path_off = struct_start + 24

    # Structure length
    struct_len_hex = reverse_hex(read_unpack(f,struct_start,4))
    struct_len = int(struct_len_hex, 16)
    struct_end = struct_start + struct_len

    # First offset after struct - Should be 1C under normal circumstances
    first_off = read_unpack(f,first_off_off,1)

    # File location flags
    vol_flags = read_unpack_bin(f,vol_flags_off,1)

    # Local volume table
    # Random garbage if bit0 is clear in volume flags
    if vol_flags[:2] == "10":
        
        output += "Target is on local volume\n"

        # This is the offset of the local volume table within the 
        # File Info Location Structure
        loc_vol_tab_off_hex = reverse_hex(read_unpack(f,local_vol_off,4))
        loc_vol_tab_off = int(loc_vol_tab_off_hex, 16)

        # This is the asolute start location of the local volume table
        loc_vol_tab_start = loc_vol_tab_off + struct_start

        # This is the length of the local volume table
        local_vol_len_hex = reverse_hex(read_unpack(f,loc_vol_tab_off+struct_start,4))
        local_vol_len = int(local_vol_len_hex, 16)

        # We now have enough info to
        # Calculate the end of the local volume table.
        local_vol_tab_end = loc_vol_tab_start + local_vol_len

        # This is the volume type
        curr_tab_offset = loc_vol_tab_off + struct_start + 4
        vol_type_hex = reverse_hex(read_unpack(f,curr_tab_offset,4))
        vol_type = int(vol_type_hex, 16)
        output += "Volume Type: "+str(vol_type_hash[vol_type]) + "\n"

        # Volume Serial Number
        curr_tab_offset = loc_vol_tab_off + struct_start + 8
        vol_serial = reverse_hex(read_unpack(f,curr_tab_offset,4))
        output += "Volume Serial: "+str(vol_serial) + "\n"

        # Get the location, and length of the volume label 
        vol_label_loc = loc_vol_tab_off + struct_start + 16
        vol_label_len = local_vol_tab_end - vol_label_loc
        vol_label = read_unpack_ascii(f,vol_label_loc,vol_label_len);
        output += "Vol Label: "+str(vol_label) + "\n"

        #------------------------------------------------------------------------
        # This is the offset of the base path info within the
        # File Info structure
        #------------------------------------------------------------------------

        base_path_off_hex = reverse_hex(read_unpack(f,base_path_off,4))
        base_path_off = struct_start + int(base_path_off_hex, 16)

        # Read base path data upto NULL term 
        base_path = read_null_term(f,base_path_off)
        output += "Base Path: "+str(base_path) + "\n"

    # Network Volume Table
    elif vol_flags[:2] == "01":

        # TODO: test this section!
        output += "Target is on Network share\n"

        net_vol_off_hex = reverse_hex(read_unpack(f,net_vol_off,4))
        net_vol_off = struct_start + int(net_vol_off_hex, 16)
        net_vol_len_hex = reverse_hex(read_unpack(f,net_vol_off,4))
        net_vol_len = struct_start + int(net_vol_len_hex, 16)

        # Network Share Name
        net_share_name_off = net_vol_off + 8
        net_share_name_loc_hex = reverse_hex(read_unpack(f,net_share_name_off,4))
        net_share_name_loc = int(net_share_name_loc_hex, 16)

        if(net_share_name_loc != 20):
            output += " [!] Error: NSN ofset should always be 14h\n"
            sys.exit(1)

        net_share_name_loc = net_vol_off + net_share_name_loc
        net_share_name = read_null_term(f,net_share_name_loc)
        output += "Network Share Name: "+str(net_share_name) + "\n"

        # Mapped Network Drive Info
        net_share_mdrive = net_vol_off + 12
        net_share_mdrive_hex = reverse_hex(read_unpack(f,net_share_mdrive,4))
        net_share_mdrive = int(net_share_mdrive_hex, 16)

        if(net_share_mdrive != 0):
            net_share_mdrive = net_vol_off + net_share_mdrive
            net_share_mdrive = read_null_term(f,net_share_mdrive)
            output += "Mapped Drive: "+str(net_share_mdrive) + "\n"

    else:
        output += " [!] Error: unknown volume flags\n"
        sys.exit(1)


    # Remaining path
    rem_path_off_hex = reverse_hex(read_unpack(f,rem_path_off,4))
    rem_path_off = struct_start +int(rem_path_off_hex, 16)
    rem_data = read_null_term(f,rem_path_off);
    output += "(App Path:) Remaining Path: "+str(rem_data) + "\n"

    #------------------------------------------------------------------------
    # End of FileInfo Structure
    #------------------------------------------------------------------------

    # The next starting location is the end of the structure
    next_loc = struct_end
    addnl_text = ""

    if flags[2]=="1":
         addnl_text,next_loc = add_info(f,next_loc)
         output += "Description: "+str(addnl_text) + "\n"
         next_loc = next_loc + 1
            
    if flags[3]=="1":
         addnl_text,next_loc = add_info(f,next_loc)
         output += "Relative Path: "+str(addnl_text) + "\n"
         next_loc = next_loc + 1

    if flags[4]=="1":
         addnl_text,next_loc = add_info(f,next_loc)
         output += "Working Dir: "+str(addnl_text) + "\n"
         next_loc = next_loc + 1

    if flags[5]=="1":
         addnl_text,next_loc = add_info(f,next_loc)
         output += "Command Line: "+str(addnl_text) + "\n"
         next_loc = next_loc + 1
            
    if flags[6]=="1":
         addnl_text,next_loc = add_info(f,next_loc)
         output += "Icon filename: "+str(addnl_text) + "\n"
    
    return output


def usage():
    print "Usage: ./pylnker.py .LNK_FILE"
    sys.exit(1)


if __name__ == "__main__":
    
    if len(sys.argv) != 2:
        usage()
    
    # parse .lnk file
    out = parse_lnk(sys.argv[2])
    print "out: ",out
