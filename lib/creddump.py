
"""
The following lines are a single-file combination of
the awesome creddump tool from https://code.google.com/p/creddump/

Only minor changes made.

"""




###############################################
#
# hashdump.py
#
###############################################


"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

# from framework.win32.rawreg import *
# from framework.addrspace import HiveFileAddressSpace
from Crypto.Hash import MD5
from Crypto.Cipher import ARC4,DES
from struct import unpack,pack

odd_parity = [
  1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
  16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
  32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
  49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
  64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
  81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
  97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
  112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
  128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
  145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
  161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
  176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
  193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
  208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
  224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
  241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
]

# Permutation matrix for boot key
p = [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
      0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]

# Constants for SAM decrypt algorithm
aqwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
anum = "0123456789012345678901234567890123456789\0"
antpassword = "NTPASSWORD\0"
almpassword = "LMPASSWORD\0"

empty_lm = "aad3b435b51404eeaad3b435b51404ee".decode('hex')
empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0".decode('hex')

def str_to_key(s):
    key = []
    key.append( ord(s[0])>>1 )
    key.append( ((ord(s[0])&0x01)<<6) | (ord(s[1])>>2) )
    key.append( ((ord(s[1])&0x03)<<5) | (ord(s[2])>>3) )
    key.append( ((ord(s[2])&0x07)<<4) | (ord(s[3])>>4) )
    key.append( ((ord(s[3])&0x0F)<<3) | (ord(s[4])>>5) )
    key.append( ((ord(s[4])&0x1F)<<2) | (ord(s[5])>>6) )
    key.append( ((ord(s[5])&0x3F)<<1) | (ord(s[6])>>7) )
    key.append( ord(s[6])&0x7F )
    for i in range(8):
        key[i] = (key[i]<<1)
        key[i] = odd_parity[key[i]]
    return "".join(chr(k) for k in key)

def sid_to_key(sid):
    s1 = ""
    s1 += chr(sid & 0xFF)
    s1 += chr((sid>>8) & 0xFF)
    s1 += chr((sid>>16) & 0xFF)
    s1 += chr((sid>>24) & 0xFF)
    s1 += s1[0];
    s1 += s1[1];
    s1 += s1[2];
    s2 = s1[3] + s1[0] + s1[1] + s1[2]
    s2 += s2[0] + s2[1] + s2[2]

    return str_to_key(s1),str_to_key(s2)
    
def find_control_set(sysaddr):
    root = get_root(sysaddr)
    if not root:
        return 1

    csselect = open_key(root, ["Select"])
    if not csselect:
        return 1

    for v in values(csselect):
        if v.Name == "Current": return v.Data.value

def get_bootkey(sysaddr):
    cs = find_control_set(sysaddr)
    lsa_base = ["ControlSet%03d" % cs, "Control", "Lsa"]
    lsa_keys = ["JD","Skew1","GBG","Data"]

    root = get_root(sysaddr)
    if not root: return None

    lsa = open_key(root, lsa_base)
    if not lsa: return None

    bootkey = ""
    
    for lk in lsa_keys:
        key = open_key(lsa, [lk])
        class_data = sysaddr.read(key.Class.value, key.ClassLength.value)
        bootkey += class_data.decode('utf-16-le').decode('hex')
    
    bootkey_scrambled = ""
    for i in range(len(bootkey)):
        bootkey_scrambled += bootkey[p[i]]
    
    return bootkey_scrambled

def get_hbootkey(samaddr, bootkey):
    sam_account_path = ["SAM", "Domains", "Account"]

    root = get_root(samaddr)
    if not root: return None

    sam_account_key = open_key(root, sam_account_path)
    if not sam_account_key: return None

    F = None
    for v in values(sam_account_key):
        if v.Name == 'F':
            F = samaddr.read(v.Data.value, v.DataLength.value)
    if not F: return None

    md5 = MD5.new()
    md5.update(F[0x70:0x80] + aqwerty + bootkey + anum)
    rc4_key = md5.digest()

    rc4 = ARC4.new(rc4_key)
    hbootkey = rc4.encrypt(F[0x80:0xA0])
    
    return hbootkey

def get_user_keys(samaddr):
    user_key_path = ["SAM", "Domains", "Account", "Users"]

    root = get_root(samaddr)
    if not root: return []

    user_key = open_key(root, user_key_path)
    if not user_key: return []

    return [k for k in subkeys(user_key) if k.Name != "Names"]

def decrypt_single_hash(rid, hbootkey, enc_hash, lmntstr):
    (des_k1,des_k2) = sid_to_key(rid)
    d1 = DES.new(des_k1, DES.MODE_ECB)
    d2 = DES.new(des_k2, DES.MODE_ECB)

    md5 = MD5.new()
    md5.update(hbootkey[:0x10] + pack("<L",rid) + lmntstr)
    rc4_key = md5.digest()
    rc4 = ARC4.new(rc4_key)
    obfkey = rc4.encrypt(enc_hash)
    hash = d1.decrypt(obfkey[:8]) + d2.decrypt(obfkey[8:])

    return hash

def decrypt_hashes(rid, enc_lm_hash, enc_nt_hash, hbootkey):
    # LM Hash
    if enc_lm_hash:
        lmhash = decrypt_single_hash(rid, hbootkey, enc_lm_hash, almpassword)
    else:
        lmhash = ""
    
    # NT Hash
    if enc_nt_hash:
        nthash = decrypt_single_hash(rid, hbootkey, enc_nt_hash, antpassword)
    else:
        nthash = ""

    return lmhash,nthash

def get_user_hashes(user_key, hbootkey):
    samaddr = user_key.space
    rid = int(user_key.Name, 16)
    V = None
    for v in values(user_key):
        if v.Name == 'V':
            V = samaddr.read(v.Data.value, v.DataLength.value)
    if not V: return None

    hash_offset = unpack("<L", V[0x9c:0x9c+4])[0] + 0xCC

    lm_exists = True if unpack("<L", V[0x9c+4:0x9c+8])[0] == 20 else False
    nt_exists = True if unpack("<L", V[0x9c+16:0x9c+20])[0] == 20 else False

    enc_lm_hash = V[hash_offset+4:hash_offset+20] if lm_exists else ""
    enc_nt_hash = V[hash_offset+(24 if lm_exists else 8):hash_offset+(24 if lm_exists else 8)+16] if nt_exists else ""

    return decrypt_hashes(rid, enc_lm_hash, enc_nt_hash, hbootkey)

def get_user_name(user_key):
    samaddr = user_key.space
    V = None
    for v in values(user_key):
        if v.Name == 'V':
            V = samaddr.read(v.Data.value, v.DataLength.value)
    if not V: return None

    name_offset = unpack("<L", V[0x0c:0x10])[0] + 0xCC
    name_length = unpack("<L", V[0x10:0x14])[0]

    username = V[name_offset:name_offset+name_length].decode('utf-16-le')
    return username

def dump_hashes(sysaddr, samaddr):
    bootkey = get_bootkey(sysaddr)
    hbootkey = get_hbootkey(samaddr,bootkey)

    results = ""

    for user in get_user_keys(samaddr):
        lmhash,nthash = get_user_hashes(user,hbootkey)
        if not lmhash: lmhash = empty_lm
        if not nthash: nthash = empty_nt
        results += "%s:%d:%s:%s:::\n" % (get_user_name(user), int(user.Name,16),
                            lmhash.encode('hex'), nthash.encode('hex'))
    return results

def dump_file_hashes(syshive_fname, samhive_fname):
    sysaddr = HiveFileAddressSpace(syshive_fname)
    samaddr = HiveFileAddressSpace(samhive_fname)
    return dump_hashes(sysaddr, samaddr)



###############################################
#
# lassecrets.py
#
###############################################


"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

# from framework.win32.rawreg import *
# from framework.addrspace import HiveFileAddressSpace
# from framework.win32.hashdump import get_bootkey,str_to_key
from Crypto.Hash import MD5
from Crypto.Cipher import ARC4,DES

def get_lsa_key(secaddr, bootkey):
    root = get_root(secaddr)
    if not root:
        return None

    enc_reg_key = open_key(root, ["Policy", "PolSecretEncryptionKey"])
    if not enc_reg_key:
        return None

    enc_reg_value = enc_reg_key.ValueList.List[0]
    if not enc_reg_value:
        return None

    obf_lsa_key = secaddr.read(enc_reg_value.Data.value,
            enc_reg_value.DataLength.value)
    if not obf_lsa_key:
        return None

    md5 = MD5.new()
    md5.update(bootkey)
    for i in range(1000):
        md5.update(obf_lsa_key[60:76])
    rc4key = md5.digest()

    rc4 = ARC4.new(rc4key)
    lsa_key = rc4.decrypt(obf_lsa_key[12:60])

    return lsa_key[0x10:0x20]

def decrypt_secret(secret, key):
    """Python implementation of SystemFunction005.

    Decrypts a block of data with DES using given key.
    Note that key can be longer than 7 bytes."""
    decrypted_data = ''
    j = 0   # key index
    for i in range(0,len(secret),8):
        enc_block = secret[i:i+8]
        block_key = key[j:j+7]
        des_key = str_to_key(block_key)

        des = DES.new(des_key, DES.MODE_ECB)
        decrypted_data += des.decrypt(enc_block)
        
        j += 7
        if len(key[j:j+7]) < 7:
            j = len(key[j:j+7])

    (dec_data_len,) = unpack("<L", decrypted_data[:4])
    return decrypted_data[8:8+dec_data_len]

def get_secret_by_name(secaddr, name, lsakey):
    root = get_root(secaddr)
    if not root:
        return None
    
    enc_secret_key = open_key(root, ["Policy", "Secrets", name, "CurrVal"])
    if not enc_secret_key:
        return None

    enc_secret_value = enc_secret_key.ValueList.List[0]
    if not enc_secret_value:
        return None

    enc_secret = secaddr.read(enc_secret_value.Data.value,
            enc_secret_value.DataLength.value)
    if not enc_secret:
        return None

    return decrypt_secret(enc_secret[0xC:], lsakey)

def get_secrets(sysaddr, secaddr):
    root = get_root(secaddr)
    if not root:
        return None

    bootkey = get_bootkey(sysaddr)
    lsakey = get_lsa_key(secaddr, bootkey)

    secrets_key = open_key(root, ["Policy", "Secrets"])
    if not secrets_key:
        return None
    
    secrets = {}
    for key in subkeys(secrets_key):
        sec_val_key = open_key(key, ["CurrVal"])
        if not sec_val_key:
            continue
        
        enc_secret_value = sec_val_key.ValueList.List[0]
        if not enc_secret_value:
            continue
        
        enc_secret = secaddr.read(enc_secret_value.Data.value,
                enc_secret_value.DataLength.value)
        if not enc_secret:
            continue

        secret = decrypt_secret(enc_secret[0xC:], lsakey)
        secrets[key.Name] = secret

    return secrets

def get_file_secrets(sysfile, secfile):
    sysaddr = HiveFileAddressSpace(sysfile)
    secaddr = HiveFileAddressSpace(secfile)

    return get_secrets(sysaddr, secaddr)







###############################################
#
# Framework helper methods are all below...
#
###############################################




###############################################
#
# addrspace.py
#
###############################################

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

""" Alias for all address spaces """

import os
import struct

class FileAddressSpace:

    def __init__(self, fname, mode='rb', fast=False):
        self.fname = fname
        self.name = fname
        self.fhandle = open(fname, mode)
        self.fsize = os.path.getsize(fname)

        if fast == True:
            self.fast_fhandle = open(fname, mode)

    def fread(self,len):
        return self.fast_fhandle.read(len)

    def read(self, addr, len):
        self.fhandle.seek(addr)        
        return self.fhandle.read(len)    

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def get_address_range(self):
        return [0,self.fsize-1]

    def get_available_addresses(self):
        return [self.get_address_range()]

    def is_valid_address(self, addr):
        return addr < self.fsize - 1

    def close():
        self.fhandle.close()

# Code below written by Brendan Dolan-Gavitt

BLOCK_SIZE = 0x1000

class HiveFileAddressSpace:
    def __init__(self, fname):
        self.fname = fname
        self.base = FileAddressSpace(fname)

    def vtop(self, vaddr):
        return vaddr + BLOCK_SIZE + 4

    def read(self, vaddr, length, zero=False):
        first_block = BLOCK_SIZE - vaddr % BLOCK_SIZE
        full_blocks = ((length + (vaddr % BLOCK_SIZE)) / BLOCK_SIZE) - 1
        left_over = (length + vaddr) % BLOCK_SIZE
        
        paddr = self.vtop(vaddr)
        if paddr == None and zero:
            if length < first_block:
                return "\0" * length
            else:
                stuff_read = "\0" * first_block
        elif paddr == None:
            return None
        else:
            if length < first_block:
                stuff_read = self.base.read(paddr, length)
                if not stuff_read and zero:
                    return "\0" * length
                else:
                    return stuff_read

            stuff_read = self.base.read(paddr, first_block)
            if not stuff_read and zero:
                stuff_read = "\0" * first_block

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * BLOCK_SIZE
            elif paddr == None:
                return None
            else:
                new_stuff = self.base.read(paddr, BLOCK_SIZE)
                if not new_stuff and zero:
                    new_stuff = "\0" * BLOCK_SIZE
                elif not new_stuff:
                    return None
                else:
                    stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + BLOCK_SIZE

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * left_over
            elif paddr == None:
                return None
            else:
                stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def is_valid_address(self, vaddr):
        paddr = self.vtop(vaddr)
        if not paddr: return False
        return self.base.is_valid_address(paddr)


###############################################
#
# newobj.py
#
###############################################

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

# from framework.object import *
# from framework.types import regtypes as types
from operator import itemgetter
from struct import unpack

def get_ptr_type(structure, member):
    """Return the type a pointer points to.
       
       Arguments:
         structure : the name of the structure from vtypes
         member : a list of members

       Example:
         get_ptr_type('_EPROCESS', ['ActiveProcessLinks', 'Flink']) => ['_LIST_ENTRY']
    """
    if len(member) > 1:
        _, tp = get_obj_offset(types, [structure, member[0]])
        if tp == 'array':
            return types[structure][1][member[0]][1][2][1]
        else:
            return get_ptr_type(tp, member[1:])
    else:
        return types[structure][1][member[0]][1][1]

class Obj(object):
    """Base class for all objects.
       
       May return a subclass for certain data types to allow
       for special handling.
    """

    def __new__(typ, name, address, space):
        if name in globals():
            # This is a bit of "magic"
            # Could be replaced with a dict mapping type names to types
            return globals()[name](name,address,space)
        elif name in builtin_types:
            return Primitive(name, address, space)
        else:
            obj = object.__new__(typ)
            return obj
    
    def __init__(self, name, address, space):
        self.name = name
        self.address = address
        self.space = space

        # Subclasses can add fields to this list if they want them
        # to show up in values() or members(), even if they do not
        # appear in the vtype definition
        self.extra_members = []
    
    def __getattribute__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            pass

        if self.name in builtin_types:
            raise AttributeError("Primitive types have no dynamic attributes")

        try:
            off, tp = get_obj_offset(types, [self.name, attr])
        except:
            raise AttributeError("'%s' has no attribute '%s'" % (self.name, attr))
        
        if tp == 'array':
            a_len = types[self.name][1][attr][1][1]
            l = []
            for i in range(a_len):
                a_off, a_tp = get_obj_offset(types, [self.name, attr, i])
                if a_tp == 'pointer':
                    ptp = get_ptr_type(self.name, [attr, i])
                    l.append(Pointer(a_tp, self.address+a_off, self.space, ptp))
                else:
                    l.append(Obj(a_tp, self.address+a_off, self.space))
            return l
        elif tp == 'pointer':
            # Can't just return a Obj here, since pointers need to also
            # know what type they point to.
            ptp = get_ptr_type(self.name, [attr])
            return Pointer(tp, self.address+off, self.space, ptp)
        else:
            return Obj(tp, self.address+off, self.space)
    
    def __div__(self, other):
        if isinstance(other,tuple) or isinstance(other,list):
            return Pointer(other[0], self.address, self.space, other[1])
        elif isinstance(other,str):
            return Obj(other, self.address, self.space)
        else:
            raise ValueError("Must provide a type name as string for casting")
    
    def members(self):
        """Return a list of this object's members, sorted by offset."""

        # Could also just return the list
        membs = [ (k, v[0]) for k,v in types[self.name][1].items()]
        membs.sort(key=itemgetter(1))
        return map(itemgetter(0),membs) + self.extra_members

    def values(self):
        """Return a dictionary of this object's members and their values"""
        
        valdict = {}
        for k in self.members():
            valdict[k] = getattr(self, k)
        return valdict

    def bytes(self, length=-1):
        """Get bytes starting at the address of this object.
        
           Arguments:
             length : the number of bytes to read. Default: size of
                this object.
        """

        if length == -1:
            length = self.size()
        return self.space.read(self.address, length)

    def size(self):
        """Get the size of this object."""

        if self.name in builtin_types:
            return builtin_types[self.name][0]
        else:
            return types[self.name][0]
    
    def __repr__(self):
        return "<%s @%08x>" % (self.name, self.address)

    def __eq__(self, other):
        if not isinstance(other, Obj):
            raise TypeError("Types are incomparable")
        return self.address == other.address and self.name == other.name

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.address) ^ hash(self.name)

    def is_valid(self):
        return self.space.is_valid_address(self.address)

    def get_offset(self, member):
        return get_obj_offset(types, [self.name] + member)

class Primitive(Obj):
    """Class to represent a primitive data type.
       
       Attributes:
         value : the python primitive value of this type
    """

    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def __init__(self, name, address, space):
        super(Primitive,self).__init__(name, address, space)
        length, fmt = builtin_types[name]
        data = space.read(address,length)
        if not data: self.value = None
        else: self.value = unpack(fmt,data)[0]
    
    def __repr__(self):
        return repr(self.value)

    def members(self):
        return []

class Pointer(Obj):
    """Class to represent pointers.
    
       value : the object pointed to

       If an attribute is not found in this instance,
       the attribute will be looked up in the referenced
       object."""

    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def __init__(self, name, address, space, ptr_type):
        super(Pointer,self).__init__(name, address, space)
        ptr_address = read_value(space, name, address)
        if ptr_type[0] == 'pointer':
            self.value = Pointer(ptr_type[0], ptr_address, self.space, ptr_type[1])
        else:
            self.value = Obj(ptr_type[0], ptr_address, self.space)
    
    def __getattribute__(self, attr):
        # It's still nice to be able to access things through pointers
        # without having to explicitly dereference them, so if we don't
        # find an attribute via our superclass, just dereference the pointer
        # and return the attribute in the pointed-to type.
        try:
            return super(Pointer,self).__getattribute__(attr)
        except AttributeError:
            return getattr(self.value, attr)
    
    def __repr__(self):
        return "<pointer to [%s @%08x]>" % (self.value.name, self.value.address)

    def members(self):
        return self.value.members()

class _UNICODE_STRING(Obj):
    """Class representing a _UNICODE_STRING

    Adds the following behavior:
      * The Buffer attribute is presented as a Python string rather
        than a pointer to an unsigned short.
      * The __str__ method returns the value of the Buffer.
    """

    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def __str__(self):
        return self.Buffer

    # Custom Attributes
    def getBuffer(self):
        return read_unicode_string(self.space, types, [], self.address)
    Buffer = property(fget=getBuffer)

class _CM_KEY_NODE(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getName(self):
        return read_string(self.space, types, ['_CM_KEY_NODE', 'Name'],
            self.address, self.NameLength.value)
    Name = property(fget=getName)

class _CM_KEY_VALUE(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getName(self):
        return read_string(self.space, types, ['_CM_KEY_VALUE', 'Name'],
            self.address, self.NameLength.value)
    Name = property(fget=getName)

class _CHILD_LIST(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getList(self):
        lst = []
        list_address = read_obj(self.space, types,
            ['_CHILD_LIST', 'List'], self.address)
        for i in range(self.Count.value):
            lst.append(Pointer("pointer", list_address+(i*4), self.space,
                ["_CM_KEY_VALUE"]))
        return lst
    List = property(fget=getList)

class _CM_KEY_INDEX(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getList(self):
        lst = []
        for i in range(self.Count.value):
            # we are ignoring the hash value here
            off,tp = get_obj_offset(types, ['_CM_KEY_INDEX', 'List', i*2])
            lst.append(Pointer("pointer", self.address+off, self.space,
                ["_CM_KEY_NODE"]))
        return lst
    List = property(fget=getList)



###############################################
#
# types.py
#
###############################################


"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

types = {
  '_CM_KEY_VALUE' : [ 0x18, {
    'Signature' : [ 0x0, ['unsigned short']],
    'NameLength' : [ 0x2, ['unsigned short']],
    'DataLength' : [ 0x4, ['unsigned long']],
    'Data' : [ 0x8, ['unsigned long']],
    'Type' : [ 0xc, ['unsigned long']],
    'Flags' : [ 0x10, ['unsigned short']],
    'Spare' : [ 0x12, ['unsigned short']],
    'Name' : [ 0x14, ['array', 1, ['unsigned short']]],
} ],
  '_CM_KEY_NODE' : [ 0x50, {
    'Signature' : [ 0x0, ['unsigned short']],
    'Flags' : [ 0x2, ['unsigned short']],
    'LastWriteTime' : [ 0x4, ['_LARGE_INTEGER']],
    'Spare' : [ 0xc, ['unsigned long']],
    'Parent' : [ 0x10, ['unsigned long']],
    'SubKeyCounts' : [ 0x14, ['array', 2, ['unsigned long']]],
    'SubKeyLists' : [ 0x1c, ['array', 2, ['unsigned long']]],
    'ValueList' : [ 0x24, ['_CHILD_LIST']],
    'ChildHiveReference' : [ 0x1c, ['_CM_KEY_REFERENCE']],
    'Security' : [ 0x2c, ['unsigned long']],
    'Class' : [ 0x30, ['unsigned long']],
    'MaxNameLen' : [ 0x34, ['unsigned long']],
    'MaxClassLen' : [ 0x38, ['unsigned long']],
    'MaxValueNameLen' : [ 0x3c, ['unsigned long']],
    'MaxValueDataLen' : [ 0x40, ['unsigned long']],
    'WorkVar' : [ 0x44, ['unsigned long']],
    'NameLength' : [ 0x48, ['unsigned short']],
    'ClassLength' : [ 0x4a, ['unsigned short']],
    'Name' : [ 0x4c, ['array', 1, ['unsigned short']]],
} ],
  '_CM_KEY_INDEX' : [ 0x8, {
    'Signature' : [ 0x0, ['unsigned short']],
    'Count' : [ 0x2, ['unsigned short']],
    'List' : [ 0x4, ['array', 1, ['unsigned long']]],
} ],
  '_CHILD_LIST' : [ 0x8, {
    'Count' : [ 0x0, ['unsigned long']],
    'List' : [ 0x4, ['unsigned long']],
} ],
}



###############################################
#
# object.py
#
###############################################


"""
@author:       AAron Walters and Nick Petroni
@license:      GNU General Public License 2.0 or later
@contact:      awalters@komoku.com, npetroni@komoku.com
@organization: Komoku, Inc.
"""

import struct

builtin_types = { \
    'int' : (4, 'i'), \
    'long': (4, 'i'), \
    'unsigned long' : (4, 'I'), \
    'unsigned int' : (4, 'I'), \
    'address' : (4, 'I'), \
    'char' : (1, 'c'), \
    'unsigned char' : (1, 'B'), \
    'unsigned short' : (2, 'H'), \
    'short' : (2, 'h'), \
    'long long' : (8, 'q'), \
    'unsigned long long' : (8, 'Q'), \
    'pointer' : (4, 'I'),\
    }


def obj_size(types, objname):
    if not types.has_key(objname):
        raise Exception('Invalid type %s not in types' % (objname))

    return types[objname][0]

def builtin_size(builtin):
    if not builtin_types.has_key(builtin):
        raise Exception('Invalid built-in type %s' % (builtin))

    return builtin_types[builtin][0]

def read_value(addr_space, value_type, vaddr):
    """
    Read the low-level value for a built-in type. 
    """

    if not builtin_types.has_key(value_type):
        raise Exception('Invalid built-in type %s' % (value_type))

    type_unpack_char = builtin_types[value_type][1]
    type_size        = builtin_types[value_type][0]

    buf = addr_space.read(vaddr, type_size)
    if buf is None:
        return None
    (val, ) = struct.unpack(type_unpack_char, buf)

    return val

def read_unicode_string(addr_space, types, member_list, vaddr):
    offset = 0
    if len(member_list) > 1:
        (offset, current_type) = get_obj_offset(types, member_list)


    buf    = read_obj(addr_space, types, ['_UNICODE_STRING', 'Buffer'], vaddr + offset)
    length = read_obj(addr_space, types, ['_UNICODE_STRING', 'Length'], vaddr + offset)

    if length == 0x0:
        return ""

    if buf is None or length is None:
        return None

    readBuf = read_string(addr_space, types, ['char'], buf, length)

    if readBuf is None:
        return None
    
    try:
        readBuf = readBuf.decode('UTF-16').encode('ascii')
    except:
        return None
    
    return readBuf

def read_string(addr_space, types, member_list, vaddr, max_length=256):
    offset = 0
    if len(member_list) > 1:
        (offset, current_type) = get_obj_offset(types, member_list)

    val = addr_space.read(vaddr + offset, max_length)

    return val    
    

def read_null_string(addr_space, types, member_list, vaddr, max_length=256):
    string = read_string(addr_space, types, member_list, vaddr, max_length)

    if string is None:
        return None

    if (string.find('\0') == -1):
        return string
    (string, none) = string.split('\0', 1)
    return string
        

def get_obj_offset(types, member_list):
    """
    Returns the (offset, type) pair for a given list
    """
    member_list.reverse()

    current_type = member_list.pop()

    offset = 0

    while (len(member_list) > 0):
        if current_type == 'array':
            current_type = member_dict[current_member][1][2][0]
            if current_type in builtin_types:
                current_type_size = builtin_size(current_type)
            else:
                current_type_size = obj_size(types, current_type)
            index = member_list.pop()
            offset += index * current_type_size
            continue
            
        elif not types.has_key(current_type):
            raise Exception('Invalid type ' + current_type)
        
        member_dict = types[current_type][1]
        
        current_member = member_list.pop()
        if not member_dict.has_key(current_member):
            raise Exception('Invalid member %s in type %s' % (current_member, current_type))

        offset += member_dict[current_member][0]

        current_type = member_dict[current_member][1][0]

    return (offset, current_type)


def read_obj(addr_space, types, member_list, vaddr):
    """
    Read the low-level value for some complex type's member.
    The type must have members.
    """
    if len(member_list) < 2:
        raise Exception('Invalid type/member ' + str(member_list))
    

    
    (offset, current_type) = get_obj_offset(types, member_list)
    return read_value(addr_space, current_type, vaddr + offset)



###############################################
#
# win32/rawreg.py
#
###############################################


"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

# from framework.newobj import Obj,Pointer
from struct import unpack

ROOT_INDEX = 0x20
LH_SIG = unpack("<H","lh")[0]
LF_SIG = unpack("<H","lf")[0]
RI_SIG = unpack("<H","ri")[0]

def get_root(address_space):
    return Obj("_CM_KEY_NODE", ROOT_INDEX, address_space)

def open_key(root, key):
    if key == []:
        return root
    
    keyname = key.pop(0)
    for s in subkeys(root):
        if s.Name.upper() == keyname.upper():
            return open_key(s, key)
    print "ERR: Couldn't find subkey %s of %s" % (keyname, root.Name)
    return None

def subkeys(key,stable=True):
    if stable: k = 0
    else: k = 1
    sk = (key.SubKeyLists[k]/["pointer", ["_CM_KEY_INDEX"]]).value
    sub_list = []
    if (sk.Signature.value == LH_SIG or
            sk.Signature.value == LF_SIG):
        sub_list = sk.List
    elif sk.Signature.value == RI_SIG:
        lfs = []
        for i in range(sk.Count.value):
            off,tp = sk.get_offset(['List', i])
            lfs.append(Pointer("pointer", sk.address+off, sk.space,
                ["_CM_KEY_INDEX"]))
        for lf in lfs:
            sub_list += lf.List

    for s in sub_list:
        if s.is_valid() and s.Signature.value == 27502:
            yield s.value

def values(key):
    for v in key.ValueList.List:
        yield v.value

def walk(root):
    for k in subkeys(root):
        yield k
        for j in walk(k):
            yield j
