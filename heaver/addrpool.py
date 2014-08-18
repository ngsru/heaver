"""AddressPool manages list of addresses in heaver.
It performs these tasks:
* Parse range of addresses from configs
* Pick free address
* Dump used addresses"""


class InvalidAddressRange(Exception):
    pass

class InvalidAddress(Exception):
    pass

# FIXME: rethink ip address api, datatypes and usage.

# NOTE: if performance matters, replace list operations with sorted lists and unpacked addresses
class AddressPool(object):

    def __init__(self, used=None):
        self.all_addrs = []
        if used is None:
            self.used_addrs = []
        else:
            self.used_addrs = used

    def add_range(self, addrs):
        self.all_addrs.extend(parse_range(addrs))

    def add_used_range(self, addrs):
        self.used_addrs.extend(parse_range(addrs))

    def alloc_address(self):
        "Get free address from pool"
        free_addrs = sorted(set(self.all_addrs) - set(self.used_addrs))
        if len(free_addrs) == 0:
            return None
        addr = free_addrs[0]
        self.used_addrs.append(addr)
        return format_address(addr)

    def alloc_addresses(self, count):
        "Get 'count' free addresses from pool"
        free_addrs = sorted(set(self.all_addrs) - set(self.used_addrs))
        if len(free_addrs) < count:
            return None
        addrs = free_addrs[:count]
        self.used_addrs.extend(addrs)
        return map(format_address, addrs)

    def free_address(self, address):
        "Remove address from used address pool"
        addr = parse_address(address)
        if addr in self.used_addrs:
            self.used_addrs.remove(addr)

    def mark_address(self, address):
        "Mark address as used"
        addr = parse_address(address)
        self.used_addrs.append(addr)

    def count_free_addresses(self):
        "Return count of free addresses in pool"
        free_addrs = sorted(set(self.all_addrs) - set(self.used_addrs))
        return len(free_addrs)

    def dump_used_ranges(self):
        used = sorted(self.used_addrs)
        if len(used) == 0:
            return []

        used.append((255, 255, 255, 255)) # sentinel, see below
        dump = []
        prev = first = pack_address(used[0])
        for ip in used[1:]:
            current = pack_address(ip)
            if current == prev:
                # FIXME: duplicate, where to fix it?
                continue
            if current == prev + 1:
                # we in range
                prev = current
                continue
            else:
                # current element does not fit in range
                # put range from previous elements into dump
                # thus, 'current' element does not occur in dump in this loop step
                # because of that sentinel is used to flush last range into dump
                if prev == first:
                    # Only one address in range
                    dump.append("%d.%d.%d.%d" % unpack_address(first))
                else:
                    # We have a range
                    first_unpacked = unpack_address(first)
                    last_unpacked = unpack_address(prev)
                    first_str = "%d.%d.%d.%d" % first_unpacked
                    suffix = resolve_suffix(first_unpacked, last_unpacked)
                    suffix_str = ".".join(map(str, suffix))
                    if not suffix:
                        raise Exception("Internal error: suffix for range is empty!")
                    dump.append("%s-%s" % (first_str, suffix_str))
                first = prev = current
        return dump


def parse_range(range_str):
    """
    Create address range from range string.
    Range string defined in a form firstAddr-lastAddrSuffix, where firstAddr is first ip address in
    range and lastAddrSuffix is a part of ipaddr, which would be supplemented to full address using
    correspondent parts from firstAddr. I.e. range string 192.168.1.1-100 corresponds to addresses
    from 192.168.1.1 to 192.168.1.100 and range string 192.168.1.1-3.100 corresponds to addresses
    from 192.168.1.1 to 192.168.1.255, from 192.168.2.0 to 192.168.2.255 and from 192.168.3.0 to
    192.168.3.100"""

    addrs = []

    # check if string is valid range
    # check for suffix character
    if range_str.count("-") > 1:
        raise InvalidAddressRange("Must be no more than one address suffix")

    # check for valid symbols
    valid_symbols = map(chr, range(ord("0"), ord("9") + 1)) # digits
    valid_symbols += [".", "-"]
    for idx, c in enumerate(range_str):
        if c not in valid_symbols:
            raise InvalidAddressRange("Invalid character on position %d" % idx)

    # parse ip addr
    addr_str, _dash, suffix_str = range_str.partition("-")
    first_addr = parse_address(addr_str)

    if suffix_str:
        last_addr = parse_address(suffix_str, first_addr)
        if last_addr < first_addr:
            raise InvalidAddressRange("Last address must be greater than first address")
        for ip in range(pack_address(first_addr), pack_address(last_addr) + 1):
            addrs.append(unpack_address(ip))
    else:
        addrs = [first_addr]

    return addrs


def parse_address(src, complement=None):
    "Parse ip address from string or parse ip address suffix and complement it to full address"
    parts = src.split(".")
    if len(parts) > 4:
        raise InvalidAddress("Too much parts")
    elif complement is None and len(parts) < 4:
        raise InvalidAddress("Too few parts")
    elif complement is not None and len(complement) != 4:
        raise InvalidAddress("Invalid complementary address")

    addr = []
    for idx, part in enumerate(parts):
        if len(part) == 0:
            raise InvalidAddress("Empty address part at index %d" % idx)
        part_number = int(part)
        if 0 <= part_number <= 255:
            addr.append(part_number)
        else:
            raise InvalidAddress("Invalid ip address part at index %d" % idx)

    if complement is not None:
        # fulfill missing parts
        addr = list(complement)[:4-len(addr)] + addr

    return tuple(addr)


def format_address(addr):
    return "%d.%d.%d.%d" % addr

def pack_address(addr):
    "Join tuple of 4 bytes into one 4-byte int"
    return (addr[0] << 24) + (addr[1] << 16) + (addr[2] << 8) + addr[3]

def unpack_address(addr):
    "Split 4-byte int into tuple of 4 bytes"
    return tuple(int((addr >> (idx * 8)) & 0xFF) for idx in [3, 2, 1, 0])

def resolve_suffix(first_addr, last_addr):
    "Find the least uncommon part of addresses"
    suffix = []
    # pair corresponding parts
    for idx, (part_f, part_l) in enumerate(zip(first_addr, last_addr)):
        if part_f == part_l:
            continue
        # if we found different part, return it and remaining parts
        else:
            return last_addr[idx:]
