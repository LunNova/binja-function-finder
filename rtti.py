from collections import defaultdict

from binaryninja import *
from typing import List

import undname


def define_named_type(bv, name, creator):
    t = bv.get_type_by_name(name)
    if t:
        return t
    # t = Type.named_type_from_type(name, creator(bv))
    t = creator(bv)
    bv.define_type(name, name, t)
    return bv.get_type_by_name(name)


def vtable_type(bv, length):
    # TODO
    # could make function pointer - but that seems to cause analysis trouble, not sure why
    # results in auto analysis thinking the methods in vtable take first argument as a function pointer pointer pointer
    # I am probably doing something stupid
    # Type.function(Type.void(), []))
    return define_named_type(bv, "vtable__" + str(length),
                             lambda _bv: Type.array(Type.pointer(_bv.arch, Type.void()), length))


def build_rva_pointer(bv):
    return define_named_type(bv, "RTTI_RVA_Pointer", lambda _bv: Type.int(4, False))


def create_rtti_col(bv):
    """
    :type bv: BinaryView
    :type bv: BinaryView
    """
    structure = Structure()
    # this is actually a 32-bit pointer relative to the image base address
    # TODO: Find out how/raise binary ninja issue for image base relative pointer types
    rva_pointer = build_rva_pointer(bv)

    structure.append(rva_pointer, "signature")
    structure.append(rva_pointer, "offset")
    structure.append(rva_pointer, "cdOffset")
    structure.append(rva_pointer, "pTypeDescriptor")
    structure.append(rva_pointer, "pClassDescriptor")
    structure.append(rva_pointer, "pSelf")

    # return structure
    return Type.structure_type(structure)


def create_rtti_type_descriptor(bv):
    """
    :type bv: BinaryView
    """
    structure = Structure()
    pointer, _ = bv.parse_type_string("void *")
    structure.append(pointer, "pVFTable")
    structure.append(pointer, "spare")
    # this should be flexibly sized not 0 but can't do that
    structure.append(bv.parse_type_string("char[0]")[0], "name")

    return Type.structure_type(structure)


def make_thiscall(fn, t=None):
    """
    :type fn: Function
    :type t: Type
    """
    pvs = fn.parameter_vars
    if not pvs or len(pvs) == 0:
        pvs = [Variable(fn, VariableSourceType.RegisterVariableSourceType, 0, 56, "this")]
    if pvs[0].storage != 56:
        # raise Exception("this should be in rcx for " + hex(function.start) +
        #  " " + repr([(x.name, x.index, x.storage) for x in pvs]))
        for pv in pvs:
            if pv.storage == 56:
                raise Exception("this should be arg0 in rcx for " + hex(fn.start) + " " + repr(
                    [(x.name, x.index, x.storage) for x in pvs]))
            pv.index += 1

        original_pvs = pvs
        pvs = [Variable(fn, VariableSourceType.RegisterVariableSourceType, 0, 56, "this")]
        pvs.extend(original_pvs)
    pvs[0].name = "this"
    if t:
        pvs[0].type = t
    fn.parameter_vars = pvs


# noinspection PyPep8Naming
class RTTIFinder(object):
    delayed_symbols = None  # type: List[Symbol]
    bv = None  # type: BinaryView

    def __init__(self, bv):
        self.bv = bv
        self.rtti_col = define_named_type(self.bv, "RTTICompleteObjectLocator", lambda _bv: create_rtti_col(_bv))
        self.rtti_td = define_named_type(self.bv, "RTTITypeDescriptor", lambda _bv: create_rtti_type_descriptor(_bv))

    def find_rtti_data(self):
        rdata = self.bv.get_section_by_name(".rdata")
        if not rdata:
            print("No rdata section, can't look for RTTI info")

        self.find_rtti_data_at(rdata.start, rdata.end)

    def find_rtti_data_at(self, start, end):
        bv = self.bv
        found = 0
        to_create = []
        address_size = bv.arch.address_size
        current = start
        end = end
        br = BinaryReader(bv)
        class_vtables = defaultdict(list)
        while current < end:
            next_address = bv.get_next_data_var_after(current)
            if not next_address or next_address <= current or next_address >= end:
                print("Done, found " + str(found) + " vtables")
                break
            current = next_address
            dv = bv.get_data_var_at(current)
            next_address = current + address_size
            prev = current - address_size
            prev_dv = bv.get_data_var_at(prev)
            next_dv = bv.get_data_var_at(next_address)
            if prev_dv or (next_dv and next_dv.address != dv.address):
                # References around it, probably not vtable
                continue
            br.offset = prev
            rtti_address = br.read64()
            rtti_data = self.read_rtti_data(br, rtti_address)
            if not rtti_data:
                continue
            br.offset = current
            method_count = 0
            method_addresses = []
            while True:
                method_address = br.read64()
                segment = bv.get_segment_at(method_address)
                if not segment or not segment.readable or not segment.executable or segment.writable:
                    # method should be in RX memory
                    break
                method_addresses.append(method_address)
                method_count += 1
            if method_count == 0:
                print("Found possible vtable with valid RTTI data methods at " + hex(
                    current) + " but no valid methods")
                continue
            other_vtables = class_vtables[rtti_data]
            other_vtables.append(method_address)
            found += 1
            # if found > 10:
            #     break
            # print("Found possible vtable with " + str(method_count) + " methods at " + hex(current) + " type " + str(
            #     type) + " for " + rtti_data)
            self.define_data(current, "vtable_" + rtti_data + "_" + hex(current), vtable_type(bv, method_count))
            index = 0
            for method_address in method_addresses:
                existing_method = bv.get_function_at(method_address)  # type: Function
                prefix = rtti_data + '::' + (
                    "" if len(other_vtables) == 1 else (str(len(other_vtables)) + '_')) + format(
                    index, 'x')
                if not existing_method:
                    bv.add_function(method_address)
                    existing_method = bv.get_function_at(method_address)
                if existing_method:  # and "::" not in existing_method.name:
                    make_thiscall(existing_method)
                    existing_method.name = prefix  # + '(' + existing_method.name + ')'
                if not existing_method:
                    to_create.append((prefix, method_address))
                index += 1
        bv.update_analysis_and_wait()
        for prefix, method_address in to_create:
            existing_method = bv.get_function_at(method_address)  # type: Function
            make_thiscall(existing_method)
            existing_method.name = prefix  # + '(' + existing_method.name + ')'

        print("Found " + str(found) + " vtables")

    def read_rtti_data(self, br, address):
        """
        :type br: BinaryReader
        :type address: long
        """
        bv = self.bv
        address_size = bv.arch.address_size
        if address % address_size != 0:
            return None
        segment = bv.get_segment_at(address)
        if not segment or not segment.readable or segment.executable or segment.writable:
            # RTTI data should be in read-only memory
            return None
        image_base = bv.start
        br.offset = address

        signature = br.read32()
        if signature not in (0, 1):
            # print("Invalid RTTI signature " + str(signature) + " at " + hex(address))
            return None

        # don't think we can do anything useful with these two yet - used for runtime casting
        # https://gist.github.com/ichenq/1382068/1b9a8be58848a54023f41f23813013ea75429407#file-__rtdynamiccast-cpp-L19

        # offset = \
        br.read32()

        # cdOffset = \
        br.read32()

        pTypeDescriptor = br.read32() + image_base
        if pTypeDescriptor % address_size != 0:
            print("Invalid RTTI type descriptor pointer " + hex(pTypeDescriptor) + " at " + hex(address))
            return None
        pClassDescriptor = br.read32() + image_base
        if pClassDescriptor % address_size != 0:
            print("Invalid RTTI class descriptor pointer " + hex(pClassDescriptor) + " at " + hex(address))
            return None
        pSelf = br.read32() + image_base
        if pSelf != address:
            print("Invalid RTTI self pointer " + hex(pSelf) + " != " + hex(address))
            return None

        type_descriptor = self.read_type_descriptor(br, pTypeDescriptor)
        if not type_descriptor:
            return None

        vtable, name, mangled_name = type_descriptor

        rtti_td, _ = bv.parse_type_string("RTTITypeDescriptor")
        self.define_data(pTypeDescriptor, name, rtti_td)
        name_address = pTypeDescriptor + address_size * 2
        self.define_data(name_address, "mangled_name_" + hex(name_address),
                         bv.parse_type_string("char[" + str(len(mangled_name)) + "]")[0])

        rtti_col, _ = bv.parse_type_string("RTTICompleteObjectLocator")
        self.define_data(address, "COL_" + name + "_" + hex(address), rtti_col)

        return name

        # TODO: Use class descriptor
        # print(type_descriptor)
        # print str(locals())

    def define_data(self, address, name, t):
        bv = self.bv
        dv = bv.get_data_var_at(address)
        if not dv or str(dv.type) != str(t):
            bv.define_user_data_var(address, t)

        existing = bv.get_symbol_at(address)
        if existing:
            bv.undefine_user_symbol(existing)
            bv.undefine_auto_symbol(existing)

        symbol = Symbol(SymbolType.DataSymbol, address, name)
        bv.define_auto_symbol(symbol)

    def read_type_descriptor(self, br, address):
        """
        :type br: BinaryReader
        :type address: long
        """
        bv = self.bv
        image_base = bv.start

        segment = bv.get_segment_at(address)
        if not segment or not segment.readable or segment.executable:
            # RTTI data should be in read-only memory
            print("Invalid RTTI type descriptor at " + hex(address) + " (invalid address) " + str(segment))
            return None

        br.offset = address
        pVFTable = br.read64()
        pVFTable += image_base

        spare = br.read64()
        if spare not in (0, 1):
            print("Invalid RTTI type descriptor at " + hex(address) + " (spare = " + hex(spare) + ")")
            return None

        name = ""
        while True:
            char = br.read8()
            if char == 0:
                break
            name += chr(char)

        return pVFTable, undname.unmangle(name[1:], True), name
