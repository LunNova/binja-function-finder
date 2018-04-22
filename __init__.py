import binaryninja
from binaryninja import DataVariable, BinaryReader, BinaryView, Endianness, Function, Section, Symbol
from binaryninja.plugin import BackgroundTaskThread, PluginCommand


class XrefSearcher(BackgroundTaskThread):
    bv = None  # type: BinaryView
    found = -1

    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Function finder", True)
        self.bv = bv

    def run(self):
        bv = self.bv

        print 'Waiting for analysis'
        bv.update_analysis_and_wait()

        while self.found != 0:
            self.found = 0
            for segment in bv.segments:
                # Code
                if segment.executable:
                    start = segment.start
                    end = segment.end
                    self.find(bv, start, end)
            print 'Found ' + str(self.found) + ' functions'

    def find(self, bv, start, end):
        cur = start
        while True:
            cur = bv.get_next_data_var_after(cur)
            if cur >= end:
                break
            dv = bv.get_data_var_at(cur)  # type: DataVariable
            if str(dv.type) != 'void':
                # Not unknown type
                continue

            if bv.get_basic_blocks_at(cur):
                # (should we create one anyway?)
                # already a function here
                continue

            sym = bv.get_symbol_at(cur)  # type: Symbol
            if sym and sym.name.startswith("jump"):
                # Jump table
                continue
            bv.create_user_function(cur)
            f = bv.get_function_at(cur)  # type: Function
            if f.name[0:4] == 'sub_':
                f.name += '_xref'
            print 'Found ' + f.name
            self.found += 1
        bv.update_analysis_and_wait()


PluginCommand.register("Function Finder - code xref",
                       "Search for references to possible functions in executable segments",
                       lambda bv: XrefSearcher(bv).start())


class PdataSearcher(BackgroundTaskThread):
    bv = None  # type: BinaryView
    found = -1

    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Function finder", True)
        self.bv = bv

    def run(self):
        bv = self.bv

        print 'Waiting for analysis'
        bv.update_analysis_and_wait()

        while self.found != 0:
            self.found = 0
            for section_name in bv.sections:
                print section_name
                if section_name == ".pdata":
                    section = bv.sections[section_name]  # type: Section
                    self.find(bv, section.start, section.end)
            print 'Found ' + str(self.found) + ' functions'

    def find(self, bv, start, end):
        """

        :type bv: BinaryView
        :type start: int
        :type end: int
        """
        br = BinaryReader(bv, Endianness.LittleEndian)
        br.offset = start
        ends = []
        offset = bv.start
        while br.offset < end:
            start_address = br.read32()
            end_address = br.read32()
            unwind_information = br.read32()
            if start_address == 0 and end_address == 0 and unwind_information == 0:
                break
            start_address += offset
            end_address += offset
            ends.append(end_address)
            current = bv.get_function_at(start_address)  # type: Function
            if current is None or current.start != start_address:
                # if not bv.get_basic_blocks_at(start_address):
                bv.create_user_function(start_address)
                f = bv.get_function_at(start_address)  # type: Function
                if f.name[0:4] == 'sub_':
                    f.name += '_pdata'
                self.found += 1
        bv.update_analysis_and_wait()

        for end_address in ends:
            if not bv.get_functions_containing(end_address - 1):
                print "Expected pdata end_address to be in function " + hex(end_address)


PluginCommand.register("Function Finder - .pdata", "Search for functions using .pdata section",
                       lambda bv: PdataSearcher(bv).start())
