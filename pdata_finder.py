from binaryninja import BinaryReader, BinaryView, Endianness, Function, Section
from binaryninja.plugin import BackgroundTaskThread


class PdataFinder(BackgroundTaskThread):
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


if 'bv' in locals():
    # noinspection PyUnresolvedReferences
    PdataFinder(bv).start()
