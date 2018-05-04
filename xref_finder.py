from binaryninja import DataVariable, BinaryView, Function, Symbol
from binaryninja.plugin import BackgroundTaskThread


class XrefFinder(BackgroundTaskThread):
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


if 'bv' in locals():
    # noinspection PyUnresolvedReferences
    XrefFinder(bv).start()
