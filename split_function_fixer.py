from binaryninja import BinaryView, Function, ReferenceSource, BasicBlock, \
    InstructionTextToken
from binaryninja.plugin import BackgroundTaskThread
from typing import Set


def is_split_far(calling_functions, jumps, start):
    for cf in calling_functions:
        dist = abs(cf.start - start)
        if dist > 1000:
            print (hex(start) + " looks like split function, jumped to " + str(
                jumps) + " times")
            print("Not unsplitting as jump from " + str(dist) + " bytes away")
            return True
    return False


class SplitFunctionFixer(BackgroundTaskThread):
    bv = None  # type: BinaryView
    found = None  # type: int
    abort = False

    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Split Function Fixer", True)
        self.bv = bv
        self.found = 0

    def run(self):
        bv = self.bv

        splits = []
        calling_functions_to_update = set()  # type: Set[int]

        print 'Waiting for analysis'
        bv.update_analysis_and_wait()

        print 'Finding split functions'
        for called_function in bv.functions:
            if SplitFunctionFixer.abort:
                return

            xrefs = bv.get_code_refs(called_function.start)
            if not xrefs or len(xrefs) == 0:
                continue

            calls = 0
            jumps = 0
            calling_functions = set()

            for xref in xrefs:  # type: ReferenceSource
                calling_function = xref.function  # type: Function
                if calling_function.start == called_function.start:
                    continue
                for bb in calling_function.basic_blocks:  # type: BasicBlock
                    ins = get_instruction(bb, xref.address)
                    if ins is not None:
                        itt = ins[0]  # type: InstructionTextToken
                        if itt.text == 'call':
                            calls += 1
                        if itt.text[0] == 'j':
                            calling_functions.add(calling_function)
                            jumps += 1
                        break

            if calls > 0 or jumps == 0:
                continue

            start = called_function.start
            failed = is_split_far(calling_functions, jumps, start)

            if failed:
                continue

            # if len(calling_functions) != 1:
            #     print (hex(start) + " looks like split function, jumped to " + str(
            #         jumps) + " times but jumped to from multiple functions")
            #     continue

            splits.append(called_function)
            calling_functions_to_update.update([x.start for x in calling_functions])

        removed = []
        print('Removing ' + str(len(splits)) + " split functions")
        for split in splits:
            removed.append(split.start)
            bv.remove_function(split)

        for update in calling_functions_to_update:
            fn = bv.get_function_at(update)  # type: Function
            if fn:
                fn.reanalyze()

        print('Reanalysing callers of removed functions')
        bv.update_analysis_and_wait()

        print('Adding back apparently split functions which disappeared')
        added = 0
        for start in removed:
            if len(bv.get_basic_blocks_at(start)) == 0:
                added += 1
                bv.add_function(start)

        print("Added " + str(added) + " missing functions")
        print("Done")


def get_instruction(bb, address):
    start = bb.start
    end = bb.end

    if not (start <= address < end):
        return None

    idx = start
    while idx < end:
        data = bb.view.read(idx, bb.arch.max_instr_length)
        inst_info = bb.arch.get_instruction_info(data, idx)

        if idx == address:
            return bb.arch.get_instruction_text(data, idx)[0]

        if idx > address:
            break

        # yield inst_text
        idx += inst_info.length

    return None


if 'bv' in locals():
    # noinspection PyUnresolvedReferences
    SplitFunctionFixer(bv).start()
