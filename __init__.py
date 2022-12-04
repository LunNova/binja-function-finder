from binaryninja.plugin import PluginCommand

from .pdata_finder import PdataFinder
from .split_function_fixer import SplitFunctionFixer
from .xref_finder import XrefFinder
from .rtti import RTTIFinder


PluginCommand.register("Function Finder - Fix Split Functions", "Combines unnecessarily split functions",
                       lambda bv: SplitFunctionFixer(bv).start())

PluginCommand.register("Function Finder - RTTI", "Search for functions using MSVC RTTI data",
                       lambda bv: RTTIFinder(bv).start())

PluginCommand.register("Function Finder - code xref",
                       "Search for references to possible functions in executable segments",
                       lambda bv: XrefFinder(bv).start())

PluginCommand.register("Function Finder - .pdata", "Search for functions using .pdata section",
                       lambda bv: PdataFinder(bv).start())

PluginCommand.register("Function Finder - Remove all functions", "",
                       lambda bv: FunctionRemover(bv).start())

class FunctionRemover:
    def __init__(self, bv):
        self.bv = bv

    def start(self):
        for f in list(self.bv.functions):
            self.bv.remove_function(f)
