from binaryninja.plugin import PluginCommand

from pdata_finder import PdataFinder
from split_function_fixer import SplitFunctionFixer
from xref_finder import XrefFinder

PluginCommand.register("Function Finder - Fix Split Functions", "Combines unnecessarily split functions",
                       lambda bv: SplitFunctionFixer(bv).start())

PluginCommand.register("Function Finder - code xref",
                       "Search for references to possible functions in executable segments",
                       lambda bv: XrefFinder(bv).start())

PluginCommand.register("Function Finder - .pdata", "Search for functions using .pdata section",
                       lambda bv: PdataFinder(bv).start())
