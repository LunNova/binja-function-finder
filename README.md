# Function Finder
Author: **nallar**

A few tools for finding functions which might be missed by binary ninja's auto analysis.

## Description:

#### .pdata:
Creates functions for each [RUNTIME_FUNCTION](https://msdn.microsoft.com/en-us/library/ft9x1kdx.aspx) entry in the .pdata section.

#### xref:
Creates functions for each reference from an existing function into executable data that does not have a known type. Will have false positives.

## Installation:

To install this plugin, navigate to your Binary Ninja plugins directory, and run

```git clone https://github.com/nallar/binja-function-finder.git function-finder```

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release (Commercial) - 1.0.729-dev
 * release (Personal) - 1.0.729-dev

## License

This plugin is released under the [AGPL](LICENSE) license.

