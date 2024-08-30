# ida-gcc

A collection of GCC utilities, specifically aimed for the reverse engineering tool [IDA Pro](https://hex-rays.com/ida-pro/)

Includes a symbols parser for GCC .map and .symbols file which mangles names back for a proper display of function arguments in the functions list aswell as applying this data to the function prototype for proper decompiler output

## Usage

### Symbols parser

Simply open up your IDB, go to File->Script file, and run ``gcc_sym_parse.py``

### Name mangler

Import ``shared_lib`` into your IDA Python script (if you want to use this outside of IDA's scope, remove/comment out all references to IDA in the previously mentioned file)

Call ``mangle_name()`` and pass a function prototype (without return type) as argument

Output will be a tuple, first element containing the mangled name and second element containing the extracted arguments

```py
from shared_lib import *

print(mangle_name("sce::Gnm::printErrorMessage(char const*, unsigned int, char const*, char const*, ...)"))
# output: ('_ZN3sce3Gnm17printErrorMessageEPKcjPKcPKcN3...E', 'char const*, unsigned int, char const*, char const*, ...')
```

## Features

- Apply guessed type info, sets the function prototype in IDA to the extracted arguments from the symbols file
- Verbose output
- Support for small formatting changes in .map files
- Support for .symbols files if they exist

## Known issues

- C style variadic arguments aren't properly mangled, they're currently output as a namespace, it will show correctly in IDA but won't work as intended when applying type info
- Templates are not taken into account
- Destructor type is assumed to be a complete destructor
- No support for a lot of stuff described in the [Itanium C++ ABI's mangling section](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling)

## Screenshots

![User Interface](https://github.com/Patoke/ida-gcc/blob/main/assets/user_interface.png?raw=true)

### Example of symbols parser working in Modern Warfare Remastered (2017) and Shadow of the Tomb Raider

![Modern Warfare Remastered (2017)](https://github.com/Patoke/ida-gcc/blob/main/assets/modern_warfare_remastered.png?raw=true)
![Shadow of the Tomb Raider](https://github.com/Patoke/ida-gcc/blob/main/assets/shadow_of_the_tomb_raider.png?raw=true)

## Thanks to

- [@gchatelet](https://github.com/gchatelet/) for their [amazing documentation](https://github.com/gchatelet/gcc_cpp_mangling_documentation) of GCC name mangling!
