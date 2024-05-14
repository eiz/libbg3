A simple single header C library to do IO on some Baldur's Gate 3 file formats.
If you don't know why you'd use this library specifically, refer to LSLib
instead. I'm mainly posting this to document the aigrid/patch formats and show
how Granny models can be decompressed without a binary blob.

Supported formats:

- Osiris story databases (roundtrip capable). Can decompile to a text format
  that is buildable, but not by the engine as this implementation uses its own
  S-expression syntax. Allows for cross platform Osiris scripting without script
  extender and full modding of the game script.
- .pak (zstd compression not supported currently)
- .lsf (only "modern" format versions)
- .loca (ditto)
- aigrid.data (only version 21, the latest as of patch 6)
- .patch (does not support writing compressed normal maps)
- .gr2 (read only, see https://github.com/eiz/pybg3 for compression support)

Support for the text based formats is generally out of scope for this library.

Other curiosities:

There's a multi-threaded string index builder, but most of the code that uses it
isn't released here yet. This will likely join many other things in moving
outside of this library soon.

# Requirements

- Currently only tested with clang/mac. MSVC/gcc + win32/linux soon
- lz4 and miniz libraries are required for compression. compatible versions are
  included here.

# Usage

Just copy `libbg3.h` into your project. You'll also need to add the LZ4 and
miniz dependencies from somewhere if they're not already in your project:
compatible versions are included in `third_party`. In one C or C++ file, define
`#define LIBBG3_IMPLEMENTATION` prior to including the header. Note that
currently some unprefixed symbols leak into the TU that defines the
implementation.

Several example programs are available in the examples/ directory. You can build
them as follows:

```
git submodule update --init
mkdir build && cd build
cmake ..
make
```

# BUGS

- There is a very rarely used Osiris feature, "always enabled" rules that don't
  belong to a goal, which is used for 4 rules related to the shadow curse. These
  currently don't roundtrip properly and are lost when recompiling the story
- This code is what game devs call "not fuzz safe" 🤣
- A lot of the code is just bad and/or not done

# License

`libbg3.h` is released under the MIT license. Programs in the examples directory
are released under the GPLv3 or later.
