A simple single header C library to do IO on some Baldur's Gate 3 file formats.
If you don't know why you'd use this library specifically, refer to LSLib
instead. I'm mainly posting this to document the aigrid/patch formats.

Supported formats:

- Osiris story databases (roundtrip capable). Can decompile to a text format
  that is buildable, but not by the engine (different syntax). Allows for cross
  platform Osiris scripting without script extender and full modding of the game
  script.
- .pak (zstd compression not supported currently)
- .lsf (only "modern" format versions)
- .loca (ditto)
- .aigrid (only version 21, the latest as of patch 6)
- .patch (does not support writing compressed normal maps)
- .gr2 (read only and hacky compression support atm which probably won't work for you!)

Support for the text based formats is generally out of scope for this library.

Other curiosities:

There's a multi-threaded string index builder, but most of the code that uses
it isn't released here yet. This will likely join many other things in moving
outside of this library soon.

Requirements:

- Currently only tested with clang/mac. MSVC/gcc + win32/linux soon
- lz4 and miniz libraries are required for compression. compatible versions are
  included here.

Usage:

In one C file, define `#define LIBBG3_IMPLEMENTATION` prior to including the
header. Note that currently some unprefixed symbols leak into the TU that
defines the implementation.

Sorry, there's no documentation or examples right now.

# BUGS

- Multi-part pak files aren't loaded as I haven't needed them yet
- There is a very rarely used Osiris feature, "always enabled" rules that don't
  belong to a goal, which is used for 2 rules related to the shadow curse. These
  currently don't roundtrip properly and are lost when recompiling the story
- This code is what game devs call "not fuzz safe" 🤣
- A lot of the code is just bad and/or not done
