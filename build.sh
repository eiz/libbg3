#!/bin/bash
set -euox pipefail
CC=cc
CFLAGS="-std=c2x -Wall -Wextra -g -I$(dirname $0)/third_party"
THIRD_PARTY_LIBS="third_party/lz4.c third_party/lz4frame.c third_party/lz4hc.c third_party/xxhash.c third_party/miniz.c"
cd $(dirname $0)
mkdir -p bin
$CC $CFLAGS -o bin/granny examples/granny.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/bg3_find examples/bg3_find.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/bg3_index examples/bg3_index.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/lspk examples/lspk.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/osiris examples/osiris.c $THIRD_PARTY_LIBS