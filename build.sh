#!/bin/bash
set -euox pipefail
CC=cc
CFLAGS="-std=c2x -Wall -Wextra -g"
THIRD_PARTY_LIBS="lz4.c lz4frame.c lz4hc.c xxhash.c miniz.c"
cd $(dirname $0)
mkdir -p bin
$CC $CFLAGS -o bin/granny examples/granny.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/bg3_find examples/bg3_find.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/bg3_index examples/bg3_index.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/lspk examples/lspk.c $THIRD_PARTY_LIBS
$CC $CFLAGS -o bin/osiris examples/osiris.c $THIRD_PARTY_LIBS