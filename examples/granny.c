// libbg3 examples
//
// Copyright (C) 2024 Mackenzie Straight.
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

#define LIBBG3_IMPLEMENTATION
#include "../libbg3.h"

#include "bitknit.c"

typedef struct bg3_bk_context {
  BitknitState* state;
  void* dst;
  uint32_t dst_len;
} bg3_bk_context;

static void* bg3_bk_begin_file_decompression(int type,
                                             bool endian_swapped,
                                             uint32_t dst_len,
                                             void* dst,
                                             uint32_t work_size,
                                             void* work) {
  if (endian_swapped || sizeof(BitknitState) > work_size) {
    bg3_panic("big endian granny files are unsupported");
  }
  bg3_bk_context* ctx = calloc(1, sizeof(bg3_bk_context));
  ctx->state = (BitknitState*)work;
  ctx->dst = dst;
  ctx->dst_len = dst_len;
  memset(dst, 0xFC, dst_len);
  BitknitState_Init(ctx->state);
  return ctx;
}

#define BITKNIT2_MAGIC 0x75B1

static bool bg3_bk_decompress_incremental(void* ctx, uint32_t src_len, void* src) {
  bg3_bk_context* bk_ctx = (bg3_bk_context*)ctx;
  if (src_len < 2 || *(uint16_t*)src != BITKNIT2_MAGIC) {
    return false;
  }
  void *src_cur = src + 2, *src_end = src + src_len, *dst_cur = bk_ctx->dst,
       *dst_end = bk_ctx->dst + bk_ctx->dst_len;
  int chunk_index = 1;
  while (dst_cur < dst_end) {
    uint32_t chunk_end = LIBBG3_MIN(bk_ctx->dst_len, chunk_index * 65536);
    if (!*(uint16_t*)src_cur) {
      src_cur += 2;
      size_t copy_len =
          LIBBG3_MIN(src_end - src_cur, chunk_end - (uint32_t)(dst_cur - bk_ctx->dst));
      memcpy(dst_cur, src_cur, copy_len);
      src_cur += copy_len;
      dst_cur += copy_len;
    } else {
      size_t used =
          Bitknit_Decode(src_cur, src_end, (uint8_t**)&dst_cur, bk_ctx->dst + chunk_end,
                         dst_end, bk_ctx->dst, bk_ctx->state);
      if (!used) {
        return false;
      }
      src_cur += used;
    }
    chunk_index++;
  }
  return true;
}

static bool bg3_bk_end_file_decompression(void* ctx) {
  free(ctx);
  return true;
}

static void print_granny_type(bg3_granny_type_info* info, int indent) {
  bg3_granny_type_info* first = info;
  while (info->type) {
    for (int i = 0; i < indent; ++i) {
      putchar(' ');
    }
    if (info->num_elements) {
      printf("%02d %s[%d]\n", info->type, info->name, info->num_elements);
    } else {
      printf("%02d %s\n", info->type, info->name);
    }
    if (info->tags[0] || info->tags[1] || info->tags[2]) {
      for (int i = 0; i < indent; ++i) {
        putchar(' ');
      }
      printf("  tags %08X %08X %08X\n", info->tags[0], info->tags[1], info->tags[2]);
    }
    if (info->reference_type) {
      bg3_granny_data_type prev_type = first->type;
      first->type = bg3_granny_dt_end;
      print_granny_type(info->reference_type, indent + 2);
      first->type = prev_type;
    }
    info++;
  }
}

int main(int argc, char const** argv) {
  bg3_granny_compressor_ops compress_ops = {
      0,
      bg3_bk_begin_file_decompression,
      bg3_bk_decompress_incremental,
      bg3_bk_end_file_decompression,
  };
  if (argc < 2) {
    fprintf(stderr, "syntax: %s <.gr2 path>\n", argv[0]);
    return 1;
  }
  bg3_mapped_file mapped;
  bg3_granny_reader reader;
  if (bg3_mapped_file_init_ro(&mapped, argv[1])) {
    fprintf(stderr, "failed to open file\n");
    return 1;
  }
  if (bg3_granny_reader_init(&reader, mapped.data, mapped.data_len, &compress_ops)) {
    fprintf(stderr, "failed to load granny file\n");
    return 1;
  }
  bg3_granny_type_info* root_type = bg3_granny_reader_get_root_type(&reader);
  printf("File schema:\n");
  print_granny_type(root_type, 0);
  bg3_granny_reader_destroy(&reader);
  return bg3_error_failed;
}
