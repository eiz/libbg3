// libbg3
//
// Copyright (C) 2024 Mackenzie Straight.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the “Software”), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef LIBBG3_H
#define LIBBG3_H

#ifdef LIBBG3_CLANGD
#ifndef LIBBG3_IMPLEMENTATION
#define LIBBG3_IMPLEMENTATION
#endif
#endif

// Set to 1 to enable bcdec integration. Currently only used for dumping
// debugging info about patch files.
#ifndef LIBBG3_CONFIG_ENABLE_BCDEC
#define LIBBG3_CONFIG_ENABLE_BCDEC 0
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_MAC
#define LIBBG3_PLATFORM_MACOS
#endif  // TARGET_OS_MAC
#endif  // __APPLE__

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// utilities
#define LIBBG3_API  __attribute__((visibility("default")))
#define LIBBG3_PACK __attribute__((__packed__))

#define LIBBG3_IS_SET(field, flag) (((field) & (flag)) != 0)

#define LIBBG3_COUNT_OF(array) ((sizeof(array)) / sizeof(*(array)))

#define LIBBG3_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define LIBBG3_MIN(x, y) (((x) < (y)) ? (x) : (y))

#define LIBBG3_ROUND_UP(x, y) ((((x) + (y)-1) / (y)) * (y))

#define LIBBG3_MAKE_FOURCC(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

#define LIBBG3_FOURCC_FMT "%c%c%c%c"
#define LIBBG3_FOURCC_FMT_ARGS(fourcc)                     \
  (char)((fourcc) & 0xFF), (char)(((fourcc) >> 8) & 0xFF), \
      (char)(((fourcc) >> 16) & 0xFF), (char)(((fourcc) >> 24) & 0xFF)

typedef _Float16 bg3_half;
typedef float bg3_vec3[3];
typedef float bg3_vec4[4];
typedef bg3_vec4 bg3_mat4x4[4];

typedef enum bg3_status {
  bg3_success = 0,
  bg3_error_failed = -1,
  bg3_error_overflow = -2,
  bg3_error_bad_magic = -3,
  bg3_error_bad_version = -4,
  bg3_error_libc = -5,
  bg3_error_not_found = -6,
  bg3_error_unsupported = -7,
} bg3_status;

typedef enum bg3_log_level {
  bg3_log_level_panic,
  bg3_log_level_error,
  bg3_log_level_info,
} bg3_log_level;

void LIBBG3_API bg3_set_log_level(bg3_log_level level);
void LIBBG3_API bg3_log_vprintf(bg3_log_level level, char const* format, va_list ap);
void LIBBG3_API __attribute__((format(printf, 1, 2))) bg3_info(char const* fmt, ...);
void LIBBG3_API __attribute__((format(printf, 1, 2))) bg3_error(char const* fmt, ...);
void LIBBG3_API __attribute__((noreturn, format(printf, 1, 2)))
bg3_panic(char const* fmt, ...);

#define LIBBG3_UUID_STRING_LEN 37  // including the null terminator

typedef struct bg3_uuid {
  uint32_t word;
  uint16_t half[6];
} bg3_uuid;

typedef struct bg3_mapped_file {
  int fd;
  char* data;
  size_t data_len;
} bg3_mapped_file;

bg3_status LIBBG3_API bg3_mapped_file_init_ro(bg3_mapped_file* file, char const* path);
bg3_status LIBBG3_API bg3_mapped_file_init_rw_trunc(bg3_mapped_file* file,
                                                    char const* path,
                                                    size_t new_size);
void LIBBG3_API bg3_mapped_file_destroy(bg3_mapped_file* file);
bg3_status LIBBG3_API bg3_mapped_file_read(bg3_mapped_file* file,
                                           void* dest,
                                           size_t offset,
                                           size_t len);

// the absolute most poverty level parallel do stuff operator
struct bg3_parallel_for_thread;
typedef int bg3_parallel_for_cb(struct bg3_parallel_for_thread* tcb);
typedef struct bg3_parallel_for_sync {
  pthread_cond_t cond;
  pthread_mutex_t mutex;
  int gate_enter;
  int gate_exit;
} bg3_parallel_for_sync;
typedef struct bg3_parallel_for_thread {
  int thread_num;
  int thread_count;
  int status;
  pthread_t thread;
  bg3_parallel_for_cb* callback;
  void* user_data;
  bg3_parallel_for_sync* sync;
} bg3_parallel_for_thread;
int LIBBG3_API bg3_parallel_for_ncpu();
int LIBBG3_API bg3_parallel_for(bg3_parallel_for_cb* callback, void* user_data);
int LIBBG3_API bg3_parallel_for_n(bg3_parallel_for_cb* callback,
                                  void* user_data,
                                  int nthreads);
// gpu style thread sync, must be executed unconditionally in all parallel for
// threads
void LIBBG3_API bg3_sync_threads(bg3_parallel_for_thread* tcb);

#define LIBBG3_HASH_EMPTY_VALUE     ((void*)-1)
#define LIBBG3_HASH_TOMBSTONE_VALUE ((void*)-2)

typedef struct bg3_hash_ops {
  uint64_t (*hash_fn)(void* key, void* user_data);
  bool (*equal_fn)(void* lhs, void* rhs, void* user_data);
  void* (*copy_key_fn)(void* key, void* user_data);
  void (*free_key_fn)(void* key, void* user_data);
  void* (*copy_value_fn)(void* value, void* user_data);
  void (*free_value_fn)(void* value, void* user_data);
} bg3_hash_ops;

typedef struct bg3_hash_entry {
  void* key;
  void* value;
} bg3_hash_entry;

typedef struct bg3_hash {
  bg3_hash_ops const* ops;
  void* user_data;
  size_t num_keys;
  size_t table_size;
  bg3_hash_entry* entries;
} bg3_hash;

void LIBBG3_API bg3_hash_init(bg3_hash* table, bg3_hash_ops const* ops, void* user_data);
void LIBBG3_API bg3_hash_destroy(bg3_hash* table);
void LIBBG3_API bg3_hash_set(bg3_hash* table, void* key, void* value);
// sets a key if it does not exist, otherwise returns existing entry. *existing
// is always set to the hash entry for the key, true is returned if the key was
// inserted.
bool LIBBG3_API bg3_hash_try_set(bg3_hash* table,
                                 void* key,
                                 void* value,
                                 bg3_hash_entry** existing);
bg3_hash_entry* LIBBG3_API bg3_hash_get_entry(bg3_hash* table, void* key);
bool LIBBG3_API bg3_hash_delete(bg3_hash* table, void* key);
void LIBBG3_API bg3_hash_clear(bg3_hash* table);

uint64_t LIBBG3_API bg3_hash_default_hash_fn(void* key, void* user_data);
bool LIBBG3_API bg3_hash_default_equal_fn(void* lhs, void* rhs, void* user_data);
void* LIBBG3_API bg3_hash_default_copy_fn(void* value, void* user_data);
void LIBBG3_API bg3_hash_default_free_fn(void* value, void* user_data);

extern const bg3_hash_ops bg3_default_hash_ops;

// For the following hash ops, keys should be null-terminated strings and values
// should be LIBBG3_MAKE_SYMBOL_VALUE values. user_data must be a pointer to an
// arena. keys will be copied into the arena.
extern const bg3_hash_ops bg3_symtab_hash_ops;       // for case insensitive symbol tables
extern const bg3_hash_ops bg3_symtab_case_hash_ops;  // same thing but case sensitive

#define LIBBG3_MAKE_SYMBOL_VALUE(symtype, index) \
  ((void*)((((size_t)symtype) << 24) | (size_t)(index)))
#define LIBBG3_SYMBOL_TYPE_OF(sym_value)  (((size_t)sym_value) >> 24)
#define LIBBG3_SYMBOL_INDEX_OF(sym_value) (((size_t)sym_value) & 0xFFFFFF)

typedef struct bg3_cursor {
  char* start;
  char* ptr;
  char* end;
} bg3_cursor;

static inline void bg3_cursor_init(bg3_cursor* cursor, void* ptr, size_t length) {
  cursor->ptr = cursor->start = (char*)ptr;
  cursor->end = cursor->ptr + length;
}

static inline void bg3_cursor_read(bg3_cursor* cursor, void* dest, size_t length) {
  ptrdiff_t avail = cursor->end - cursor->ptr;
  if (avail < length) {
    bg3_panic("buffer copy out of bounds");
  }
  if (dest) {
    memcpy(dest, cursor->ptr, length);
  }
  cursor->ptr += length;
}

static inline void bg3_cursor_align(bg3_cursor* cursor, size_t alignment) {
  ptrdiff_t used = cursor->ptr - cursor->start;
  size_t rem = used % alignment;
  if (rem > 0) {
    bg3_cursor_read(cursor, 0, alignment - rem);
  }
}

static inline void bg3_cursor_seek(bg3_cursor* cursor, size_t offset) {
  cursor->ptr = cursor->start;
  bg3_cursor_read(cursor, 0, offset);
}

typedef struct bg3_buffer {
  char* data;
  size_t size;
  size_t capacity;
} bg3_buffer;

static inline void bg3_buffer_init(bg3_buffer* buffer) {
  memset(buffer, 0, sizeof(bg3_buffer));
}

static inline void bg3_buffer_destroy(bg3_buffer* buffer) {
  free(buffer->data);
}

static inline void bg3_buffer_push(bg3_buffer* buffer, void const* new_data, size_t len) {
  // TODO: overflow =( we need checked math lol
  size_t new_size = buffer->size + len;
  size_t new_capacity = buffer->capacity;
  while (new_capacity < new_size) {
    new_capacity = new_capacity + (new_capacity / 2) + 1;
  }
  if (new_capacity != buffer->capacity) {
    buffer->data = (char*)realloc(buffer->data, new_capacity);
    buffer->capacity = new_capacity;
  }
  memcpy(buffer->data + buffer->size, new_data, len);
  buffer->size += len;
}

static inline void bg3_buffer_pop(bg3_buffer* buffer, size_t len) {
  assert(buffer->size >= len);
  buffer->size -= len;
}

static inline void bg3_buffer_vprintf(bg3_buffer* buffer,
                                      char const* format,
                                      va_list ap) {
  va_list ap_tmp;
  va_copy(ap_tmp, ap);
  size_t avail = buffer->capacity - buffer->size;
  size_t used = vsnprintf(buffer->data + buffer->size, avail, format, ap_tmp);
  va_end(ap_tmp);
  if (avail < used + 1) {
    size_t new_capacity = buffer->capacity;
    while (new_capacity - buffer->size < used + 1) {
      new_capacity = new_capacity + (new_capacity / 2) + 1;
    }
    buffer->data = (char*)realloc(buffer->data, new_capacity);
    buffer->capacity = new_capacity;
    avail = buffer->capacity - buffer->size;
    used = vsnprintf(buffer->data + buffer->size, avail, format, ap);
  }
  buffer->size += used;
}

static inline void __attribute__((format(printf, 2, 3)))
bg3_buffer_printf(bg3_buffer* buffer, char const* format, ...) {
  va_list ap;
  va_start(ap, format);
  bg3_buffer_vprintf(buffer, format, ap);
  va_end(ap);
}

static inline void bg3_buffer_putchar(bg3_buffer* buffer, char chr) {
  bg3_buffer_push(buffer, &chr, 1);
}

static inline void bg3_buffer_copy(bg3_buffer* dest, bg3_buffer* src) {
  dest->size = 0;
  bg3_buffer_push(dest, src->data, src->size);
  bg3_buffer_putchar(dest, 0);
  dest->size--;
}

void LIBBG3_API bg3_buffer_hexdump(bg3_buffer* buf,
                                   size_t base,
                                   void* ptr,
                                   size_t length);
void LIBBG3_API bg3_hex_dump(void* ptr, size_t length);
bool LIBBG3_API bg3_strcasesuffix(char const* str, char const* suffix);

typedef struct bg3_arena_chunk {
  struct bg3_arena_chunk* next;
  char* bump;
  char* end;
} bg3_arena_chunk;

typedef struct bg3_arena {
  size_t chunk_size;
  size_t max_waste;
  bg3_arena_chunk* chunks;
  bg3_arena_chunk* full_chunks;
} bg3_arena;

void LIBBG3_API bg3_arena_init(bg3_arena* a, size_t chunk_size, size_t max_waste);
void LIBBG3_API bg3_arena_destroy(bg3_arena* a);
void* LIBBG3_API bg3_arena_alloc(bg3_arena* a, size_t size);
static inline void* bg3_arena_calloc(bg3_arena* a, size_t count, size_t size) {
  size_t total_size = count * size;
  void* result = bg3_arena_alloc(a, total_size);
  memset(result, 0, total_size);
  return result;
}
char* LIBBG3_API bg3_arena_strdup(bg3_arena* a, char const* str);
char* LIBBG3_API bg3_arena_sprintf(bg3_arena* a, char const* format, ...);

#ifdef __cplusplus
#define LIBBG3_ARRAY_PUSH(alloc, owner, member, val)                           \
  do {                                                                         \
    if ((owner)->cap_##member == (owner)->num_##member) {                      \
      size_t old_cap = (owner)->cap_##member;                                  \
      size_t new_cap = old_cap + old_cap / 2 + 1;                              \
      void* dest = bg3_arena_alloc(alloc, new_cap * sizeof(*(owner)->member)); \
      if (old_cap) {                                                           \
        memcpy(dest, (owner)->member, old_cap * sizeof(*(owner)->member));     \
      }                                                                        \
      (owner)->cap_##member = new_cap;                                         \
      (owner)->member = (decltype((owner)->member))dest;                       \
    }                                                                          \
    (owner)->member[(owner)->num_##member++] = val;                            \
  } while (0)
#else
#define LIBBG3_ARRAY_PUSH(alloc, owner, member, val)                           \
  do {                                                                         \
    if ((owner)->cap_##member == (owner)->num_##member) {                      \
      size_t old_cap = (owner)->cap_##member;                                  \
      size_t new_cap = old_cap + old_cap / 2 + 1;                              \
      void* dest = bg3_arena_alloc(alloc, new_cap * sizeof(*(owner)->member)); \
      if (old_cap) {                                                           \
        memcpy(dest, (owner)->member, old_cap * sizeof(*(owner)->member));     \
      }                                                                        \
      (owner)->cap_##member = new_cap;                                         \
      (owner)->member = dest;                                                  \
    }                                                                          \
    (owner)->member[(owner)->num_##member++] = val;                            \
  } while (0)
#endif

// pack files
#define LIBBG3_LSPK_MAGIC   0x4B50534C
#define LIBBG3_LSPK_VERSION 18

#define LIBBG3_LSPK_ENTRY_COMPRESSION_METHOD_MASK 0xF
#define LIBBG3_LSPK_ENTRY_COMPRESSION_LEVEL_MASK  0xF0

#define LIBBG3_LSPK_ENTRY_COMPRESSION_METHOD(x) \
  ((x) & LIBBG3_LSPK_ENTRY_COMPRESSION_METHOD_MASK)
#define LIBBG3_LSPK_ENTRY_COMPRESSION_LEVEL(x) \
  (((x) & LIBBG3_LSPK_ENTRY_COMPRESSION_LEVEL_MASK) >> 4)

#define LIBBG3_LSPK_ENTRY_COMPRESSION_NONE    0
#define LIBBG3_LSPK_ENTRY_COMPRESSION_ZLIB    1
#define LIBBG3_LSPK_ENTRY_COMPRESSION_LZ4     2
#define LIBBG3_LSPK_ENTRY_COMPRESSION_FAST    1
#define LIBBG3_LSPK_ENTRY_COMPRESSION_DEFAULT 2
#define LIBBG3_LSPK_ENTRY_COMPRESSION_MAX     4

typedef struct bg3_lspk_header {
  uint32_t magic;
  uint32_t version;
  uint64_t manifest_offset;
  uint32_t manifest_size;
  uint8_t flags;
  uint8_t priority;
  uint8_t md5[16];
  uint16_t num_parts;
} bg3_lspk_header;

typedef struct bg3_lspk_manifest_header {
  uint32_t num_files;
  uint32_t compressed_size;
} bg3_lspk_manifest_header;

typedef struct bg3_lspk_manifest_entry {
  char name[256];
  uint32_t offset_lo;
  uint16_t offset_hi;
  uint8_t part_num;
  uint8_t compression;
  uint32_t compressed_size;
  uint32_t uncompressed_size;
} bg3_lspk_manifest_entry;

typedef struct bg3_lspk_part {
  char* data;
  size_t data_len;
} bg3_lspk_part;

typedef struct bg3_lspk_file {
  bg3_mapped_file* mapped;
  bg3_lspk_header header;
  size_t num_files;
  bg3_lspk_manifest_entry* manifest;
  bg3_lspk_part* parts;
} bg3_lspk_file;

bg3_status LIBBG3_API bg3_lspk_file_init(bg3_lspk_file* file, bg3_mapped_file* mapped);
bg3_status LIBBG3_API bg3_lspk_file_attach_part(bg3_lspk_file* file,
                                                size_t part_num,
                                                char* data,
                                                size_t data_len);
void LIBBG3_API bg3_lspk_file_destroy(bg3_lspk_file* file);
bg3_status LIBBG3_API bg3_lspk_file_extract(bg3_lspk_file* file,
                                            bg3_lspk_manifest_entry* entry,
                                            char* dest,
                                            size_t* dest_len);

// object files
#define LIBBG3_LSOF_MAGIC       0x464F534C
#define LIBBG3_LSOF_VERSION_MIN 6
#define LIBBG3_LSOF_VERSION_MAX 7

typedef enum {
  bg3_lsof_dt_none = 0x00,
  bg3_lsof_dt_uint8 = 0x01,
  bg3_lsof_dt_int16 = 0x02,
  bg3_lsof_dt_uint16 = 0x03,
  bg3_lsof_dt_int32 = 0x04,
  bg3_lsof_dt_uint32 = 0x05,
  bg3_lsof_dt_float = 0x06,
  bg3_lsof_dt_double = 0x07,
  bg3_lsof_dt_ivec2 = 0x08,
  bg3_lsof_dt_ivec3 = 0x09,
  bg3_lsof_dt_ivec4 = 0x0A,
  bg3_lsof_dt_vec2 = 0x0B,
  bg3_lsof_dt_vec3 = 0x0C,
  bg3_lsof_dt_vec4 = 0x0D,
  bg3_lsof_dt_mat2 = 0x0E,
  bg3_lsof_dt_mat3 = 0x0F,
  bg3_lsof_dt_mat3x4 = 0x10,
  bg3_lsof_dt_mat4x3 = 0x11,
  bg3_lsof_dt_mat4 = 0x12,
  bg3_lsof_dt_bool = 0x13,
  bg3_lsof_dt_string = 0x14,
  bg3_lsof_dt_path = 0x15,
  bg3_lsof_dt_fixedstring = 0x16,
  bg3_lsof_dt_lsstring = 0x17,
  bg3_lsof_dt_uint64 = 0x18,
  bg3_lsof_dt_scratchbuffer = 0x19,
  bg3_lsof_dt_long = 0x1A,
  bg3_lsof_dt_int8 = 0x1B,
  bg3_lsof_dt_translatedstring = 0x1C,
  bg3_lsof_dt_wstring = 0x1D,
  bg3_lsof_dt_lswstring = 0x1E,
  bg3_lsof_dt_uuid = 0x1F,
  bg3_lsof_dt_int64 = 0x20,
  bg3_lsof_dt_translatedfsstring = 0x21,

  bg3_lsof_dt_last = bg3_lsof_dt_translatedfsstring,
} bg3_lsof_dt;

typedef struct bg3_lsof_size {
  uint32_t uncompressed_size;
  uint32_t compressed_size;
} bg3_lsof_size;

typedef struct bg3_lsof_header {
  uint32_t magic;
  uint32_t version;
  uint64_t engine_version;  // according to lslib
  bg3_lsof_size string_table;
  bg3_lsof_size unknown_table;
  bg3_lsof_size node_table;
  bg3_lsof_size attr_table;
  bg3_lsof_size value_table;
  uint8_t compression;
  uint32_t flags;
} bg3_lsof_header;

// Not always set even in current BG3!
#define LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS 0x1
// This is set on some _merged.lsf files in Levels/ and I'm not sure what it is
#define LIBBG3_LSOF_FLAG_UNKNOWN_1            0x2

#define LIBBG3_LSOF_OWNS_STRING_TABLE 0x1
#define LIBBG3_LSOF_OWNS_NODE_TABLE   0x2
#define LIBBG3_LSOF_OWNS_ATTR_TABLE   0x4
#define LIBBG3_LSOF_OWNS_VALUE_TABLE  0x8
#define LIBBG3_LSOF_OWNS_ALL          0xF

typedef struct bg3_lsof_sym_ref {
  uint16_t entry;
  uint16_t bucket;
} bg3_lsof_sym_ref;
typedef int32_t bg3_lsof_node_ref;
typedef int32_t bg3_lsof_attr_ref;
typedef int32_t bg3_lsof_value_ref;

typedef struct bg3_lsof_node_wide {
  bg3_lsof_sym_ref name;
  bg3_lsof_node_ref parent;
  bg3_lsof_node_ref next;
  bg3_lsof_attr_ref attrs;
} bg3_lsof_node_wide;

typedef struct bg3_lsof_node_slim {
  bg3_lsof_sym_ref name;
  bg3_lsof_node_ref attrs;
  bg3_lsof_node_ref parent;
} bg3_lsof_node_slim;

typedef struct bg3_lsof_attr_wide {
  bg3_lsof_sym_ref name;
  uint32_t type : 6;
  uint32_t length : 26;
  bg3_lsof_attr_ref next;
  union {
    bg3_lsof_value_ref value;
    bg3_lsof_node_ref owner;
  };
} bg3_lsof_attr_wide;

typedef struct bg3_lsof_attr_slim {
  bg3_lsof_sym_ref name;
  uint32_t type : 6;
  uint32_t length : 26;
  bg3_lsof_node_ref owner;
} bg3_lsof_attr_slim;

typedef struct bg3_lsof_symtab_entry {
  size_t length;
  char* data;
  char* c_str;
} bg3_lsof_symtab_entry;

typedef struct bg3_lsof_symtab_bucket {
  size_t num_entries;
  size_t capacity;
  bg3_lsof_symtab_entry* entries;
} bg3_lsof_symtab_bucket;

typedef struct bg3_lsof_symtab {
  size_t num_buckets;
  bool is_writable;
  bg3_lsof_symtab_bucket* buckets;
} bg3_lsof_symtab;

typedef struct bg3_lsof_reader {
  char* data;
  size_t data_len;
  bg3_lsof_header header;
  bg3_lsof_symtab symtab;
  size_t num_nodes;
  size_t num_attrs;
  char* string_table_raw;
  char* node_table_raw;
  char* attr_table_raw;
  char* value_table_raw;
  uint32_t* value_offsets;
  uint32_t owned_sections;
} bg3_lsof_reader;

typedef struct bg3_lsof_writer_stack_frame {
  bg3_lsof_node_ref node_id;
  bg3_lsof_node_ref last_child;
  bg3_lsof_attr_ref last_attr;
} bg3_lsof_writer_stack_frame;

typedef struct bg3_lsof_writer {
  bg3_lsof_symtab symtab;
  size_t num_nodes;
  size_t num_attrs;
  size_t num_stack;
  bg3_buffer stack;
  bg3_buffer node_table;
  bg3_buffer attr_table;
  bg3_buffer value_table;
} bg3_lsof_writer;

void LIBBG3_API bg3_lsof_symtab_init(bg3_lsof_symtab* table, int num_buckets);
void LIBBG3_API bg3_lsof_symtab_init_data(bg3_lsof_symtab* table,
                                          char* ptr,
                                          size_t length);
void LIBBG3_API bg3_lsof_symtab_destroy(bg3_lsof_symtab* table);
bg3_lsof_symtab_entry* LIBBG3_API bg3_lsof_symtab_get_ref(bg3_lsof_symtab* table,
                                                          bg3_lsof_sym_ref ref);
char const* LIBBG3_API bg3_lsof_symtab_entry_c_str(bg3_lsof_symtab_entry* entry);
void LIBBG3_API bg3_lsof_symtab_dump(bg3_lsof_symtab* table);
bg3_lsof_sym_ref LIBBG3_API bg3_lsof_symtab_intern(bg3_lsof_symtab* table,
                                                   char const* name);
void LIBBG3_API bg3_lsof_symtab_write(bg3_lsof_symtab* table, bg3_buffer* buf);

bg3_status LIBBG3_API bg3_lsof_reader_init(bg3_lsof_reader* file,
                                           char* data,
                                           size_t data_len);
void LIBBG3_API bg3_lsof_reader_destroy(bg3_lsof_reader* file);
int LIBBG3_API bg3_lsof_reader_get_node(bg3_lsof_reader* file,
                                        bg3_lsof_node_wide* node,
                                        size_t node_index);
int LIBBG3_API bg3_lsof_reader_get_attr(bg3_lsof_reader* file,
                                        bg3_lsof_attr_wide* attr,
                                        size_t attr_index);
void LIBBG3_API bg3_lsof_reader_ensure_value_offsets(bg3_lsof_reader* file);
void LIBBG3_API bg3_lsof_reader_ensure_sibling_pointers(bg3_lsof_reader* file);
int LIBBG3_API bg3_lsof_reader_print_sexp(bg3_lsof_reader* file, bg3_buffer* out);

void LIBBG3_API bg3_lsof_writer_init(bg3_lsof_writer* writer);
void LIBBG3_API bg3_lsof_writer_destroy(bg3_lsof_writer* writer);
bg3_status LIBBG3_API bg3_lsof_writer_write_file(bg3_lsof_writer* writer,
                                                 char const* path);
void LIBBG3_API bg3_lsof_writer_push_node(bg3_lsof_writer* writer, char const* node_name);
void LIBBG3_API bg3_lsof_writer_push_attr(bg3_lsof_writer* writer,
                                          char const* attr_name,
                                          bg3_lsof_dt type,
                                          void* ptr,
                                          size_t len);
void LIBBG3_API bg3_lsof_writer_pop_node(bg3_lsof_writer* writer);
bg3_status LIBBG3_API bg3_lsof_writer_push_sexps(bg3_lsof_writer* writer,
                                                 char const* data,
                                                 size_t data_len);

// localization files
#define LIBBG3_LOCA_MAGIC 0x41434F4C  // 'LOCA' in little endian

typedef struct bg3_loca_reader_entry_raw {
  char handle[64];
  uint16_t version;
  uint16_t size_lo;
  uint16_t size_hi;
} bg3_loca_reader_entry_raw;

typedef struct bg3_loca_reader_entry {
  char handle[64];
  uint16_t version;
  char* data;
  size_t data_size;
} bg3_loca_reader_entry;

typedef struct bg3_loca_header {
  uint32_t magic;
  uint32_t num_entries;
  uint32_t heap_offset;
} bg3_loca_header;

typedef struct bg3_loca_reader {
  bg3_loca_header header;
  bg3_loca_reader_entry* entries;
} bg3_loca_reader;

bg3_status LIBBG3_API bg3_loca_reader_init(bg3_loca_reader* file,
                                           char* data,
                                           size_t data_len);
int LIBBG3_API bg3_loca_reader_dump(bg3_loca_reader* file);
void LIBBG3_API bg3_loca_reader_destroy(bg3_loca_reader* file);

typedef struct bg3_loca_writer {
  bg3_buffer entries;
  bg3_buffer heap;
} bg3_loca_writer;

void LIBBG3_API bg3_loca_writer_init(bg3_loca_writer* writer);
void LIBBG3_API bg3_loca_writer_destroy(bg3_loca_writer* writer);
void LIBBG3_API bg3_loca_writer_push(bg3_loca_writer* writer,
                                     char const* handle,
                                     uint16_t version,
                                     char const* text);
bg3_status LIBBG3_API bg3_loca_writer_write_file(bg3_loca_writer* writer,
                                                 char const* path);

// patch files

#define LIBBG3_PATCH_MAGIC              0x6E6F697372655650  // 'PVersion'
#define LIBBG3_PATCH_VERSION            8
#define LIBBG3_PATCH_VERSION_NON_ROBUST 5

typedef struct bg3_patch_header {
  uint64_t magic;
  uint32_t version;
  uint32_t metadata_size;
} bg3_patch_header;

typedef struct bg3_patch_key_bounds {
  int32_t x0;
  int32_t x1;
  int32_t y0;
  int32_t y1;
} bg3_patch_key_bounds;

typedef struct bg3_patch_metadata {
  uint32_t local_cols;
  uint32_t local_rows;
  uint32_t tex_cols;
  uint32_t tex_rows;
  uint32_t global_cols;
  uint32_t global_rows;
  uint32_t chunk_x;
  uint32_t chunk_y;
  uint32_t num_holes;
  uint32_t num_layers;
  bg3_patch_key_bounds key_bounds[2];
} bg3_patch_metadata;

typedef struct bg3_patch_layer {
  char* name;
  uint8_t* weights;
} bg3_patch_layer;

// the structure of these is known, but the function currently isn't.
// in the engine these are referred to as "KeyMaps"
typedef struct bg3_patch_key_entry {
  char* data;
  size_t data_len;
} bg3_patch_key_entry;

typedef struct bg3_patch_keys {
  bg3_patch_key_bounds* bounds;
  bg3_patch_key_entry entries[4];
} bg3_patch_keys;

typedef struct bg3_bc7_block {
  uint64_t lo;
  uint64_t hi;
} bg3_bc7_block;

typedef struct bg3_patch_file {
  bg3_patch_header header;
  bg3_patch_metadata metadata;
  char* data;
  size_t data_len;
  float* heightfield;
  uint32_t* holes;
  bg3_bc7_block* normal_map;
  size_t normal_map_rows;
  size_t normal_map_cols;
  bg3_patch_layer* layers;
  size_t num_keys;
  bg3_patch_keys keys[2];
} bg3_patch_file;

bg3_status LIBBG3_API bg3_patch_file_init(bg3_patch_file* file,
                                          char* data,
                                          size_t data_len);
void LIBBG3_API bg3_patch_file_destroy(bg3_patch_file* file);
bg3_status LIBBG3_API bg3_patch_file_dump(bg3_patch_file* file);

// granny models
typedef enum bg3_granny_compression_type {
  bg3_granny_compression_none,
  bg3_granny_compression_oodle0,
  bg3_granny_compression_oodle1,
  bg3_granny_compression_bitknit1,
  bg3_granny_compression_bitknit2,
} bg3_granny_compression_type;

// there are other granny magics, but this one is the one we care about:
// 64-bit little endian.
#define LIBBG3_GRANNY_MAGIC_HI      0xC4EDBE90A9EB131E
#define LIBBG3_GRANNY_MAGIC_LO      0x141F636F5E499BE5
#define LIBBG3_GRANNY_VERSION       7
#define LIBBG3_GRANNY_BITKNIT_CHUNK 0x2000

// Begin Granny3D on-disk structures

typedef enum bg3_granny_data_type {
  bg3_granny_dt_end = 0,
  bg3_granny_dt_inline = 1,
  bg3_granny_dt_reference = 2,
  bg3_granny_dt_reference_to_array = 3,
  bg3_granny_dt_array_of_references = 4,
  bg3_granny_dt_variant_reference = 5,
  bg3_granny_dt_reference_to_variant_array = 7,
  bg3_granny_dt_string = 8,
  bg3_granny_dt_transform = 9,
  bg3_granny_dt_float = 10,
  bg3_granny_dt_int8 = 11,
  bg3_granny_dt_uint8 = 12,
  bg3_granny_dt_binormal_int8 = 13,
  bg3_granny_dt_normal_uint8 = 14,
  bg3_granny_dt_int16 = 15,
  bg3_granny_dt_uint16 = 16,
  bg3_granny_dt_binormal_int16 = 17,
  bg3_granny_dt_normal_uint16 = 18,
  bg3_granny_dt_int32 = 19,
  bg3_granny_dt_uint32 = 20,
  bg3_granny_dt_half = 21,
  bg3_granny_dt_empty_reference = 22,
  bg3_granny_dt_count = bg3_granny_dt_empty_reference + 1,
} bg3_granny_data_type;

typedef struct LIBBG3_PACK bg3_granny_section_ptr {
  uint32_t section;
  uint32_t offset;
} LIBBG3_PACK bg3_granny_section_ptr;

typedef struct LIBBG3_PACK bg3_granny_fixup {
  uint32_t section_offset;
  bg3_granny_section_ptr ptr;
} LIBBG3_PACK bg3_granny_fixup;

typedef struct LIBBG3_PACK bg3_granny_magic {
  uint64_t lo;
  uint64_t hi;
  uint32_t header_size;
  uint32_t header_format;
  uint32_t reserved[2];
} bg3_granny_magic;

typedef struct LIBBG3_PACK bg3_granny_header {
  uint32_t format_version;
  uint32_t file_size;
  uint32_t crc32;
  uint32_t section_table;
  uint32_t num_sections;
  bg3_granny_section_ptr root_type;
  bg3_granny_section_ptr root_obj;
  uint32_t type_tag;
  uint32_t extra_tags[4];
  uint32_t strings_crc;
  uint32_t reserved[3];
} bg3_granny_header;

typedef struct LIBBG3_PACK bg3_granny_section_header {
  uint32_t compression;
  uint32_t offset;
  uint32_t compressed_len;
  uint32_t uncompressed_len;
  uint32_t alignment;
  // some compressors use multiple streams?
  uint32_t stream0_end;
  uint32_t stream1_end;
  uint32_t fixups_offset;
  uint32_t num_fixups;
  uint32_t mixed_marshal_offset;
  uint32_t num_mixed_marshals;
} bg3_granny_section_header;

typedef struct LIBBG3_PACK bg3_granny_type_info {
  bg3_granny_data_type type;
  char* name;
  struct bg3_granny_type_info* reference_type;
  uint32_t num_elements;
  uint32_t tags[3];
  uint64_t reserved;
} bg3_granny_type_info;

typedef struct LIBBG3_PACK bg3_granny_variant {
  bg3_granny_type_info* type;
  void* obj;
} bg3_granny_variant;

typedef struct LIBBG3_PACK bg3_granny_variant_array {
  bg3_granny_type_info* type;
  int32_t num_items;
  void* items;
} bg3_granny_variant_array;

typedef struct LIBBG3_PACK bg3_granny_transform {
  uint32_t flags;
  bg3_vec3 position;
  bg3_vec4 orientation;
  bg3_vec3 scale_shear[3];
} bg3_granny_transform;

// End Granny3D on-disk structures

typedef size_t bg3_fn_granny_decompress_data(int type,
                                             bool endian_swapped,
                                             uint32_t compressed_size,
                                             void* compressed_data,
                                             uint32_t stream0_end,
                                             uint32_t stream1_end,
                                             uint32_t uncompressed_size,
                                             void* uncompressed_data);
typedef void* bg3_fn_granny_begin_file_decompression(int type,
                                                     bool endian_swapped,
                                                     uint32_t uncompressed_size,
                                                     void* uncompressed_data,
                                                     uint32_t buf_size,
                                                     void* buffer);
typedef bool bg3_fn_granny_decompress_incremental(void* context,
                                                  uint32_t compressed_size,
                                                  void* compressed_data);
typedef bool bg3_fn_granny_end_file_decompression(void* context);

typedef struct bg3_granny_compressor_ops {
  bg3_fn_granny_decompress_data* decompress_data;
  bg3_fn_granny_begin_file_decompression* begin_file_decompression;
  bg3_fn_granny_decompress_incremental* decompress_incremental;
  bg3_fn_granny_end_file_decompression* end_file_decompression;
} bg3_granny_compressor_ops;

typedef struct bg3_granny_section {
  char* data;
  size_t data_len;
  bool owned;
} bg3_granny_section;

typedef struct bg3_granny_reader {
  char* data;
  size_t data_len;
  bg3_granny_magic magic;
  bg3_granny_header header;
  bg3_granny_section_header* section_headers;
  bg3_granny_section* sections;
} bg3_granny_reader;

void LIBBG3_API bg3_granny_reader_destroy(bg3_granny_reader* reader);
bg3_status LIBBG3_API
bg3_granny_reader_init(bg3_granny_reader* reader,
                       char* data,
                       size_t data_len,
                       bg3_granny_compressor_ops const* compressor_ops);
void* LIBBG3_API bg3_granny_reader_get_root(bg3_granny_reader* reader);
bg3_granny_type_info* LIBBG3_API
bg3_granny_reader_get_root_type(bg3_granny_reader* reader);

// granite tile set

#define LIBBG3_GTS_MAGIC   0x47505247  // 'GRPG' in little endian
#define LIBBG3_GTS_VERSION 5

typedef struct LIBBG3_PACK bg3_gts_header {
  uint32_t magic;                    // 0x0
  uint32_t version;                  // 0x4
  uint32_t unk0_a;                   // 0x8
  uint64_t unk0_b;                   // 0xC
  uint64_t unk0_c;                   // 0x14
  uint32_t num_layers;               // 0x1C
  uint64_t layers_offset;            // 0x20
  uint32_t num_levels;               // 0x28
  uint64_t levels_offset;            // 0x2C
  uint32_t width;                    // 0x34, guessed order
  uint32_t height;                   // 0x38
  uint32_t unk1[21];                 // 0x3C
  uint32_t gdex_len;                 // 0x90
  uint64_t gdex_offset;              // 0x94
  uint32_t num_parameter_blocks;     // 0x9C
  uint64_t parameter_blocks_offset;  // 0xA0
  // pointer to 0xC byte header, first field is # of 0x24 byte entries
  uint64_t thumbnails_offset;  // 0xA8
  uint32_t unk2a[4];           // 0xB0
  // header len is 0xC0
} LIBBG3_PACK bg3_gts_header;

typedef struct bg3_gts_layer_header {
  uint64_t unk0;
} LIBBG3_PACK bg3_gts_layer_header;

typedef struct bg3_gts_level_header {
  uint32_t x;
  uint32_t y;
  uint64_t offset;
} LIBBG3_PACK bg3_gts_level_header;

typedef struct bg3_gts_parameter_block_header {
  uint32_t unk0[2];
  uint32_t data_len;
  uint64_t data_offset;
} LIBBG3_PACK bg3_gts_parameter_block_header;

typedef struct bg3_gts_reader {
  char* data;
  size_t data_len;
  bg3_gts_header header;
} bg3_gts_reader;

typedef struct bg3_gts_thumbnails_entry {
  bg3_uuid uuid;
  uint64_t offset;  // offset for both of the following, which are contiguous
  // compressed? not sure if fastlz or lz4 or ? looks very simple
  uint32_t thumbnail_length;
  uint32_t miptail_length;  // idk format of this data yet
  uint16_t width;
  uint16_t height;
} LIBBG3_PACK bg3_gts_thumbnails_entry;

bg3_status LIBBG3_API bg3_gts_reader_init(bg3_gts_reader* reader,
                                          char* data,
                                          size_t data_len);
void LIBBG3_API bg3_gts_reader_destroy(bg3_gts_reader* reader);
void LIBBG3_API bg3_gts_reader_dump(bg3_gts_reader* reader);

typedef enum bg3_gdex_tag : uint32_t {
  bg3_gdex_tag_meta = LIBBG3_MAKE_FOURCC('M', 'E', 'T', 'A'),
  bg3_gdex_tag_atls = LIBBG3_MAKE_FOURCC('A', 'T', 'L', 'S'),
  bg3_gdex_tag_proj = LIBBG3_MAKE_FOURCC('P', 'R', 'O', 'J'),
  bg3_gdex_tag_linf = LIBBG3_MAKE_FOURCC('L', 'I', 'N', 'F'),
  bg3_gdex_tag_info = LIBBG3_MAKE_FOURCC('I', 'N', 'F', 'O'),
  bg3_gdex_tag_txts = LIBBG3_MAKE_FOURCC('T', 'X', 'T', 'S'),
  bg3_gdex_tag_txtr = LIBBG3_MAKE_FOURCC('T', 'X', 'T', 'R'),
  bg3_gdex_tag_name = LIBBG3_MAKE_FOURCC('N', 'A', 'M', 'E'),
  bg3_gdex_tag_wdth = LIBBG3_MAKE_FOURCC('W', 'D', 'T', 'H'),
  bg3_gdex_tag_hght = LIBBG3_MAKE_FOURCC('H', 'G', 'H', 'T'),
  bg3_gdex_tag_xxxx = LIBBG3_MAKE_FOURCC('X', 'X', 'X', 'X'),
  bg3_gdex_tag_yyyy = LIBBG3_MAKE_FOURCC('Y', 'Y', 'Y', 'Y'),
  bg3_gdex_tag_addr = LIBBG3_MAKE_FOURCC('A', 'D', 'D', 'R'),
  bg3_gdex_tag_srgb = LIBBG3_MAKE_FOURCC('S', 'R', 'G', 'B'),
  bg3_gdex_tag_thmb = LIBBG3_MAKE_FOURCC('T', 'H', 'M', 'B'),
  bg3_gdex_tag_layr = LIBBG3_MAKE_FOURCC('L', 'A', 'Y', 'R'),
  bg3_gdex_tag_indx = LIBBG3_MAKE_FOURCC('I', 'N', 'D', 'X'),
  bg3_gdex_tag_type = LIBBG3_MAKE_FOURCC('T', 'Y', 'P', 'E'),
  bg3_gdex_tag_comp = LIBBG3_MAKE_FOURCC('C', 'O', 'M', 'P'),
  bg3_gdex_tag_cmpw = LIBBG3_MAKE_FOURCC('C', 'M', 'P', 'W'),
  bg3_gdex_tag_majr = LIBBG3_MAKE_FOURCC('M', 'A', 'J', 'R'),
  bg3_gdex_tag_minr = LIBBG3_MAKE_FOURCC('M', 'I', 'N', 'R'),
  bg3_gdex_tag_binf = LIBBG3_MAKE_FOURCC('B', 'I', 'N', 'F'),
  bg3_gdex_tag_date = LIBBG3_MAKE_FOURCC('D', 'A', 'T', 'E'),
  bg3_gdex_tag_blks = LIBBG3_MAKE_FOURCC('B', 'L', 'K', 'S'),
  bg3_gdex_tag_tile = LIBBG3_MAKE_FOURCC('T', 'I', 'L', 'E'),
  bg3_gdex_tag_bdpr = LIBBG3_MAKE_FOURCC('B', 'D', 'P', 'R'),
  bg3_gdex_tag_ltmp = LIBBG3_MAKE_FOURCC('L', 'T', 'M', 'P'),
  bg3_gdex_tag_nvld = LIBBG3_MAKE_FOURCC('N', 'V', 'L', 'D'),
} bg3_gdex_tag;

typedef enum bg3_gdex_item_type : uint8_t {
  bg3_gdex_item_bytes = 0,
  bg3_gdex_item_container = 1,
  bg3_gdex_item_string = 2,
  bg3_gdex_item_int = 3,
  bg3_gdex_item_float = 3,  // ya rly
  bg3_gdex_item_int64 = 4,
  bg3_gdex_item_double = 6,
  bg3_gdex_item_date = 7,         // actually just a uint64_t
  bg3_gdex_item_typed_array = 8,  // they don't write any metadata for these
  bg3_gdex_item_uuid = 12,
  bg3_gdex_item_uuid_array = 13,
} bg3_gdex_item_type;

// looks similar to an mpeg-4 box? but more cringe
typedef struct bg3_gdex_item {
  uint32_t tag;
  bg3_gdex_item_type type;
  uint8_t flag;
  uint16_t length_lo;
} LIBBG3_PACK bg3_gdex_item;

static inline size_t bg3_gdex_item_header_length(bg3_gdex_item const* item) {
  return sizeof(bg3_gdex_item) + (item->flag & 1 ? 4 : 0);
}

static inline char const* bg3_gdex_item_payload(bg3_gdex_item const* item) {
  return (char*)item + bg3_gdex_item_header_length(item);
}

static inline uint32_t bg3_gdex_item_extended_length(bg3_gdex_item const* item) {
  return *(uint32_t const*)(item + 1);
}

static inline size_t bg3_gdex_item_payload_length(bg3_gdex_item const* item) {
  return (item->flag & 1) ? ((uint64_t)item->length_lo |
                             ((uint64_t)bg3_gdex_item_extended_length(item) << 16ULL))
                          : (uint64_t)item->length_lo;
}

static inline uint64_t bg3_gdex_item_length(bg3_gdex_item const* item) {
  return LIBBG3_ROUND_UP(
      bg3_gdex_item_header_length(item) + bg3_gdex_item_payload_length(item), 4);
}

bg3_gdex_item const* bg3_gdex_item_find_child(bg3_gdex_item const* parent, uint32_t tag);

typedef struct bg3_gdex_iter {
  bg3_cursor c;
} bg3_gdex_iter;

static inline void bg3_gdex_iter_init(bg3_gdex_iter* iter, bg3_gdex_item const* item) {
  if (item->type != bg3_gdex_item_container) {
    iter->c.ptr = iter->c.start = iter->c.end = 0;
    return;
  }
  bg3_cursor_init(&iter->c, (char*)item + bg3_gdex_item_header_length(item),
                  bg3_gdex_item_payload_length(item));
}

static inline bg3_gdex_item* bg3_gdex_iter_next(bg3_gdex_iter* iter) {
  if (iter->c.ptr == iter->c.end) {
    return 0;
  }
  bg3_gdex_item* item = (bg3_gdex_item*)iter->c.ptr;
  iter->c.ptr += bg3_gdex_item_length(item);
  return item;
}

// sexp lexer

typedef enum bg3_sexp_token_type {
  bg3_sexp_token_type_invalid,
  bg3_sexp_token_type_eof,
  bg3_sexp_token_type_lparen,
  bg3_sexp_token_type_rparen,
  bg3_sexp_token_type_hash,
  bg3_sexp_token_type_symbol,
  bg3_sexp_token_type_string,
  bg3_sexp_token_type_integer,
  bg3_sexp_token_type_decimal,
} bg3_sexp_token_type;

typedef struct bg3_sexp_token {
  bg3_sexp_token_type type;
  bg3_buffer text;
  union {
    int64_t int_val;
    double float_val;
  };
  int line;
  int col;
  int len;
} bg3_sexp_token;

typedef struct bg3_sexp_lexer {
  bg3_sexp_token next;
  int line;
  int col;
  bg3_cursor c;
} bg3_sexp_lexer;

void LIBBG3_API bg3_sexp_token_copy(bg3_sexp_token* dest, bg3_sexp_token* src);
void LIBBG3_API bg3_sexp_lexer_copy(bg3_sexp_lexer* dest, bg3_sexp_lexer* src);
void LIBBG3_API bg3_sexp_lexer_init(bg3_sexp_lexer* lexer,
                                    char const* data,
                                    size_t data_len);
void LIBBG3_API bg3_sexp_lexer_init_cstr(bg3_sexp_lexer* lexer, char const* text);
void LIBBG3_API bg3_sexp_lexer_destroy(bg3_sexp_lexer* lexer);
void LIBBG3_API bg3_sexp_lexer_advance(bg3_sexp_lexer* lexer);

// indent buffer
typedef struct bg3_indent_buffer {
  bg3_buffer stack;
  bg3_buffer tmp;
  bg3_buffer output;
  uint32_t line_len;
} bg3_indent_buffer;

void LIBBG3_API bg3_ibuf_init(bg3_indent_buffer* buf);
void LIBBG3_API bg3_ibuf_destroy(bg3_indent_buffer* buf);
void LIBBG3_API bg3_ibuf_clear(bg3_indent_buffer* buf);
void LIBBG3_API bg3_ibuf_vprintf(bg3_indent_buffer* buf, char const* fmt, va_list args);
void LIBBG3_API __attribute__((format(printf, 2, 3)))
bg3_ibuf_printf(bg3_indent_buffer* buf, char const* fmt, ...);
void LIBBG3_API bg3_ibuf_fresh_line(bg3_indent_buffer* buf);
void LIBBG3_API bg3_ibuf_push_align(bg3_indent_buffer* buf);
void LIBBG3_API bg3_ibuf_push(bg3_indent_buffer* buf, uint32_t width);
void LIBBG3_API bg3_ibuf_pop(bg3_indent_buffer* buf);
uint32_t LIBBG3_API bg3_ibuf_get_next_col(bg3_indent_buffer* buf);
uint32_t LIBBG3_API bg3_ibuf_get_indent(bg3_indent_buffer* buf);

// xref index
#define LIBBG3_INDEX_MAGIC   0x5844534C  // 'LSDX'
#define LIBBG3_INDEX_VERSION 1

typedef struct bg3_index_entry {
  uint32_t string_offset;
  uint32_t string_len;
  uint32_t match_index;
  uint32_t match_len;
} bg3_index_entry;

typedef struct bg3_index_pak_entry {
  char name[256];
} bg3_index_pak_entry;

typedef struct bg3_index_file_entry {
  uint32_t pak_idx;
  char name[256];
} bg3_index_file_entry;

typedef struct bg3_index_match_entry {
  uint32_t file_idx;
  uint32_t value;
} bg3_index_match_entry;

typedef struct bg3_index_header {
  uint32_t magic;
  uint32_t version;
  uint32_t num_paks;
  uint32_t num_files;
  uint32_t num_entries;
  uint32_t num_matches;
  uint32_t strings_len;
} bg3_index_header;

typedef struct bg3_index_reader {
  bg3_index_header header;
  bg3_index_pak_entry* paks;
  bg3_index_file_entry* files;
  bg3_index_entry* entries;
  bg3_index_match_entry* matches;
  char* strings;
} bg3_index_reader;

typedef struct bg3_index_search_hit {
  bg3_index_pak_entry* pak;
  bg3_index_file_entry* file;
  uint32_t value;
} bg3_index_search_hit;

typedef struct bg3_index_search_results {
  size_t num_hits;
  bg3_index_search_hit* hits;
} bg3_index_search_results;

bg3_status LIBBG3_API bg3_index_reader_init(bg3_index_reader* reader,
                                            char* data,
                                            size_t data_len);
void LIBBG3_API bg3_index_reader_destroy(bg3_index_reader* reader);
bg3_index_entry* LIBBG3_API bg3_index_reader_find_entry(bg3_index_reader* reader,
                                                        uint32_t string_idx);
void bg3_index_reader_query(bg3_index_reader* reader,
                            bg3_index_search_results* results,
                            char const* query);
bg3_status LIBBG3_API bg3_index_build(int argc, char const** argv);
void bg3_index_search_results_destroy(bg3_index_search_results* results);

typedef enum bg3_surface_type {
  bg3_surface_none = 0,
  bg3_surface_water = 1,
  bg3_surface_water_electrified = 2,
  bg3_surface_water_frozen = 3,
  bg3_surface_blood = 4,
  bg3_surface_blood_electrified = 5,
  bg3_surface_blood_frozen = 6,
  bg3_surface_poison = 7,
  bg3_surface_oil = 8,
  bg3_surface_lava = 9,
  bg3_surface_grease = 10,
  bg3_surface_wyvern_poison = 11,
  bg3_surface_web = 12,
  bg3_surface_deep_water = 13,
  bg3_surface_vines = 14,
  bg3_surface_fire = 15,
  bg3_surface_acid = 16,
  bg3_surface_trial_fire = 17,
  bg3_surface_black_powder = 18,
  bg3_surface_shadow_cursed_vines = 19,
  bg3_surface_alien_oil = 20,
  bg3_surface_mud = 21,
  bg3_surface_alcohol = 22,
  bg3_surface_invisible_web = 23,
  bg3_surface_blood_silver = 24,
  bg3_surface_chasm = 25,
  bg3_surface_hellfire = 26,
  bg3_surface_caustic_brine = 27,
  bg3_surface_blood_exploding = 28,
  bg3_surface_ash = 29,
  bg3_surface_spike_growth = 30,
  bg3_surface_holy_fire = 31,
  bg3_surface_black_tentacles = 32,
  bg3_surface_overgrowth = 33,
  bg3_surface_purple_worm_poison = 34,
  bg3_surface_serpent_venom = 35,
  bg3_surface_invisible_gith_acid = 36,
  bg3_surface_blade_barrier = 37,
  bg3_surface_sewer = 38,
  bg3_surface_water_cloud = 39,
  bg3_surface_water_cloud_electrified = 40,
  bg3_surface_poison_cloud = 41,
  bg3_surface_explosion_cloud = 42,
  bg3_surface_shockwave_cloud = 43,
  bg3_surface_cloudkill_cloud = 44,
  bg3_surface_malice_cloud = 45,
  bg3_surface_blood_cloud = 46,
  bg3_surface_stinking_cloud = 47,
  bg3_surface_darkness_cloud = 48,
  bg3_surface_fog_cloud = 49,
  bg3_surface_gith_pheromone_gas_cloud = 50,
  bg3_surface_spore_white_cloud = 51,
  bg3_surface_spore_green_cloud = 52,
  bg3_surface_spore_black_cloud = 53,
  bg3_surface_drow_poison_cloud = 54,
  bg3_surface_ice_cloud = 55,
  bg3_surface_potion_healing_cloud = 56,
  bg3_surface_potion_healing_greater_cloud = 57,
  bg3_surface_potion_healing_superior_cloud = 58,
  bg3_surface_potion_healing_supreme_cloud = 59,
  bg3_surface_potion_invisibility_cloud = 60,
  bg3_surface_potion_speed_cloud = 61,
  bg3_surface_potion_vitality_cloud = 62,
  bg3_surface_potion_antitoxin_cloud = 63,
  bg3_surface_potion_resistance_acid_cloud = 64,
  bg3_surface_potion_resistance_cold_cloud = 65,
  bg3_surface_potion_resistance_fire_cloud = 66,
  bg3_surface_potion_resistance_force_cloud = 67,
  bg3_surface_potion_resistance_lightning_cloud = 68,
  bg3_surface_potion_resistance_poison_cloud = 69,
  bg3_surface_spore_pink_cloud = 70,
  bg3_surface_black_powder_detonation_cloud = 71,
  bg3_surface_void_cloud = 72,
  bg3_surface_crawler_mucus_cloud = 73,
  bg3_surface_cloudkill6_cloud = 74,
} bg3_surface_type;

#define LIBBG3_AIGRID_VERSION 21

// Many of the AI grid state flags are updated dynamically at runtime and their
// stored value doesn't seem to really matter. The ones I know for sure have an
// effect at load time are:
//  - LIBBG3_AIGRID_TILE_SURFACE_{CLOUD, GROUND}_MASK
//  - LIBBG3_AIGRID_TILE_EMPTY
//  - LIBBG3_AIGRID_TILE_MOVEMENT_BLOCKED
//  - LIBBG3_AIGRID_TILE_LIT_SUNLIGHT_ATMOSPHERE

// At load time, tile state is masked to these bits only.
#define LIBBG3_AIGRID_TILE_PERSISTENT_MASK          0xF9BE3FFFFF00F84FULL
#define LIBBG3_AIGRID_TILE_SURFACE_GROUND_SHIFT     24
#define LIBBG3_AIGRID_TILE_SURFACE_CLOUD_SHIFT      32
// surface indices in cloud layer have this offset added automatically
#define LIBBG3_AIGRID_TILE_SURFACE_CLOUD_OFFSET     38
#define LIBBG3_AIGRID_TILE_EMPTY                    0x0000000000000001ULL
#define LIBBG3_AIGRID_TILE_MOVEMENT_BLOCKED_BASE    0x0000000000000002ULL
#define LIBBG3_AIGRID_TILE_MOVEMENT_BLOCKED         0x0000000000000004ULL
#define LIBBG3_AIGRID_TILE_SHOOT_BLOCKED            0x0000000000000008ULL
#define LIBBG3_AIGRID_TILE_BUSY_CHARACTER_WALK      0x0000000000000010ULL
#define LIBBG3_AIGRID_TILE_BUSY_CHARACTER_SHOOT     0x0000000000000020ULL
#define LIBBG3_AIGRID_TILE_CLIMBABLE_STATIC         0x0000000000000040ULL
#define LIBBG3_AIGRID_TILE_BUSY_ITEM_WALK           0x0000000000000080ULL
#define LIBBG3_AIGRID_TILE_BUSY_ITEM_SHOOT          0x0000000000000100ULL
#define LIBBG3_AIGRID_TILE_BUSY_ITEM_SURFACE        0x0000000000000200ULL
#define LIBBG3_AIGRID_TILE_BUSY_ITEM_CLOUD          0x0000000000000400ULL
#define LIBBG3_AIGRID_TILE_SLOPE_STEEP              0x0000000000000800ULL
#define LIBBG3_AIGRID_TILE_BLOCKED_SLOPE            0x0000000000001000ULL
#define LIBBG3_AIGRID_TILE_BLOCKED_PAINTED          0x0000000000002000ULL
#define LIBBG3_AIGRID_TILE_BLOCKED_STATIC           0x0000000000004000ULL
#define LIBBG3_AIGRID_TILE_BLOCKED_UNREACHABLE      0x0000000000008000ULL
#define LIBBG3_AIGRID_TILE_INDESTRUCTIBLE_OBJECT    0x0000000000010000ULL
#define LIBBG3_AIGRID_TILE_CLIMBABLE_DYNAMIC        0x0000000000020000ULL
#define LIBBG3_AIGRID_TILE_TRAP                     0x0000000000040000ULL
#define LIBBG3_AIGRID_TILE_PORTAL_SOURCE            0x0000000000080000ULL
#define LIBBG3_AIGRID_TILE_PORTAL_DESTINATION       0x0000000000100000ULL
#define LIBBG3_AIGRID_TILE_TIMELINE                 0x0000000000200000ULL
#define LIBBG3_AIGRID_TILE_DOOR_WALK                0x0000000000400000ULL
#define LIBBG3_AIGRID_TILE_DOOR_SHOOT               0x0000000000800000ULL
#define LIBBG3_AIGRID_TILE_SURFACE_GROUND_MASK      0x00000000FF000000ULL
#define LIBBG3_AIGRID_TILE_SURFACE_CLOUD_MASK       0x000000FF00000000ULL
#define LIBBG3_AIGRID_TILE_MATERIAL_MASK            0x00003F0000000000ULL
#define LIBBG3_AIGRID_TILE_OBSCURED_LIGHTSOURCE     0x0000400000000000ULL
#define LIBBG3_AIGRID_TILE_LIT_SUNLIGHT_LIGHTSOURCE 0x0000800000000000ULL
#define LIBBG3_AIGRID_TILE_HALF_LIT_LIGHTSOURCE     0x0001000000000000ULL
#define LIBBG3_AIGRID_TILE_LEDGE_STATIC             0x0002000000000000ULL
#define LIBBG3_AIGRID_TILE_LEDGE_NORMAL_NORTH       0x0004000000000000ULL
#define LIBBG3_AIGRID_TILE_LEDGE_NORMAL_EAST        0x0008000000000000ULL
#define LIBBG3_AIGRID_TILE_LEDGE_NORMAL_SOUTH       0x0010000000000000ULL
#define LIBBG3_AIGRID_TILE_LEDGE_NORMAL_WEST        0x0020000000000000ULL
#define LIBBG3_AIGRID_TILE_CHASM                    0x0040000000000000ULL
#define LIBBG3_AIGRID_TILE_SUBGRID_EDGE             0x0080000000000000ULL
#define LIBBG3_AIGRID_TILE_CAN_BE_LIT_SUN           0x0100000000000000ULL
#define LIBBG3_AIGRID_TILE_MULTIPLE_SUBGRIDS        0x0200000000000000ULL
#define LIBBG3_AIGRID_TILE_FULLY_LIT_LIGHTSOURCE    0x0400000000000000ULL
// I'm still not fully clear on the exact mechanics of this flag, but it causes
// the tile's obscurity state to be "Clear" instead of "Heavily Obscured" in my
// test case. I believe the exact result may depend on the lighting system
// behavior however -- the obscurity values it's selecting between seem to come
// from there.
#define LIBBG3_AIGRID_TILE_LIT_SUNLIGHT_ATMOSPHERE  0x0800000000000000ULL
#define LIBBG3_AIGRID_TILE_PAINTED_SURFACE          0x1000000000000000ULL
#define LIBBG3_AIGRID_TILE_PAINTED_CLOUD            0x2000000000000000ULL
#define LIBBG3_AIGRID_TILE_IRREPLACEABLE_SURFACE    0x4000000000000000ULL
#define LIBBG3_AIGRID_TILE_IRREPLACEABLE_CLOUD      0x8000000000000000ULL

typedef struct bg3_aigrid_header {
  uint32_t version;
} bg3_aigrid_header;

typedef struct bg3_aigrid_subgrid_header {
  // this is aigrid_uuid_hash(object_uuid) + some offset that gets added when
  // there's duplicates. not sure how that works yet. I suspect it might be
  // constructed from patch chunk x/y coordinates?
  uint32_t subgrid_id;
  // aigrid tiles are 0.5 meters square, so *2 the number of patch grid tiles
  uint32_t width;
  uint32_t height;
  // x and z are rounded to 0.5 so grid tile positions are aligned.
  float x;
  float y;
  float z;
} bg3_aigrid_subgrid_header;

typedef struct bg3_aigrid_tile {
  uint64_t state;
  // these appear to be quantized: (short)(float_val * 100.0 * 0.5 + 0.5)
  int16_t height;
  int16_t bottom;
  // runtime only, discarded on load.
  int16_t metadata_idx;
  // runtime only, discarded on load.
  int16_t surface;
} bg3_aigrid_tile;

static inline void bg3_aigrid_tile_set_ground_surface(bg3_aigrid_tile* tile,
                                                      bg3_surface_type surface) {
  tile->state &= ~LIBBG3_AIGRID_TILE_SURFACE_GROUND_MASK;
  tile->state |= ((uint64_t)surface << LIBBG3_AIGRID_TILE_SURFACE_GROUND_SHIFT) &
                 LIBBG3_AIGRID_TILE_SURFACE_GROUND_MASK;
}

static inline bg3_surface_type bg3_aigrid_tile_get_ground_surface(bg3_aigrid_tile* tile) {
  return (bg3_surface_type)((tile->state & LIBBG3_AIGRID_TILE_SURFACE_GROUND_MASK) >>
                            LIBBG3_AIGRID_TILE_SURFACE_GROUND_SHIFT);
}

static inline void bg3_aigrid_tile_set_cloud_surface(bg3_aigrid_tile* tile,
                                                     bg3_surface_type surface) {
  if (surface != bg3_surface_none) {
    surface = (bg3_surface_type)(surface - LIBBG3_AIGRID_TILE_SURFACE_CLOUD_OFFSET);
  }
  tile->state &= ~LIBBG3_AIGRID_TILE_SURFACE_CLOUD_MASK;
  tile->state |= ((uint64_t)surface << LIBBG3_AIGRID_TILE_SURFACE_CLOUD_SHIFT) &
                 LIBBG3_AIGRID_TILE_SURFACE_CLOUD_MASK;
}

static inline bg3_surface_type bg3_aigrid_tile_get_cloud_surface(bg3_aigrid_tile* tile) {
  bg3_surface_type surface =
      (bg3_surface_type)((tile->state & LIBBG3_AIGRID_TILE_SURFACE_CLOUD_MASK) >>
                         LIBBG3_AIGRID_TILE_SURFACE_CLOUD_SHIFT);
  if (surface != bg3_surface_none) {
    surface = (bg3_surface_type)(surface + LIBBG3_AIGRID_TILE_SURFACE_CLOUD_OFFSET);
  }
  return surface;
}

typedef struct bg3_aigrid_subgrid {
  bg3_aigrid_subgrid_header header;
  char object_uuid[LIBBG3_UUID_STRING_LEN];
  char template_uuid[LIBBG3_UUID_STRING_LEN];
  bg3_aigrid_tile* tiles;
} bg3_aigrid_subgrid;

typedef struct bg3_aigrid_layer_entry {
  // position of the subgrid tile modified by the layer entry
  uint16_t x;
  uint16_t y;
  uint32_t subgrid_id;
  uint64_t state;
  float height;
  uint32_t unused;  // this is discarded when reading
} bg3_aigrid_layer_entry;

typedef struct bg3_aigrid_layer {
  // do any layers have an id that's not a level template id? other than the
  // first one.
  bg3_uuid level_template;
  bg3_hash lookup;
  uint32_t num_entries;
  uint32_t cap_entries;
  bg3_aigrid_layer_entry* entries;
} bg3_aigrid_layer;

typedef struct bg3_aigrid_file {
  bg3_arena alloc;
  bg3_cursor c;
  bg3_aigrid_header header;
  char file_uuid[LIBBG3_UUID_STRING_LEN];
  uint32_t num_subgrids;
  uint32_t cap_subgrids;
  bg3_aigrid_subgrid* subgrids;
  uint32_t num_layers;
  uint32_t cap_layers;
  bg3_aigrid_layer* layers;
} bg3_aigrid_file;

bg3_status LIBBG3_API bg3_aigrid_file_init(bg3_aigrid_file* file,
                                           char* data,
                                           size_t data_len);
void LIBBG3_API bg3_aigrid_file_init_new(bg3_aigrid_file* file);
void LIBBG3_API bg3_aigrid_file_destroy(bg3_aigrid_file* file);
bg3_aigrid_subgrid* LIBBG3_API bg3_aigrid_file_create_subgrid(bg3_aigrid_file* file,
                                                              uint32_t width,
                                                              uint32_t height,
                                                              bg3_uuid* object_uuid,
                                                              bg3_uuid* template_uuid,
                                                              int16_t tile_x,
                                                              int16_t tile_y,
                                                              bg3_vec3 world_pos);
void LIBBG3_API bg3_aigrid_file_cook_patch(bg3_aigrid_file* file,
                                           bg3_uuid* object_uuid,
                                           bg3_vec3 world_pos,
                                           bg3_patch_file* patch);
bg3_status LIBBG3_API bg3_aigrid_file_write(bg3_aigrid_file* file, char const* path);
void LIBBG3_API bg3_aigrid_file_dump(bg3_aigrid_file* file);

// osiris
#define LIBBG3_OSIRIS_VERSION_MAJOR 1
#define LIBBG3_OSIRIS_VERSION_MINOR 13
#define LIBBG3_OSIRIS_STRING_MASK   0xAD

typedef enum bg3_osiris_prim_type {
  bg3_osiris_prim_type_undef = 0,
  bg3_osiris_prim_type_integer = 1,
  bg3_osiris_prim_type_integer64 = 2,
  bg3_osiris_prim_type_real = 3,
  bg3_osiris_prim_type_string = 4,
  bg3_osiris_prim_type_guidstring = 5,
  bg3_osiris_prim_type_enum = 0xFFFFFFFF,
} bg3_osiris_prim_type;

typedef enum bg3_osiris_function_type : uint8_t {
  bg3_osiris_function_invalid,
  bg3_osiris_function_event = 1,
  bg3_osiris_function_div_query = 2,
  bg3_osiris_function_div_call = 3,
  bg3_osiris_function_db = 4,
  bg3_osiris_function_proc = 5,
  bg3_osiris_function_sys_query = 6,
  bg3_osiris_function_sys_call = 7,
  bg3_osiris_function_query = 8,
} bg3_osiris_function_type;

typedef enum bg3_osiris_compare_op : uint32_t {
  bg3_osiris_compare_less = 0,
  bg3_osiris_compare_less_equal = 1,
  bg3_osiris_compare_greater = 2,
  bg3_osiris_compare_greater_equal = 3,
  bg3_osiris_compare_equal = 4,
  bg3_osiris_compare_not_equal = 5,
} bg3_osiris_compare_op;

typedef enum bg3_osiris_rete_node_type : uint32_t {
  bg3_osiris_rete_node_invalid = 0,
  bg3_osiris_rete_node_db = 1,
  // "events" here include other non-db entry points like procs and queries
  // these "left side" nodes for queries seem to represent the actual
  // definitions of queries and procs, distinct from the "right side" (type 9)
  // query nodes and proc actions in the action list for the terminal node of
  // a production
  bg3_osiris_rete_node_event = 2,
  bg3_osiris_rete_node_div_query = 3,
  bg3_osiris_rete_node_join_and = 4,
  bg3_osiris_rete_node_join_and_not = 5,
  bg3_osiris_rete_node_compare = 6,
  bg3_osiris_rete_node_terminal = 7,
  bg3_osiris_rete_node_sys_query = 8,
  bg3_osiris_rete_node_query = 9,
} bg3_osiris_rete_node_type;

typedef enum bg3_osiris_edge_direction : uint32_t {
  bg3_osiris_edge_direction_none,
  bg3_osiris_edge_direction_left,
  bg3_osiris_edge_direction_right,
} bg3_osiris_edge_direction;

// The lifecycle is a bit odd here.
// sleeping = goal is not active but not completed
// completed = GoalCompleted has been called
// finalised = EXIT section has run
// both not started and completed goals have the suspended flag set.
//
// in a save file, the only observed states are 0, 2, and 7 corresponding to
// active, not started, and completed goals.
typedef enum bg3_osiris_goal_state : uint8_t {
  bg3_osiris_goal_state_active = 0,
  bg3_osiris_goal_state_finalised = 1,
  bg3_osiris_goal_state_sleeping = 2,
  bg3_osiris_goal_state_completed = 4,
} bg3_osiris_goal_state;

// There's a feature in the Osiris save format that does not seem to be used in
// BG3 in which a goal can have multiple parents. The subgoal combiner field on
// the goal determines when the goal is initialized: either when all parent
// goals are completed, or when any of them are.
//
// In practice the combiner is only set to "or" for top level goals which are
// always enabled, but this doesn't matter because the check will always pass
// anyway.
typedef enum bg3_osiris_goal_combiner : uint8_t {
  bg3_osiris_goal_combiner_or = 0,   // initialize if any parent is complete
  bg3_osiris_goal_combiner_and = 1,  // initialize if all parents are complete
} bg3_osiris_goal_combiner;

typedef struct bg3_osiris_type_info {
  char const* name;
  uint8_t index;
  uint8_t alias_index;
  uint8_t enum_index;
} bg3_osiris_type_info;

typedef struct bg3_osiris_enum_entry {
  char* name;
  uint64_t value;
} bg3_osiris_enum_entry;

typedef struct bg3_osiris_enum_info {
  uint8_t index;
  uint32_t num_entries;
  uint32_t cap_entries;
  bg3_osiris_enum_entry* entries;
} bg3_osiris_enum_info;

typedef struct bg3_osiris_variant {
  bg3_osiris_prim_type type;
  uint32_t index;
  union {
    int32_t integer;
    int64_t integer64;
    float real;
    char* string;
  };
} bg3_osiris_variant;

#define LIBBG3_OSIRIS_OUT_PARAM_MASK(i) (1 << ((i & 0xF8) + (7 - (i & 7))))

typedef struct bg3_osiris_function_info {
  bg3_osiris_function_type type;
  char* name;
  uint32_t line;
  uint32_t num_conds;    // shown as 'Cond#' in GenerateFunctionList output
  uint32_t num_actions;  // shown as 'Actions#'
  uint32_t rete_node;
  // 1-3 for DIV event/query/call, values starting at 100 are internal calls
  uint32_t sys_opcode;
  uint32_t unused0;     // never set
  uint32_t div_opcode;  // possibly the opcode for DIV queries/fns?
  // appears to be set to 1 on all event, div query, and div call fns and no
  // others
  uint32_t is_external;
  uint32_t out_mask;
  uint8_t num_params;
  uint8_t cap_params;
  uint16_t* params;
} bg3_osiris_function_info;

typedef struct bg3_osiris_rete_node_edge {
  uint32_t node_id;
  bg3_osiris_edge_direction direction;
  uint32_t goal_id;
} bg3_osiris_rete_node_edge;

// Some of these fields have more specific names than what I've defined here,
// but they seem to be redundant (they can be fully determined from the
// value of other fields). Weird.
typedef struct bg3_osiris_binding {
  uint8_t is_variable;
  uint8_t is_grounded;
  uint8_t unused0;
  // can't be right, but is always equal to is_variable in my data.
  uint8_t is_variable_again;
  uint8_t index;
  // this can't be right, but in my observed data set, these are mutually
  // exclusive and is_dead only appears to be set on rule vars that aren't
  // used.
  uint8_t is_dead;
  uint8_t is_live;
  bg3_osiris_variant value;
} bg3_osiris_binding;

typedef struct bg3_osiris_action {
  char* function;
  uint8_t num_arguments;
  uint8_t cap_arguments;
  bg3_osiris_binding* arguments;
  uint8_t retract;
  uint32_t completed_goal_id;
} bg3_osiris_action;

typedef struct bg3_osiris_rete_node_parent {
  uint32_t node_id;
  uint32_t adaptor;
  // for joins which do not have their own temp db, these reference
  // the nearest parent node which has a db and the child edge which
  // reaches this node.
  uint32_t db_node;
  bg3_osiris_rete_node_edge db_edge;
  // number of edges between this node and the nearest db-having node (the
  // "token generator"). The distance is a bit quirky:
  //   - for a left distance, if no db is in the path to the root, the value is
  //   0
  //   - for a right distance, it's -1 in that case
  //   - when following a left chain, it's the shortest distance considering
  //     the right parents of the left parent chain as well.
  int8_t db_distance;
} bg3_osiris_rete_node_parent;

typedef struct bg3_osiris_rete_node {
  bg3_osiris_rete_node_type type;
  char* name;
  uint32_t node_id;
  uint32_t db;
  uint8_t arity;
  union {
    struct {
      uint32_t num_children;
      uint32_t cap_children;
      bg3_osiris_rete_node_edge* children;
    } trigger;
    struct {
      bg3_osiris_rete_node_edge child;
      bg3_osiris_rete_node_parent left_parent;
      bg3_osiris_rete_node_parent right_parent;
    } join;
    struct {
      bg3_osiris_rete_node_edge child;
      bg3_osiris_rete_node_parent parent;
      bg3_osiris_compare_op opcode;
      bg3_osiris_variant left_value;
      bg3_osiris_variant right_value;
      uint8_t left_var;
      uint8_t right_var;
    } compare;
    struct {
      bg3_osiris_rete_node_edge child;
      bg3_osiris_rete_node_parent parent;
      uint32_t num_actions;
      bg3_osiris_action* actions;
      uint8_t num_vars;
      bg3_osiris_binding* vars;
      uint32_t line;
      uint8_t is_query;
    } terminal;
  };
} bg3_osiris_rete_node;

typedef struct bg3_osiris_rete_adaptor_value {
  uint8_t index;
  bg3_osiris_variant value;
} bg3_osiris_rete_adaptor_value;

typedef struct bg3_osiris_rete_adaptor_pair {
  uint8_t left;
  uint8_t right;
} bg3_osiris_rete_adaptor_pair;

typedef struct bg3_osiris_rete_adaptor {
  uint32_t adaptor_id;
  uint8_t num_values;
  bg3_osiris_rete_adaptor_value* values;
  uint8_t num_vars;
  uint8_t* vars;
  uint8_t num_pairs;
  bg3_osiris_rete_adaptor_pair* pairs;
} bg3_osiris_rete_adaptor;

typedef struct bg3_osiris_row {
  bg3_osiris_variant* columns;
} bg3_osiris_row;

typedef struct bg3_osiris_rete_db {
  uint32_t db_id;
  uint8_t num_schema_columns;
  uint16_t* schema_columns;
  uint32_t num_rows;
  bg3_osiris_row* rows;
} bg3_osiris_rete_db;

typedef struct bg3_osiris_goal {
  uint32_t goal_id;
  uint32_t line;  // only used by osiris_save_builder
  char* name;
  char* unresolved_parent;
  uint32_t parent;
  uint32_t num_children;
  uint32_t cap_children;
  uint32_t* children;
  bg3_osiris_goal_combiner combiner;
  bg3_osiris_goal_state state;
  uint32_t num_init_actions;
  uint32_t cap_init_actions;
  bg3_osiris_action* init_actions;
  uint32_t num_exit_actions;
  uint32_t cap_exit_actions;
  bg3_osiris_action* exit_actions;
} bg3_osiris_goal;

typedef struct bg3_osiris_save {
  bg3_arena alloc;
  bg3_buffer out;
  bg3_indent_buffer text_out;
  bg3_cursor c;
  uint8_t string_mask;
  char* version;
  uint8_t version_major;
  uint8_t version_minor;
  uint8_t is_big_endian;
  uint8_t unk0;
  char story_version[0x80];
  uint32_t debug_flags;
  uint32_t cap_type_infos;
  uint32_t num_type_infos;
  bg3_osiris_type_info* type_infos;
  uint32_t cap_enums;
  uint32_t num_enums;
  bg3_osiris_enum_info* enums;
  uint32_t num_div_objects;  // always 0 in BG3 afaict
  uint32_t cap_functions;
  uint32_t num_functions;
  bg3_osiris_function_info* functions;
  uint32_t cap_rete_nodes;
  uint32_t num_rete_nodes;
  bg3_osiris_rete_node* rete_nodes;
  // yes, it's consistently misspelled..
  uint32_t cap_rete_adaptors;
  uint32_t num_rete_adaptors;
  bg3_osiris_rete_adaptor* rete_adaptors;
  uint32_t cap_dbs;
  uint32_t num_dbs;
  bg3_osiris_rete_db* dbs;
  uint32_t cap_goals;
  uint32_t num_goals;
  bg3_osiris_goal* goals;
  uint32_t num_global_actions;
  bg3_osiris_action* global_actions;
} bg3_osiris_save;

void LIBBG3_API bg3_osiris_save_destroy(bg3_osiris_save* reader);
void LIBBG3_API bg3_osiris_save_init(bg3_osiris_save* reader);
bg3_status LIBBG3_API bg3_osiris_save_init_binary(bg3_osiris_save* reader,
                                                  char* data,
                                                  size_t data_len);
bg3_status LIBBG3_API bg3_osiris_save_write_binary(bg3_osiris_save* save,
                                                   char const* path);
bg3_status LIBBG3_API bg3_osiris_save_write_sexp(bg3_osiris_save* save,
                                                 char const* path,
                                                 bool verbose);

#define LIBBG3_OSIRIS_MAX_LOCALS 32

typedef struct bg3_osiris_save_builder {
  bg3_osiris_save save;
  bg3_hash global_symbols;
  bg3_hash local_symbols;
  bg3_sexp_token current_toplevel;
  bg3_sexp_token current_item;
  uint32_t current_goal_id;
  bg3_osiris_binding current_vars[LIBBG3_OSIRIS_MAX_LOCALS];
  uint32_t next_var;
} bg3_osiris_save_builder;

void LIBBG3_API bg3_osiris_save_builder_init(bg3_osiris_save_builder* builder);
void LIBBG3_API bg3_osiris_save_builder_destroy(bg3_osiris_save_builder* builder);
bg3_status LIBBG3_API bg3_osiris_save_builder_parse(bg3_osiris_save_builder* builder,
                                                    char* data,
                                                    size_t data_len);
bg3_status LIBBG3_API bg3_osiris_save_builder_finish(bg3_osiris_save_builder* builder);

#ifdef __cplusplus
}
#endif

#ifdef LIBBG3_IMPLEMENTATION
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <locale.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if LIBBG3_CONFIG_ENABLE_BCDEC
#include "bcdec.h"
#endif

#include "lz4.h"
#include "lz4frame.h"
#include "miniz.h"
#include "xxhash.h"

#ifdef LIBBG3_PLATFORM_MACOS
#include <arm_neon.h>
#include <sys/sysctl.h>
#endif

// utilities

#define LIBBG3_CHECK(x, panic_msg) \
  do {                             \
    if (!(x)) {                    \
      bg3_panic(panic_msg);        \
    }                              \
  } while (0)

static inline uint32_t bg3__next_power_of_2(uint32_t v) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  return v;
}

static inline float bg3__clampf(float x, float lo, float hi) {
  return LIBBG3_MAX(lo, LIBBG3_MIN(x, hi));
}

static inline float bg3__smoothstepf(float edge0, float edge1, float x) {
  x = bg3__clampf((x - edge0) / (edge1 - edge0), 0.0f, 1.0f);
  return x * x * (3.0f - 2.0f * x);
}

static bg3_log_level g_bg3_log_level = bg3_log_level_error;

void bg3_set_log_level(bg3_log_level level) {
  g_bg3_log_level = level;
}

void bg3_log_vprintf(bg3_log_level level, char const* format, va_list ap) {
  if (level <= g_bg3_log_level) {
    vfprintf(stderr, format, ap);
  }
}

void __attribute__((format(printf, 1, 2))) bg3_info(char const* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  bg3_log_vprintf(bg3_log_level_info, fmt, ap);
  va_end(ap);
}

void __attribute__((format(printf, 1, 2))) bg3_error(char const* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  bg3_log_vprintf(bg3_log_level_error, fmt, ap);
  va_end(ap);
}

void __attribute__((noreturn)) bg3_panic(char const* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  bg3_log_vprintf(bg3_log_level_panic, fmt, ap);
  fprintf(stderr, "\nabort, retry, fail?\n");
  va_end(ap);
  abort();
}

static void uuid_random(bg3_uuid* id) {
  arc4random_buf(id, sizeof(bg3_uuid));
}

static bool uuid_parse(bg3_uuid* id, char const* buf) {
  return 7 == sscanf(buf, "%08x-%04hx-%04hx-%04hx-%04hx%04hx%04hx\n", &id->word,
                     &id->half[0], &id->half[1], &id->half[2], &id->half[3], &id->half[4],
                     &id->half[5]);
}

#ifdef LIBBG3_PLATFORM_MACOS
void bg3_uuid_to_string_neon(bg3_uuid const* id, char out[48]) {
  static const uint8_t hex_table[17] = "0123456789abcdef";
  static const uint8_t shuffle0[16] = {
      6, 7, 4, 5, 2, 3, 0, 1, 10, 11, 8, 9, 14, 15, 12, 13,
  };
  static const uint8_t shuffle1[16] = {
      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
  };
  static const uint8_t dashuf0[16] = {
      0, 1, 2, 3, 4, 5, 6, 7, 15, 8, 9, 10, 11, 15, 12, 13,
  };
  static const uint8_t dashuf1[16] = {
      0, 1, 15, 2, 3, 4, 5, 15, 6, 7, 8, 9, 10, 11, 12, 13,
  };
  static const uint8_t dashuf2[16] = {
      12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  uint8x16_t data = vld1q_u8((uint8_t const*)id);
  uint8x16_t digits_lo = vandq_u8(data, vmovq_n_u8(0x0F));
  uint8x16_t digits_hi = vshrq_n_u8(vandq_u8(data, vmovq_n_u8(0xF0)), 4);
  uint8x16_t ascii_lo = vqtbl1q_u8(vld1q_u8(hex_table), digits_lo);
  uint8x16_t ascii_hi = vqtbl1q_u8(vld1q_u8(hex_table), digits_hi);
  uint8x16_t zip_left = vzip1q_u8(ascii_hi, ascii_lo);
  uint8x16_t zip_right = vzip2q_u8(ascii_hi, ascii_lo);
  uint8x16_t ascii_left = vqtbl1q_u8(zip_left, vld1q_u8(shuffle0));
  uint8x16_t ascii_right = vqtbl1q_u8(zip_right, vld1q_u8(shuffle1));
  uint8x16_t dashed_left =
      vqtbl1q_u8(vsetq_lane_u8('-', ascii_left, 15), vld1q_u8(dashuf0));
  uint8x16_t dashed_mid = vqtbl1q_u8(
      vsetq_lane_u8('-', vextq_u8(ascii_left, ascii_right, 14), 15), vld1q_u8(dashuf1));
  uint8x16_t dashed_right =
      vqtbl1q_u8(vsetq_lane_u8(0, ascii_right, 0), vld1q_u8(dashuf2));
  vst1q_u8((uint8_t*)out, dashed_left);
  vst1q_u8((uint8_t*)out + 16, dashed_mid);
  vst1q_u8((uint8_t*)out + 32, dashed_right);
}

void bg3_uuid_to_string(bg3_uuid const* id, char out[48]) {
  bg3_uuid_to_string_neon(id, out);
}
#else  // LIBBG3_PLATFORM_MACOS
void bg3_uuid_to_string(bg3_uuid const* id, char out[48]) {
  memset(out, 0, 48);
  snprintf(out, 48, "%08x-%04hx-%04hx-%04hx-%04hx%04hx%04hx\n", id->word, id->half[0],
           id->half[1], id->half[2], id->half[3], id->half[4], id->half[5]);
}
#endif

#define MATCH(ty)                                                               \
  do {                                                                          \
    if (l->next.type != bg3_sexp_token_type_##ty) {                             \
      fprintf(stderr, "expected token " #ty " but got %d instead on line %d\n", \
              l->next.type, l->next.line);                                      \
      return bg3_error_failed;                                                  \
    }                                                                           \
  } while (0)
#define SLURP(type)            \
  do {                         \
    MATCH(type);               \
    bg3_sexp_lexer_advance(l); \
  } while (0)

bg3_status bg3_mapped_file_init_ro(bg3_mapped_file* file, char const* path) {
  file->fd = open(path, O_RDONLY);
  if (file->fd < 0) {
    return bg3_error_libc;
  }
  off_t file_size = lseek(file->fd, 0, SEEK_END);
  if (file_size < 0) {
    close(file->fd);
    return bg3_error_libc;
  }
  file->data_len = file_size;
  // map writable to allow copy on write modifications in memory.
  file->data =
      (char*)mmap(0, file->data_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, file->fd, 0);
  if (file->data == MAP_FAILED) {
    close(file->fd);
    return bg3_error_libc;
  }
  return bg3_success;
}

bg3_status mapped_file_init_rw(bg3_mapped_file* file, char const* path) {
  file->fd = open(path, O_RDWR);
  if (file->fd < 0) {
    return bg3_error_libc;
  }
  off_t file_size = lseek(file->fd, 0, SEEK_END);
  if (file_size < 0) {
    close(file->fd);
    return bg3_error_libc;
  }
  file->data_len = file_size;
  file->data =
      (char*)mmap(0, file->data_len, PROT_READ | PROT_WRITE, MAP_SHARED, file->fd, 0);
  if (file->data == MAP_FAILED) {
    close(file->fd);
    return bg3_error_libc;
  }
  return bg3_success;
}

bg3_status bg3_mapped_file_init_rw_trunc(bg3_mapped_file* file,
                                         char const* path,
                                         size_t new_size) {
  file->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (file->fd < 0) {
    return bg3_error_libc;
  }
  if (ftruncate(file->fd, new_size) < 0) {
    close(file->fd);
    return bg3_error_libc;
  }
  file->data_len = new_size;
  if (file->data_len > 0) {
    file->data =
        (char*)mmap(0, file->data_len, PROT_READ | PROT_WRITE, MAP_SHARED, file->fd, 0);
    if (file->data == MAP_FAILED) {
      close(file->fd);
      return bg3_error_libc;
    }
  } else {
    file->data = 0;
  }
  return bg3_success;
}

void bg3_mapped_file_destroy(bg3_mapped_file* file) {
  if (file->data) {
    munmap(file->data, file->data_len);
  }
  close(file->fd);
}

bg3_status bg3_mapped_file_read(bg3_mapped_file* file,
                                void* dest,
                                size_t offset,
                                size_t len) {
  if (offset > file->data_len || len > file->data_len - offset) {
    return bg3_error_overflow;
  }
  memcpy(dest, file->data + offset, len);
  return bg3_success;
}

static void* do_parallel_for(void* arg) {
  bg3_parallel_for_thread* tcb = (bg3_parallel_for_thread*)arg;
  tcb->status = tcb->callback(tcb);
  return 0;
}

static int ncpu = 1;
void __attribute__((constructor)) parallel_for_init() {
  ncpu = sysconf(_SC_NPROCESSORS_ONLN);
}

int bg3_parallel_for_ncpu() {
  return ncpu;
}

int bg3_parallel_for_n(bg3_parallel_for_cb* callback, void* user_data, int nthreads) {
  bg3_parallel_for_sync sync = {};
  bg3_parallel_for_thread* tcb =
      (bg3_parallel_for_thread*)alloca(sizeof(bg3_parallel_for_thread) * nthreads);
  if (pthread_cond_init(&sync.cond, 0)) {
    bg3_panic("pthread_cond_init failed");
  }
  if (pthread_mutex_init(&sync.mutex, 0)) {
    bg3_panic("pthread_mutex_init failed");
  }
  for (int i = 0; i < nthreads; ++i) {
    tcb[i].thread_num = i;
    tcb[i].thread_count = nthreads;
    tcb[i].status = 0;
    tcb[i].callback = callback;
    tcb[i].user_data = user_data;
    tcb[i].sync = &sync;
    pthread_create(&tcb[i].thread, 0, do_parallel_for, &tcb[i]);
  }
  for (int i = 0; i < nthreads; ++i) {
    pthread_join(tcb[i].thread, 0);
  }
  pthread_cond_destroy(&sync.cond);
  pthread_mutex_destroy(&sync.mutex);
  for (int i = 0; i < nthreads; ++i) {
    if (tcb[i].status != 0) {
      return tcb[i].status;
    }
  }
  return 0;
}

int bg3_parallel_for(bg3_parallel_for_cb* callback, void* user_data) {
  return bg3_parallel_for_n(callback, user_data, ncpu);
}

static void sync_threads0(bg3_parallel_for_thread* tcb, int* count) {
  pthread_mutex_lock(&tcb->sync->mutex);
  *count = (*count + 1) % tcb->thread_count;
  if (!*count) {
    pthread_mutex_unlock(&tcb->sync->mutex);
    pthread_cond_broadcast(&tcb->sync->cond);
  } else {
    while (*count) {
      pthread_cond_wait(&tcb->sync->cond, &tcb->sync->mutex);
    }
    pthread_mutex_unlock(&tcb->sync->mutex);
  }
}

void bg3_sync_threads(bg3_parallel_for_thread* tcb) {
  sync_threads0(tcb, &tcb->sync->gate_enter);
  sync_threads0(tcb, &tcb->sync->gate_exit);
}

void bg3_buffer_hexdump(bg3_buffer* buf, size_t base, void* ptr, size_t length) {
  size_t line = 0;
  while (line < length) {
    int line_len = LIBBG3_MIN(16, length - line);
    bg3_buffer_printf(buf, "%08zX: ", base + line);
    for (size_t i = line; i < line + line_len; ++i) {
      bg3_buffer_printf(buf, "%02X ", ((uint8_t*)ptr)[i]);
    }
    bg3_buffer_printf(buf, "    ");
    for (size_t i = line; i < line + line_len; ++i) {
      char chr = ((char*)ptr)[i];
      bg3_buffer_printf(buf, "%c", isprint(chr) ? chr : '.');
    }
    bg3_buffer_putchar(buf, '\n');
    line += line_len;
  }
}

void bg3_hex_dump(void* ptr, size_t length) {
  size_t line = 0;
  while (line < length) {
    int line_len = 16;
    if (line_len > length - line) {
      line_len = length - line;
    }
    printf("%08zX: ", line);
    for (size_t i = line; i < line + line_len; ++i) {
      printf("%02X ", ((uint8_t*)ptr)[i]);
    }
    printf("    ");
    for (size_t i = line; i < line + line_len; ++i) {
      char chr = ((char*)ptr)[i];
      printf("%c", isprint(chr) ? chr : '.');
    }
    puts("");
    line += line_len;
  }
}

bool bg3_strcasesuffix(char const* str, char const* suffix) {
  size_t len = strlen(str);
  size_t suf_len = strlen(suffix);
  if (len < suf_len) {
    return false;
  }
  char const* str_suffix = str + len - suf_len;
  return !strcasecmp(str_suffix, suffix);
}

// world's shittiest hash table. open addressing with double hash probing.
// tries to stay under 70% load. does not shrink itself atm.

uint64_t bg3_hash_default_hash_fn(void* key, void* user_data) {
  return XXH64(&key, sizeof(void*), 0);  // hash the pointer
}

bool bg3_hash_default_equal_fn(void* lhs, void* rhs, void* user_data) {
  return lhs == rhs;
}

void* bg3_hash_default_copy_fn(void* value, void* user_data) {
  return value;
}

void bg3_hash_default_free_fn(void* value, void* user_data) {
  // no-op
}

const bg3_hash_ops bg3_default_hash_ops = {
    .hash_fn = bg3_hash_default_hash_fn,
    .equal_fn = bg3_hash_default_equal_fn,
    .copy_key_fn = bg3_hash_default_copy_fn,
    .free_key_fn = bg3_hash_default_free_fn,
    .copy_value_fn = bg3_hash_default_copy_fn,
    .free_value_fn = bg3_hash_default_free_fn,
};

void bg3_hash_init(bg3_hash* table, bg3_hash_ops const* ops, void* user_data) {
  memset(table, 0, sizeof(bg3_hash));
  table->ops = ops;
  table->user_data = user_data;
}

void bg3_hash_destroy(bg3_hash* table) {
  bg3_hash_clear(table);
  if (table->entries) {
    free(table->entries);
  }
}

bool bg3_hash_try_set(bg3_hash* table, void* key, void* value, bg3_hash_entry** entry) {
  if (key == LIBBG3_HASH_EMPTY_VALUE || key == LIBBG3_HASH_TOMBSTONE_VALUE) {
    bg3_panic("attempt to set reserved hash key");
  }
  *entry = 0;
  uint64_t hash0 = table->ops->hash_fn(key, table->user_data) & ~1ULL;
  uint64_t hash1 = hash0 | 1;
  if (!table->table_size) {
    table->table_size = 8;
    table->entries = (bg3_hash_entry*)malloc(sizeof(bg3_hash_entry) * table->table_size);
    for (size_t i = 0; i < table->table_size; ++i) {
      table->entries[i] = (bg3_hash_entry){.key = LIBBG3_HASH_EMPTY_VALUE, .value = 0};
    }
  }
  bool rehashed;
  do {
    uint64_t mask = table->table_size - 1;
    uint64_t addr = hash0 & mask, start_addr = addr;
    bool found_new = false;
    bool found_old = false;
    bool needs_to_grow = false;
    rehashed = false;
    do {
      bg3_hash_entry* e = table->entries + addr;
      if (e->key == LIBBG3_HASH_EMPTY_VALUE || e->key == LIBBG3_HASH_TOMBSTONE_VALUE) {
        found_new = true;
        break;
      } else if (table->ops->equal_fn(e->key, key, table->user_data)) {
        found_old = true;
        break;
      }
      addr = (addr + hash1) & mask;
    } while (addr != start_addr);
    bg3_hash_entry* probed = table->entries + addr;
    if (found_old) {
      *entry = probed;
      return false;
    } else if (found_new) {
      size_t load_factor = table->num_keys * 100 / table->table_size;
      if (load_factor >= 70) {
        needs_to_grow = true;
      } else {
        table->num_keys++;
        *entry = probed;
        probed->key = table->ops->copy_key_fn(key, table->user_data);
        probed->value = table->ops->copy_value_fn(value, table->user_data);
      }
    } else {
      needs_to_grow = true;
    }
    if (needs_to_grow) {
      size_t new_size = table->table_size << 1;
      if (new_size < table->table_size) {
        bg3_panic("hash too big");
      }
      bg3_hash_entry* new_entries =
          (bg3_hash_entry*)malloc(new_size * sizeof(bg3_hash_entry));
      for (size_t i = 0; i < new_size; ++i) {
        new_entries[i] = (bg3_hash_entry){.key = LIBBG3_HASH_EMPTY_VALUE, .value = 0};
      }
      mask = new_size - 1;
      for (size_t i = 0; i < table->table_size; ++i) {
        bg3_hash_entry* old_e = table->entries + i;
        if (old_e->key == LIBBG3_HASH_EMPTY_VALUE ||
            old_e->key == LIBBG3_HASH_TOMBSTONE_VALUE) {
          continue;
        }
        uint64_t rehash0 = table->ops->hash_fn(old_e->key, table->user_data) & ~1ULL;
        uint64_t rehash1 = rehash0 | 1;
        addr = rehash0 & mask;
        start_addr = addr;
        bool found_slot = false;
        do {
          bg3_hash_entry* e = new_entries + addr;
          if (e->key == LIBBG3_HASH_EMPTY_VALUE) {
            found_slot = true;
            break;
          }
          addr = (addr + rehash1) & mask;
        } while (addr != start_addr);
        assert(found_slot && "rehash probe failed");
        new_entries[addr] = *old_e;
      }
      free(table->entries);
      table->entries = new_entries;
      table->table_size = new_size;
      rehashed = true;
    }
  } while (rehashed);
  return true;
}

void bg3_hash_set(bg3_hash* table, void* key, void* value) {
  bg3_hash_entry* entry;
  if (!bg3_hash_try_set(table, key, value, &entry)) {
    table->ops->free_value_fn(entry->value, table->user_data);
    entry->value = table->ops->copy_value_fn(value, table->user_data);
  }
}

bg3_hash_entry* bg3_hash_get_entry(bg3_hash* table, void* key) {
  if (key == LIBBG3_HASH_EMPTY_VALUE || key == LIBBG3_HASH_TOMBSTONE_VALUE) {
    bg3_panic("attempt to get reserved hash key");
  }
  if (!table->table_size) {
    return 0;
  }
  uint64_t hash0 = table->ops->hash_fn(key, table->user_data) & ~1ULL;
  uint64_t hash1 = hash0 | 1;
  uint64_t mask = table->table_size - 1;
  uint64_t addr = hash0 & mask, start_addr = addr;
  do {
    bg3_hash_entry* e = table->entries + addr;
    if (e->key == LIBBG3_HASH_EMPTY_VALUE) {
      return 0;
    } else if (e->key == LIBBG3_HASH_TOMBSTONE_VALUE) {
      continue;
    } else if (table->ops->equal_fn(e->key, key, table->user_data)) {
      return e;
    }
    addr = (addr + hash1) & mask;
  } while (addr != start_addr);
  return 0;
}

bool bg3_hash_delete(bg3_hash* table, void* key) {
  bg3_hash_entry* entry = bg3_hash_get_entry(table, key);
  if (entry) {
    table->ops->free_key_fn(entry->key, table->user_data);
    table->ops->free_value_fn(entry->value, table->user_data);
    entry->key = LIBBG3_HASH_TOMBSTONE_VALUE;
    entry->value = 0;
    table->num_keys--;
    return true;
  }
  return false;
}

void bg3_hash_clear(bg3_hash* table) {
  for (size_t i = 0; i < table->table_size; ++i) {
    bg3_hash_entry* e = table->entries + i;
    if (e->key != LIBBG3_HASH_EMPTY_VALUE && e->key != LIBBG3_HASH_TOMBSTONE_VALUE) {
      table->ops->free_key_fn(e->key, table->user_data);
      table->ops->free_value_fn(e->value, table->user_data);
    }
    e->key = LIBBG3_HASH_EMPTY_VALUE;
    e->value = 0;
  }
  table->num_keys = 0;
}

static uint64_t symtab_hash_fn(void* key, void* user_data) {
  size_t len = LIBBG3_MIN(strlen((char*)key), 64);
  char* buf = (char*)alloca(len);
  for (size_t i = 0; i < len; ++i) {
    buf[i] = tolower(((char*)key)[i]);
  }
  return XXH64(buf, len, 0);
}

static bool symtab_equal_fn(void* lhs, void* rhs, void* user_data) {
  return !strcasecmp((char const*)lhs, (char const*)rhs);
}

static void* symtab_copy_fn(void* value, void* user_data) {
  return bg3_arena_strdup((bg3_arena*)user_data, (char const*)value);
}

static void symtab_free_fn(void* value, void* user_data) {
  // do nothing
}

const bg3_hash_ops bg3_symtab_hash_ops = {
    .hash_fn = symtab_hash_fn,
    .equal_fn = symtab_equal_fn,
    .copy_key_fn = symtab_copy_fn,
    .free_key_fn = symtab_free_fn,
    .copy_value_fn = bg3_hash_default_copy_fn,
    .free_value_fn = bg3_hash_default_free_fn,
};

static uint64_t symtab_case_hash_fn(void* key, void* user_data) {
  size_t len = LIBBG3_MIN(strlen((char const*)key), 64);
  return XXH64(key, len, 0);
}

static bool symtab_case_equal_fn(void* lhs, void* rhs, void* user_data) {
  return !strcmp((char const*)lhs, (char const*)rhs);
}

const bg3_hash_ops bg3_symtab_case_hash_ops = {
    .hash_fn = symtab_case_hash_fn,
    .equal_fn = symtab_case_equal_fn,
    .copy_key_fn = symtab_copy_fn,
    .free_key_fn = symtab_free_fn,
    .copy_value_fn = bg3_hash_default_copy_fn,
    .free_value_fn = bg3_hash_default_free_fn,
};

void bg3_arena_init(bg3_arena* a, size_t chunk_size, size_t max_waste) {
  memset(a, 0, sizeof(bg3_arena));
  a->chunk_size = chunk_size;
  a->max_waste = max_waste;
}

void bg3_arena_destroy(bg3_arena* a) {
  for (bg3_arena_chunk* chunk = a->chunks; chunk;) {
    bg3_arena_chunk* prev = chunk;
    chunk = chunk->next;
    free(prev);
  }
  for (bg3_arena_chunk* chunk = a->full_chunks; chunk;) {
    bg3_arena_chunk* prev = chunk;
    chunk = chunk->next;
    free(prev);
  }
}

void* bg3_arena_alloc(bg3_arena* a, size_t size) {
  if (size & 7) {
    size += 8 - (size & 7);
  }
retry:
  for (bg3_arena_chunk *chunk = a->chunks, *prev = 0; chunk;
       prev = chunk, chunk = chunk->next) {
    size_t avail = chunk->end - chunk->bump;
    if (avail >= size) {
      void* result = chunk->bump;
      chunk->bump += size;
      avail -= size;
      if (avail < a->max_waste) {
        if (prev) {
          prev->next = chunk->next;
        } else {
          a->chunks = chunk->next;
        }
        chunk->next = a->full_chunks;
        a->full_chunks = chunk;
      }
      return result;
    }
  }
  size_t chunk_size = LIBBG3_MAX(size, a->chunk_size);
  bg3_arena_chunk* new_chunk =
      (bg3_arena_chunk*)malloc(sizeof(bg3_arena_chunk) + chunk_size);
  new_chunk->bump = (char*)(new_chunk + 1);
  new_chunk->end = new_chunk->bump + chunk_size;
  new_chunk->next = a->chunks;
  a->chunks = new_chunk;
  goto retry;
}

char* bg3_arena_strdup(bg3_arena* a, char const* str) {
  size_t len = strlen(str) + 1;
  char* result = (char*)bg3_arena_alloc(a, len);
  memcpy(result, str, len);
  return result;
}

char* bg3_arena_sprintf(bg3_arena* a, char const* format, ...) {
  va_list ap;
  va_start(ap, format);
  va_list ap_tmp;
  va_copy(ap_tmp, ap);
  size_t needed = 1 + vsnprintf(0, 0, format, ap_tmp);
  va_end(ap_tmp);
  char* result = (char*)bg3_arena_alloc(a, needed);
  vsnprintf(result, needed, format, ap);
  va_end(ap);
  return result;
}

static const char* bg3_lsof_dt_names[] = {
    "none",
    "uint8",
    "int16",
    "uint16",
    "int32",
    "uint32",
    "float",
    "double",
    "ivec2",
    "ivec3",
    "ivec4",
    "vec2",
    "vec3",
    "vec4",
    "mat2",
    "mat3",
    "mat3x4",
    "mat4x3",
    "mat4",
    "bool",
    "string",
    "path",
    "fixedstring",
    "lsstring",
    "uint64",
    "scratchbuffer",
    "long",
    "int8",
    "translatedstring",
    "wstring",
    "lswstring",
    "uuid",
    "int64",
    "translatedfsstring",
};

static inline char const* bg3_lsof_dt_name(int dt) {
  if (dt < 0 || dt > bg3_lsof_dt_last) {
    return "unknown";
  }
  return bg3_lsof_dt_names[dt];
}

bg3_status bg3_lspk_file_init(bg3_lspk_file* file, bg3_mapped_file* mapped) {
  bg3_cursor c;
  bg3_cursor_init(&c, mapped->data, mapped->data_len);
  memset(file, 0, sizeof(bg3_lspk_file));
  file->mapped = mapped;
  if (mapped->data_len < sizeof(bg3_lspk_header)) {
    return bg3_error_bad_magic;
  }
  bg3_cursor_read(&c, &file->header, sizeof(bg3_lspk_header));
  if (file->header.magic != LIBBG3_LSPK_MAGIC) {
    return bg3_error_bad_magic;
  }
  if (file->header.version != LIBBG3_LSPK_VERSION) {
    return bg3_error_bad_version;
  }
  if (!file->header.num_parts) {
    bg3_panic("pak file invariant violated: num_parts > 0");
  }
  bg3_lspk_manifest_header manifest_header;
  bg3_cursor_init(&c, mapped->data + file->header.manifest_offset,
                  mapped->data_len - file->header.manifest_offset);
  bg3_cursor_read(&c, &manifest_header, sizeof(bg3_lspk_manifest_header));
  size_t uncompressed_size = manifest_header.num_files * sizeof(bg3_lspk_manifest_entry);
  bg3_lspk_manifest_entry* entries = (bg3_lspk_manifest_entry*)malloc(uncompressed_size);
  if (LZ4_decompress_safe(
          mapped->data + file->header.manifest_offset + sizeof(bg3_lspk_manifest_header),
          (char*)entries, manifest_header.compressed_size, uncompressed_size) < 0) {
    bg3_error("failed to decompress manifest\n");
    free(entries);
    return bg3_error_failed;
  }
  file->parts = (bg3_lspk_part*)calloc(file->header.num_parts, sizeof(bg3_lspk_part));
  file->parts[0] = (bg3_lspk_part){mapped->data, mapped->data_len};
  file->num_files = manifest_header.num_files;
  file->manifest = entries;
  return bg3_success;
}

bg3_status bg3_lspk_file_attach_part(bg3_lspk_file* file,
                                     size_t part_num,
                                     char* data,
                                     size_t data_len) {
  if (part_num >= file->header.num_parts) {
    return bg3_error_overflow;
  }
  if (part_num == 0) {
    return bg3_error_failed;
  }
  file->parts[part_num] = (bg3_lspk_part){data, data_len};
  return bg3_success;
}

void bg3_lspk_file_destroy(bg3_lspk_file* file) {
  free(file->manifest);
  free(file->parts);
}

bg3_status bg3_lspk_file_extract(bg3_lspk_file* file,
                                 bg3_lspk_manifest_entry* entry,
                                 char* dest,
                                 size_t* dest_len) {
  size_t avail_len = *dest_len;
  size_t entry_offset = ((size_t)entry->offset_hi << 32) | entry->offset_lo;
  if (entry->part_num >= file->header.num_parts) {
    return bg3_error_overflow;
  }
  if (!file->parts[entry->part_num].data) {
    return bg3_error_failed;
  }
  char* entry_data = file->parts[entry->part_num].data + entry_offset;
  // TODO: bounds checking
  switch (LIBBG3_LSPK_ENTRY_COMPRESSION_METHOD(entry->compression)) {
    case LIBBG3_LSPK_ENTRY_COMPRESSION_ZLIB: {
      unsigned long src_len = entry->compressed_size, need_len = entry->uncompressed_size;
      *dest_len = need_len;
      if (avail_len < need_len) {
        return bg3_error_overflow;
      }
      if (mz_uncompress2((unsigned char*)dest, &need_len, (unsigned char*)entry_data,
                         &src_len) != 0) {
        return bg3_error_failed;
      }
      break;
    }
    case LIBBG3_LSPK_ENTRY_COMPRESSION_LZ4:
      *dest_len = entry->uncompressed_size;
      if (avail_len < entry->uncompressed_size) {
        return bg3_error_overflow;
      }
      if (LZ4_decompress_safe(entry_data, dest, entry->compressed_size,
                              entry->uncompressed_size) < 0) {
        return bg3_error_failed;
      }
      break;
    default:
      *dest_len = entry->compressed_size;
      if (avail_len < entry->compressed_size) {
        return bg3_error_overflow;
      }
      memcpy(dest, entry_data, entry->compressed_size);
      break;
  }
  return bg3_success;
}

void bg3_lsof_symtab_init(bg3_lsof_symtab* table, int num_buckets) {
  memset(table, 0, sizeof(bg3_lsof_symtab));
  table->num_buckets = num_buckets;
  table->is_writable = true;
  table->buckets =
      (bg3_lsof_symtab_bucket*)calloc(num_buckets, sizeof(bg3_lsof_symtab_bucket));
}

void bg3_lsof_symtab_init_data(bg3_lsof_symtab* table, char* ptr, size_t length) {
  uint16_t num_buckets;
  bg3_cursor c;
  bg3_cursor_init(&c, ptr, length);
  bg3_cursor_read(&c, &num_buckets, sizeof(uint16_t));
  table->num_buckets = num_buckets;
  table->is_writable = false;
  table->buckets =
      (bg3_lsof_symtab_bucket*)calloc(num_buckets, sizeof(bg3_lsof_symtab_bucket));
  // lslib says this is the upper bits of a 32bit bucket count
  // but that makes no sense because there's no way to address
  // a bucket past 16bits in the other tables.
  bg3_cursor_read(&c, 0, sizeof(uint16_t));
  for (int bucket = 0; bucket < num_buckets; ++bucket) {
    uint16_t num_entries;
    bg3_cursor_read(&c, &num_entries, sizeof(uint16_t));
    table->buckets[bucket].num_entries = num_entries;
    table->buckets[bucket].entries =
        (bg3_lsof_symtab_entry*)calloc(num_entries, sizeof(bg3_lsof_symtab_entry));
    for (int entry = 0; entry < num_entries; ++entry) {
      uint16_t length;
      bg3_cursor_read(&c, &length, sizeof(uint16_t));
      table->buckets[bucket].entries[entry].length = length;
      table->buckets[bucket].entries[entry].data = c.ptr;
      bg3_cursor_read(&c, 0, length);
    }
  }
}

void bg3_lsof_symtab_destroy(bg3_lsof_symtab* table) {
  for (int i = 0; i < table->num_buckets; ++i) {
    bg3_lsof_symtab_bucket* bucket = &table->buckets[i];
    for (int j = 0; j < bucket->num_entries; ++j) {
      bg3_lsof_symtab_entry* entry = &bucket->entries[j];
      if (table->is_writable) {
        free(entry->data);
      }
      if (entry->c_str) {
        free(entry->c_str);
      }
    }
    free(bucket->entries);
  }
  free(table->buckets);
}

bg3_lsof_symtab_entry* bg3_lsof_symtab_get_ref(bg3_lsof_symtab* table,
                                               bg3_lsof_sym_ref ref) {
  if (ref.bucket >= table->num_buckets) {
    bg3_panic("invalid bucket (%04X, %04X)\n", (int)ref.bucket, (int)ref.entry);
  }
  bg3_lsof_symtab_bucket* bucket = &table->buckets[ref.bucket];
  if (ref.entry >= bucket->num_entries) {
    bg3_panic("invalid entry (%04X, %04X)\n", (int)ref.bucket, (int)ref.entry);
  }
  return &bucket->entries[ref.entry];
}

char const* bg3_lsof_symtab_entry_c_str(bg3_lsof_symtab_entry* entry) {
  if (!entry) {
    return "NULL";
  }
  if (!entry->c_str) {
    entry->c_str = strndup(entry->data, entry->length);
  }
  return entry->c_str;
}

void bg3_lsof_symtab_dump(bg3_lsof_symtab* table) {
  for (int bucket = 0; bucket < table->num_buckets; ++bucket) {
    for (int entry = 0; entry < table->buckets[bucket].num_entries; ++entry) {
      printf("entry (%04X,%04X): %s\n", bucket, entry,
             bg3_lsof_symtab_entry_c_str(&table->buckets[bucket].entries[entry]));
    }
  }
}

bg3_lsof_sym_ref bg3_lsof_symtab_intern(bg3_lsof_symtab* table, char const* name) {
  size_t len = strlen(name);
  XXH32_hash_t hash = XXH32(name, len, 0);
  bg3_lsof_symtab_bucket* bucket = &table->buckets[hash % table->num_buckets];
  for (size_t i = 0; i < bucket->num_entries; ++i) {
    if (len == bucket->entries[i].length &&
        !strncmp(bucket->entries[i].data, name, len)) {
      bg3_lsof_sym_ref ref = {(uint16_t)i, (uint16_t)(hash % table->num_buckets)};
      return ref;
    }
  }
  if (bucket->num_entries == bucket->capacity) {
    size_t new_capacity = bucket->capacity + (bucket->capacity / 2) + 1;
    bucket->entries = (bg3_lsof_symtab_entry*)realloc(
        bucket->entries,
        new_capacity * sizeof(bg3_lsof_symtab_entry));  // TODO: CHECKED MATH OMG
    bucket->capacity = new_capacity;
  }
  bg3_lsof_symtab_entry* new_entry = &bucket->entries[bucket->num_entries];
  new_entry->data = strdup(name);
  new_entry->length = len;
  bg3_lsof_sym_ref ref = {(uint16_t)bucket->num_entries,
                          (uint16_t)(hash % table->num_buckets)};
  bucket->num_entries++;
  return ref;
}

void bg3_lsof_symtab_write(bg3_lsof_symtab* table, bg3_buffer* buf) {
  uint32_t num_buckets = table->num_buckets;
  bg3_buffer_push(buf, &num_buckets, sizeof(uint32_t));
  for (uint32_t i = 0; i < num_buckets; ++i) {
    bg3_lsof_symtab_bucket* bucket = &table->buckets[i];
    uint16_t num_entries = bucket->num_entries;
    bg3_buffer_push(buf, &num_entries, sizeof(uint16_t));
    for (uint16_t j = 0; j < num_entries; ++j) {
      uint16_t length = bucket->entries[j].length;
      bg3_buffer_push(buf, &length, sizeof(uint16_t));
      bg3_buffer_push(buf, bucket->entries[j].data, length);
    }
  }
}

int bg3_lsof_reader_get_node(bg3_lsof_reader* file,
                             bg3_lsof_node_wide* node,
                             size_t node_index) {
  char* ptr = file->node_table_raw;
  if (node_index >= file->num_nodes) {
    return -1;
  }
  bool is_wide = LIBBG3_IS_SET(file->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS);
  ptr += node_index * (is_wide ? sizeof(bg3_lsof_node_wide) : sizeof(bg3_lsof_node_slim));
  if (is_wide) {
    memcpy(node, ptr, sizeof(bg3_lsof_node_wide));
  } else {
    bg3_lsof_node_slim light;
    memcpy(&light, ptr, sizeof(bg3_lsof_node_slim));
    node->name = light.name;
    node->parent = light.parent;
    node->next = -1;
    node->attrs = light.attrs;
  }
  return 0;
}

int bg3_lsof_reader_get_attr(bg3_lsof_reader* file,
                             bg3_lsof_attr_wide* attr,
                             size_t attr_index) {
  char* ptr = file->attr_table_raw;
  if (attr_index >= file->num_attrs) {
    return -1;
  }
  bool is_wide = LIBBG3_IS_SET(file->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS);
  ptr += attr_index * (is_wide ? sizeof(bg3_lsof_attr_wide) : sizeof(bg3_lsof_attr_slim));
  if (is_wide) {
    memcpy(attr, ptr, sizeof(bg3_lsof_attr_wide));
  } else {
    bg3_lsof_attr_slim light;
    memcpy(&light, ptr, sizeof(bg3_lsof_attr_slim));
    attr->name = light.name;
    attr->type = light.type;
    attr->length = light.length;
    attr->next = -1;
    attr->owner = light.owner;
  }
  return 0;
}

// lsof_size/next_addr is trusted here so must already be validated
static bool lsof_reader_extract_section(bg3_lsof_reader* file,
                                        char** out_section,
                                        bg3_lsof_size* size,
                                        size_t* next_addr,
                                        bool use_lz4f) {
  LZ4F_dctx* dctx;
  *out_section = (char*)malloc(size->uncompressed_size);
  if (use_lz4f) {
    char *src_ptr = file->data + *next_addr, *dst_ptr = *out_section;
    size_t left_src = size->compressed_size, left_dst = size->uncompressed_size;
    size_t n_src, n_dst;
    if (LZ4F_isError(LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION))) {
      fprintf(stderr, "init dctx failed\n");
      goto fail;
    }
    while (left_dst > 0 && left_src > 0) {
      n_src = left_src;
      n_dst = left_dst;
      if (LZ4F_isError(LZ4F_decompress(dctx, dst_ptr, &n_dst, src_ptr, &n_src, 0))) {
        goto fail_dctx;
      }
      left_src -= n_src;
      left_dst -= n_dst;
      src_ptr += n_src;
      dst_ptr += n_dst;
    }
    if (left_dst > 0) {
      fprintf(stderr,
              "warning: compressed data expanded to less bytes than it "
              "should?\n");
    }
    if (left_src > 0) {
      fprintf(stderr,
              "warning: decompressed data larger than declared in "
              "manifest?\n");
    }
    LZ4F_freeDecompressionContext(dctx);
  } else {
    if (LZ4_decompress_safe(file->data + *next_addr, *out_section, size->compressed_size,
                            size->uncompressed_size) < 0) {
      goto fail;
    }
  }
  *next_addr += size->compressed_size;
  return true;
fail_dctx:
  LZ4F_freeDecompressionContext(dctx);
fail:
  free(*out_section);
  *out_section = 0;
  return false;
}

static void bg3_lsof_reader_destroy_sections(bg3_lsof_reader* file) {
  if (file->owned_sections & LIBBG3_LSOF_OWNS_STRING_TABLE) {
    free(file->string_table_raw);
  }
  if (file->owned_sections & LIBBG3_LSOF_OWNS_NODE_TABLE) {
    free(file->node_table_raw);
  }
  if (file->owned_sections & LIBBG3_LSOF_OWNS_ATTR_TABLE) {
    free(file->attr_table_raw);
  }
  if (file->owned_sections & LIBBG3_LSOF_OWNS_VALUE_TABLE) {
    free(file->value_table_raw);
  }
}

bg3_status bg3_lsof_reader_init(bg3_lsof_reader* file, char* data, size_t data_len) {
  bg3_status status = bg3_success;
  bool created_symtab = false;
  size_t node_size, attr_size;
  memset(file, 0, sizeof(bg3_lsof_reader));
  file->data = data;
  file->data_len = data_len;
  bg3_cursor c;
  bg3_cursor_init(&c, file->data, file->data_len);
  if (file->data_len < sizeof(bg3_lsof_header)) {
    status = bg3_error_bad_magic;
    goto fail;
  }
  bg3_cursor_read(&c, &file->header, sizeof(bg3_lsof_header));
  if (file->header.magic != LIBBG3_LSOF_MAGIC) {
    status = bg3_error_bad_magic;
    goto fail;
  }
  if (file->header.version < LIBBG3_LSOF_VERSION_MIN ||
      file->header.version > LIBBG3_LSOF_VERSION_MAX) {
    status = bg3_error_bad_version;
    goto fail;
  }
  switch (LIBBG3_LSPK_ENTRY_COMPRESSION_METHOD(file->header.compression)) {
    case LIBBG3_LSPK_ENTRY_COMPRESSION_NONE:
      file->string_table_raw = file->data + sizeof(file->header);
      bg3_cursor_read(&c, 0, file->header.string_table.uncompressed_size);
      file->node_table_raw =
          file->string_table_raw + file->header.string_table.uncompressed_size;
      bg3_cursor_read(&c, 0, file->header.node_table.uncompressed_size);
      file->attr_table_raw =
          file->node_table_raw + file->header.node_table.uncompressed_size;
      bg3_cursor_read(&c, 0, file->header.attr_table.uncompressed_size);
      file->value_table_raw =
          file->attr_table_raw + file->header.attr_table.uncompressed_size;
      bg3_cursor_read(&c, 0, file->header.value_table.uncompressed_size);
      break;
    case LIBBG3_LSPK_ENTRY_COMPRESSION_LZ4: {
      file->owned_sections = LIBBG3_LSOF_OWNS_ALL;
      size_t next_addr = sizeof(file->header);
      bool ok = true;
      bg3_cursor_read(&c, 0, file->header.string_table.compressed_size);
      ok = ok &&
           lsof_reader_extract_section(file, &file->string_table_raw,
                                       &file->header.string_table, &next_addr, false);
      bg3_cursor_read(&c, 0, file->header.node_table.compressed_size);
      ok = ok && lsof_reader_extract_section(file, &file->node_table_raw,
                                             &file->header.node_table, &next_addr, true);
      bg3_cursor_read(&c, 0, file->header.attr_table.compressed_size);
      ok = ok && lsof_reader_extract_section(file, &file->attr_table_raw,
                                             &file->header.attr_table, &next_addr, true);
      bg3_cursor_read(&c, 0, file->header.value_table.compressed_size);
      ok = ok && lsof_reader_extract_section(file, &file->value_table_raw,
                                             &file->header.value_table, &next_addr, true);
      if (!ok) {
        goto fail;
      }
      break;
    }
    default:
      fprintf(stderr, "unsupported compression type %d\n",
              LIBBG3_LSPK_ENTRY_COMPRESSION_METHOD(file->header.compression));
      goto fail;
  }
  bg3_lsof_symtab_init_data(&file->symtab, file->string_table_raw,
                            file->header.string_table.uncompressed_size);
  created_symtab = true;
  node_size = LIBBG3_IS_SET(file->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS)
                  ? sizeof(bg3_lsof_node_wide)
                  : sizeof(bg3_lsof_node_slim);
  attr_size = LIBBG3_IS_SET(file->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS)
                  ? sizeof(bg3_lsof_attr_wide)
                  : sizeof(bg3_lsof_attr_slim);
  file->num_nodes = file->header.node_table.uncompressed_size / node_size;
  file->num_attrs = file->header.attr_table.uncompressed_size / attr_size;
  return status;
fail:
  bg3_lsof_reader_destroy_sections(file);
  if (created_symtab) {
    bg3_lsof_symtab_destroy(&file->symtab);
  }
  return status;
}

void bg3_lsof_reader_destroy(bg3_lsof_reader* file) {
  bg3_lsof_symtab_destroy(&file->symtab);
  bg3_lsof_reader_destroy_sections(file);
  free(file->value_offsets);
}

static void* bg3__memdup(void* src, size_t size) {
  void* dst = malloc(size);
  memcpy(dst, src, size);
  return dst;
}

void bg3_lsof_reader_ensure_sibling_pointers(bg3_lsof_reader* file) {
  if (LIBBG3_IS_SET(file->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS)) {
    return;
  }
  bg3_lsof_reader_ensure_value_offsets(file);
  bg3_lsof_node_ref* last_children =
      (bg3_lsof_node_ref*)calloc(file->num_nodes + 1, sizeof(bg3_lsof_node_ref));
  for (size_t i = 0; i < file->num_nodes + 1; ++i) {
    last_children[i] = -1;
  }
  bg3_lsof_node_slim* slim_nodes = (bg3_lsof_node_slim*)file->node_table_raw;
  bg3_lsof_node_wide* wide_nodes =
      (bg3_lsof_node_wide*)calloc(file->num_nodes, sizeof(bg3_lsof_node_wide));
  bg3_lsof_attr_slim* slim_attrs = (bg3_lsof_attr_slim*)file->attr_table_raw;
  bg3_lsof_attr_wide* wide_attrs =
      (bg3_lsof_attr_wide*)calloc(file->num_attrs, sizeof(bg3_lsof_attr_wide));
  for (size_t i = 0; i < file->num_nodes; ++i) {
    int32_t prev_last_child = last_children[slim_nodes[i].parent + 1];
    if (prev_last_child != -1) {
      wide_nodes[prev_last_child].next = i;
    }
    last_children[slim_nodes[i].parent + 1] = i;
    wide_nodes[i].name = slim_nodes[i].name;
    wide_nodes[i].parent = slim_nodes[i].parent;
    wide_nodes[i].attrs = slim_nodes[i].attrs;
    wide_nodes[i].next = -1;
  }
  for (size_t i = 0; i < file->num_attrs; ++i) {
    wide_attrs[i].name = slim_attrs[i].name;
    wide_attrs[i].type = slim_attrs[i].type;
    wide_attrs[i].length = slim_attrs[i].length;
    wide_attrs[i].next = -1;
    if (i > 0 && slim_attrs[i].owner == slim_attrs[i - 1].owner) {
      wide_attrs[i - 1].next = i;
    }
    wide_attrs[i].value = file->value_offsets[i];
  }
  if (file->owned_sections & LIBBG3_LSOF_OWNS_NODE_TABLE) {
    free(file->node_table_raw);
  }
  if (file->owned_sections & LIBBG3_LSOF_OWNS_ATTR_TABLE) {
    free(file->attr_table_raw);
  }
  file->node_table_raw = (char*)wide_nodes;
  file->attr_table_raw = (char*)wide_attrs;
  // Note that this breaks the correspondence between the header and the raw file->data
  // buffer contents.
  file->header.flags |= LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS;
  file->owned_sections |= LIBBG3_LSOF_OWNS_NODE_TABLE | LIBBG3_LSOF_OWNS_ATTR_TABLE;
  free(last_children);
  free(file->value_offsets);
  file->value_offsets = 0;
}

void bg3_lsof_reader_ensure_value_offsets(bg3_lsof_reader* file) {
  bool is_wide = LIBBG3_IS_SET(file->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS);
  if (!is_wide && !file->value_offsets) {
    size_t value_offset = 0;
    file->value_offsets = (uint32_t*)calloc(file->num_attrs, sizeof(uint32_t));
    for (bg3_lsof_attr_ref i = 0; i < file->num_attrs; ++i) {
      bg3_lsof_attr_wide attr;
      if (bg3_lsof_reader_get_attr(file, &attr, i) < 0) {
        bg3_panic("unreachable");
      }
      file->value_offsets[i] = value_offset;
      value_offset += attr.length;
    }
  }
}

#define MAX_FRAMES 128
typedef struct lsof_print_stack {
  int* ptr;
  int frames[MAX_FRAMES];
  int indent;
  bool is_fresh_line;
} lsof_print_stack;

static void fresh_line(bg3_buffer* out, lsof_print_stack* stack) {
  if (!stack->is_fresh_line) {
    bg3_buffer_putchar(out, '\n');
    for (int i = 0; i < stack->indent; ++i) {
      bg3_buffer_putchar(out, ' ');
    }
  }
  stack->is_fresh_line = true;
}

// TODO clean up this disaster
int bg3_lsof_reader_print_sexp(bg3_lsof_reader* file, bg3_buffer* out) {
  lsof_print_stack stack;
  stack.ptr = &stack.frames[MAX_FRAMES - 1];
  *stack.ptr = -1;
  stack.indent = 0;
  stack.is_fresh_line = true;
  bg3_lsof_reader_ensure_value_offsets(file);
  bool is_wide = LIBBG3_IS_SET(file->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS);
  for (bg3_lsof_node_ref i = 0; i < file->num_nodes; ++i) {
    bg3_lsof_node_wide node;
    if (bg3_lsof_reader_get_node(file, &node, i) < 0) {
      return -1;
    }
    while (node.parent != *stack.ptr) {
      if (stack.ptr == &stack.frames[MAX_FRAMES - 1]) {
        fprintf(stderr, "stack underflow\n");
        return -1;
      }
      stack.ptr++;
      bg3_buffer_putchar(out, ')');
      stack.is_fresh_line = false;
      stack.indent -= 2;
    }
    if (stack.ptr == stack.frames) {
      fprintf(stderr, "stack overflow\n");
      return -1;
    }
    *(--stack.ptr) = i;
    fresh_line(out, &stack);
    stack.indent += 2;
    char const* node_name =
        bg3_lsof_symtab_entry_c_str(bg3_lsof_symtab_get_ref(&file->symtab, node.name));
    if (!*node_name) {
      node_name = "_";
    }
    size_t name_len = strlen(node_name);
    bg3_buffer_printf(out, "(%s (", node_name);
    stack.is_fresh_line = false;
    bg3_lsof_attr_ref attr_index = node.attrs;
    bool first_attr = true;
    stack.indent += name_len + 1;
    while (attr_index != -1 && attr_index < file->num_attrs) {
      bg3_lsof_attr_wide attr;
      if (bg3_lsof_reader_get_attr(file, &attr, attr_index) < 0) {
        return -1;
      }
      if (!is_wide && attr.owner != i) {
        break;
      }
      if (!first_attr) {
        fresh_line(out, &stack);
      }
      first_attr = false;
      size_t offset = is_wide ? attr.value : file->value_offsets[attr_index];
      char* raw_attr = file->value_table_raw + offset;
      bg3_buffer_printf(
          out, "(%s ",
          bg3_lsof_symtab_entry_c_str(bg3_lsof_symtab_get_ref(&file->symtab, attr.name)));
      switch (attr.type) {
        case bg3_lsof_dt_lsstring: {
          char* str = strndup(raw_attr, attr.length);
          bg3_buffer_printf(out, "(LS \"%s\")", str);
          free(str);
          break;
        }
        case bg3_lsof_dt_fixedstring: {
          char* str = strndup(raw_attr, attr.length);
          bg3_buffer_printf(out, "\"%s\"", str);
          free(str);
          break;
        }
        case bg3_lsof_dt_bool: {
          bg3_buffer_printf(out, "%s", *raw_attr ? "#t" : "#f");
          break;
        }
        case bg3_lsof_dt_uuid: {
          bg3_uuid id;
          if (attr.length != sizeof(bg3_uuid)) {
            bg3_panic("invalid uuid length");
          }
          memcpy(&id, raw_attr, sizeof(id));
          bg3_buffer_printf(out, "(uuid \"%08x-%04x-%04x-%04x-%04x%04x%04x\")", id.word,
                            id.half[0], id.half[1], id.half[2], id.half[3], id.half[4],
                            id.half[5]);
          break;
        }
        case bg3_lsof_dt_translatedstring: {
          uint16_t version;
          uint32_t string_len;
          memcpy(&version, raw_attr, sizeof(uint16_t));
          memcpy(&string_len, raw_attr + 2, sizeof(uint32_t));
          if (string_len != attr.length - 6) {
            bg3_panic("invalid translated string length");
          }
          char* str = strndup(raw_attr + 6, string_len);
          bg3_buffer_printf(out, "(TS \"%s\" %d)", str, version);
          free(str);
          break;
        }
        case bg3_lsof_dt_ivec2: {
          struct {
            int32_t x, y;
          } vec;
          memcpy(&vec, raw_attr, sizeof(vec));
          bg3_buffer_printf(out, "(ivec2 %" PRIi32 " %" PRIi32 ")", vec.x, vec.y);
          break;
        }
        case bg3_lsof_dt_ivec3: {
          struct {
            int32_t x, y, z;
          } vec;
          memcpy(&vec, raw_attr, sizeof(vec));
          bg3_buffer_printf(out, "(ivec3 %" PRIi32 " %" PRIi32 " %" PRIi32 ")", vec.x,
                            vec.y, vec.z);
          break;
        }
        case bg3_lsof_dt_ivec4: {
          struct {
            int32_t x, y, z, w;
          } vec;
          memcpy(&vec, raw_attr, sizeof(vec));
          bg3_buffer_printf(out,
                            "(ivec4 %" PRIi32 " %" PRIi32 " %" PRIi32 " %" PRIi32 ")",
                            vec.x, vec.y, vec.z, vec.w);
          break;
        }
        case bg3_lsof_dt_vec2: {
          struct {
            float x, y;
          } vec;
          memcpy(&vec, raw_attr, sizeof(vec));
          bg3_buffer_printf(out, "(vec2 %f %f)", vec.x, vec.y);
          break;
        }
        case bg3_lsof_dt_vec3: {
          struct {
            float x, y, z;
          } vec;
          memcpy(&vec, raw_attr, sizeof(vec));
          bg3_buffer_printf(out, "(vec3 %f %f %f)", vec.x, vec.y, vec.z);
          break;
        }
        case bg3_lsof_dt_vec4: {
          struct {
            float x, y, z, w;
          } vec;
          memcpy(&vec, raw_attr, sizeof(vec));
          bg3_buffer_printf(out, "(vec4 %f %f %f %f)", vec.x, vec.y, vec.z, vec.w);
          break;
        }
        case bg3_lsof_dt_mat4: {
          float mat4[16];
          memcpy(&mat4, raw_attr, sizeof(mat4));
          bg3_buffer_printf(out, "(mat4 %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f %f)",
                            mat4[0], mat4[1], mat4[2], mat4[3], mat4[4], mat4[5], mat4[6],
                            mat4[7], mat4[8], mat4[9], mat4[10], mat4[11], mat4[12],
                            mat4[13], mat4[14], mat4[15]);
          break;
        }
        case bg3_lsof_dt_mat4x3: {
          float mat4x3[12];
          memcpy(&mat4x3, raw_attr, sizeof(float) * 12);
          bg3_buffer_printf(out, "(mat4x3 %f %f %f %f %f %f %f %f %f %f %f %f)",
                            mat4x3[0], mat4x3[1], mat4x3[2], mat4x3[3], mat4x3[4],
                            mat4x3[5], mat4x3[6], mat4x3[7], mat4x3[8], mat4x3[9],
                            mat4x3[10], mat4x3[11]);
          break;
        }
#define V(dt, itype, format)               \
  case dt: {                               \
    itype val;                             \
    memcpy(&val, raw_attr, sizeof(itype)); \
    bg3_buffer_printf(out, format, val);   \
    break;                                 \
  }
          V(bg3_lsof_dt_uint8, uint8_t, "(u8 %u)");
          V(bg3_lsof_dt_int8, int8_t, "(i8 %d)");
          V(bg3_lsof_dt_uint16, uint16_t, "(u16 %u)");
          V(bg3_lsof_dt_int16, int16_t, "(i16 %d)");
          V(bg3_lsof_dt_uint32, uint32_t, "(u32 %u)");
          V(bg3_lsof_dt_int32, int32_t, "(i32 %d)");
          V(bg3_lsof_dt_uint64, int64_t, "(u64 %" PRIu64 ")");
          V(bg3_lsof_dt_int64, int64_t, "(i64 %" PRIi64 ")");
          V(bg3_lsof_dt_float, float, "(f32 %f)");
          V(bg3_lsof_dt_double, double, "(f64 %f)");
#undef V
        default: {
          bg3_buffer_printf(out, "(raw %d ", attr.type);
          for (size_t i = 0; i < attr.length; ++i) {
            bg3_buffer_printf(out, i == attr.length - 1 ? "%d" : "%d ",
                              (uint8_t)raw_attr[i]);
          }
          bg3_buffer_printf(out, ")");
          break;
        }
      }
      bg3_buffer_putchar(out, ')');
      stack.is_fresh_line = false;
      attr_index = is_wide ? attr.next : attr_index + 1;
    }
    bg3_buffer_putchar(out, ')');
    stack.is_fresh_line = false;
    stack.indent -= name_len + 1;
  }
  while (*stack.ptr != -1) {
    bg3_buffer_putchar(out, ')');
    stack.ptr++;
    stack.is_fresh_line = false;
  }
  bg3_buffer_putchar(out, '\n');
  return 0;
}

void bg3_lsof_writer_init(bg3_lsof_writer* writer) {
  memset(writer, 0, sizeof(bg3_lsof_writer));
  bg3_lsof_symtab_init(&writer->symtab, 512);
}

void bg3_lsof_writer_destroy(bg3_lsof_writer* writer) {
  bg3_lsof_symtab_destroy(&writer->symtab);
}

bg3_status bg3_lsof_writer_write_file(bg3_lsof_writer* writer, char const* path) {
  bg3_lsof_header header;
  memset(&header, 0, sizeof(bg3_lsof_header));
  header.magic = LIBBG3_LSOF_MAGIC;
  header.version = LIBBG3_LSOF_VERSION_MAX;
  header.engine_version = 0;
  header.compression = 0;
  header.flags = LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS;
  bg3_buffer string_buf = {};
  bg3_lsof_symtab_write(&writer->symtab, &string_buf);
  header.string_table.uncompressed_size = string_buf.size;
  header.node_table.uncompressed_size = writer->node_table.size;
  header.attr_table.uncompressed_size = writer->attr_table.size;
  header.value_table.uncompressed_size = writer->value_table.size;
  size_t total_size = string_buf.size + writer->node_table.size +
                      writer->attr_table.size + writer->value_table.size +
                      sizeof(bg3_lsof_header);
  bg3_mapped_file mapped;
  if (bg3_mapped_file_init_rw_trunc(&mapped, path, total_size) < 0) {
    bg3_buffer_destroy(&string_buf);
    return bg3_error_libc;
  }
  char* ptr = mapped.data;
  memcpy(ptr, &header, sizeof(bg3_lsof_header));
  ptr += sizeof(bg3_lsof_header);
  memcpy(ptr, string_buf.data, string_buf.size);
  ptr += string_buf.size;
  memcpy(ptr, writer->node_table.data, writer->node_table.size);
  ptr += writer->node_table.size;
  memcpy(ptr, writer->attr_table.data, writer->attr_table.size);
  ptr += writer->attr_table.size;
  memcpy(ptr, writer->value_table.data, writer->value_table.size);
  bg3_mapped_file_destroy(&mapped);
  bg3_buffer_destroy(&string_buf);
  return bg3_success;
}

static inline bg3_lsof_writer_stack_frame* lsof_writer_stack(bg3_lsof_writer* writer) {
  return ((bg3_lsof_writer_stack_frame*)writer->stack.data);
}

static inline bg3_lsof_writer_stack_frame* lsof_writer_stack_top(
    bg3_lsof_writer* writer) {
  return writer->num_stack ? &lsof_writer_stack(writer)[writer->num_stack - 1] : 0;
}

void bg3_lsof_writer_push_node(bg3_lsof_writer* writer, char const* node_name) {
  bg3_lsof_node_wide node = {};
  bg3_lsof_writer_stack_frame* parent_frame = lsof_writer_stack_top(writer);
  bg3_lsof_writer_stack_frame child_frame = {};
  node.name = bg3_lsof_symtab_intern(&writer->symtab, node_name);
  node.parent = parent_frame ? parent_frame->node_id : -1;
  node.next = -1;
  node.attrs = -1;
  child_frame.node_id = writer->num_nodes;
  child_frame.last_child = -1;
  child_frame.last_attr = -1;
  if (parent_frame) {
    if (parent_frame->last_child != -1) {
      bg3_lsof_node_wide* last_child =
          &((bg3_lsof_node_wide*)writer->node_table.data)[parent_frame->last_child];
      last_child->next = child_frame.node_id;
    }
    parent_frame->last_child = child_frame.node_id;
  }
  writer->num_stack++;
  writer->num_nodes++;
  bg3_buffer_push(&writer->node_table, &node, sizeof(bg3_lsof_node_wide));
  bg3_buffer_push(&writer->stack, &child_frame, sizeof(bg3_lsof_writer_stack_frame));
}

void bg3_lsof_writer_push_attr(bg3_lsof_writer* writer,
                               char const* attr_name,
                               bg3_lsof_dt type,
                               void* ptr,
                               size_t len) {
  bg3_lsof_writer_stack_frame* frame = lsof_writer_stack_top(writer);
  bg3_lsof_attr_wide attr;
  if (!frame) {
    bg3_panic("no current node");
  }
  if (len >= (1 << 26)) {
    bg3_panic("length overflow");
  }
  bg3_lsof_node_wide* node =
      &((bg3_lsof_node_wide*)writer->node_table.data)[frame->node_id];
  attr.name = bg3_lsof_symtab_intern(&writer->symtab, attr_name);
  attr.type = type;
  attr.length = len;
  attr.next = -1;
  if (frame->last_attr != -1) {
    bg3_lsof_attr_wide* prev_attr =
        &((bg3_lsof_attr_wide*)writer->attr_table.data)[frame->last_attr];
    prev_attr->next = writer->num_attrs;
  } else {
    node->attrs = writer->num_attrs;
  }
  frame->last_attr = writer->num_attrs;
  attr.value = writer->value_table.size;
  bg3_buffer_push(&writer->value_table, ptr, len);
  bg3_buffer_push(&writer->attr_table, &attr, sizeof(bg3_lsof_attr_wide));
  writer->num_attrs++;
}

void bg3_lsof_writer_pop_node(bg3_lsof_writer* writer) {
  bg3_buffer_pop(&writer->stack, sizeof(bg3_lsof_writer_stack_frame));
  writer->num_stack--;
}

static long long strtoll10(char const* ptr, char** endptr) {
  return strtoll(ptr, endptr, 10);
}

static unsigned long long strtoull10(char const* ptr, char** endptr) {
  return strtoull(ptr, endptr, 10);
}

static bg3_status lsof_writer_sexp_attr_val(bg3_lsof_writer* writer,
                                            bg3_sexp_lexer* l,
                                            char* attr_name) {
  switch (l->next.type) {
    case bg3_sexp_token_type_string:
      bg3_lsof_writer_push_attr(writer, attr_name, bg3_lsof_dt_fixedstring,
                                l->next.text.data, l->next.text.size + 1);
      SLURP(string);
      break;
    case bg3_sexp_token_type_hash:
      SLURP(hash);
      MATCH(symbol);
      uint8_t val;
      if (!strcmp(l->next.text.data, "t")) {
        val = true;
      } else if (!strcmp(l->next.text.data, "f")) {
        val = false;
      } else {
        return bg3_error_failed;
      }
      bg3_lsof_writer_push_attr(writer, attr_name, bg3_lsof_dt_bool, &val, 1);
      SLURP(symbol);
      break;
    case bg3_sexp_token_type_lparen:
      SLURP(lparen);
      MATCH(symbol);
#define DO_CONV(itype, dtype, conv_fn, token)                               \
  do {                                                                      \
    SLURP(symbol);                                                          \
    MATCH(token);                                                           \
    itype val = (itype)conv_fn(l->next.text.data, 0);                       \
    bg3_lsof_writer_push_attr(writer, attr_name, dtype, &val, sizeof(val)); \
    SLURP(token);                                                           \
  } while (0)
#define DO_INT(itype, dtype)  DO_CONV(itype, dtype, strtoll10, integer)
#define DO_UINT(itype, dtype) DO_CONV(itype, dtype, strtoull10, integer)
#define DO_CONV_VEC(itype, dtype, conv_fn, token, len)                       \
  do {                                                                       \
    SLURP(symbol);                                                           \
    itype data[len];                                                         \
    for (int i = 0; i < len; ++i) {                                          \
      MATCH(token);                                                          \
      data[i] = (itype)conv_fn(l->next.text.data, 0);                        \
      SLURP(token);                                                          \
    }                                                                        \
    bg3_lsof_writer_push_attr(writer, attr_name, dtype, data, sizeof(data)); \
  } while (0)
#define DO_FVEC(dtype, len) DO_CONV_VEC(float, dtype, strtof, decimal, len)
#define DO_IVEC(dtype, len) DO_CONV_VEC(int32_t, dtype, strtoll10, integer, len)
      if (!strcmp(l->next.text.data, "LS")) {
        SLURP(symbol);
        MATCH(string);
        bg3_lsof_writer_push_attr(writer, attr_name, bg3_lsof_dt_lsstring,
                                  l->next.text.data, l->next.text.size + 1);
        SLURP(string);
      } else if (!strcmp(l->next.text.data, "u8")) {
        DO_UINT(uint8_t, bg3_lsof_dt_uint8);
      } else if (!strcmp(l->next.text.data, "i8")) {
        DO_INT(int8_t, bg3_lsof_dt_int8);
      } else if (!strcmp(l->next.text.data, "u16")) {
        DO_UINT(uint16_t, bg3_lsof_dt_uint16);
      } else if (!strcmp(l->next.text.data, "i16")) {
        DO_INT(int16_t, bg3_lsof_dt_int16);
      } else if (!strcmp(l->next.text.data, "u32")) {
        DO_UINT(uint32_t, bg3_lsof_dt_uint32);
      } else if (!strcmp(l->next.text.data, "i32")) {
        DO_INT(int32_t, bg3_lsof_dt_int32);
      } else if (!strcmp(l->next.text.data, "u64")) {
        DO_UINT(uint64_t, bg3_lsof_dt_uint64);
      } else if (!strcmp(l->next.text.data, "i64")) {
        DO_INT(int64_t, bg3_lsof_dt_int64);
      } else if (!strcmp(l->next.text.data, "f32")) {
        DO_CONV(float, bg3_lsof_dt_float, strtof, decimal);
      } else if (!strcmp(l->next.text.data, "f64")) {
        DO_CONV(double, bg3_lsof_dt_double, strtod, decimal);
      } else if (!strcmp(l->next.text.data, "uuid")) {
        SLURP(symbol);
        MATCH(string);
        bg3_uuid id;
        int nmatch = sscanf(l->next.text.data, "%08x-%04hx-%04hx-%04hx-%04hx%04hx%04hx",
                            &id.word, &id.half[0], &id.half[1], &id.half[2], &id.half[3],
                            &id.half[4], &id.half[5]);
        if (nmatch != 7 || l->next.text.size != 36) {
          return bg3_error_failed;
        }
        bg3_lsof_writer_push_attr(writer, attr_name, bg3_lsof_dt_uuid, &id,
                                  sizeof(bg3_uuid));
        SLURP(string);
      } else if (!strcmp(l->next.text.data, "TS")) {
        const size_t handle_len = 38;  // 'h' + uuid + nul
        struct __attribute__((__packed__)) ts_header {
          uint16_t version;
          uint32_t string_len;
        }* header;
        header = (struct ts_header*)alloca(sizeof(*header) + handle_len);
        SLURP(symbol);
        MATCH(string);
        if (l->next.text.size != handle_len - 1) {
          return bg3_error_failed;
        }
        header->string_len = handle_len;
        memcpy(header + 1, l->next.text.data, l->next.text.size + 1);
        SLURP(string);
        MATCH(integer);
        header->version = (uint16_t)strtoull10(l->next.text.data, 0);
        SLURP(integer);
        bg3_lsof_writer_push_attr(writer, attr_name, bg3_lsof_dt_translatedstring, header,
                                  sizeof(*header) + handle_len + 1);
      } else if (!strcmp(l->next.text.data, "mat2")) {
        DO_FVEC(bg3_lsof_dt_mat2, 4);
      } else if (!strcmp(l->next.text.data, "mat3")) {
        DO_FVEC(bg3_lsof_dt_mat3, 9);
      } else if (!strcmp(l->next.text.data, "mat3x4")) {
        DO_FVEC(bg3_lsof_dt_mat3x4, 12);
      } else if (!strcmp(l->next.text.data, "mat4x3")) {
        DO_FVEC(bg3_lsof_dt_mat4x3, 12);
      } else if (!strcmp(l->next.text.data, "mat4")) {
        DO_FVEC(bg3_lsof_dt_mat4, 16);
      } else if (!strcmp(l->next.text.data, "vec2")) {
        DO_FVEC(bg3_lsof_dt_vec2, 2);
      } else if (!strcmp(l->next.text.data, "vec3")) {
        DO_FVEC(bg3_lsof_dt_vec3, 3);
      } else if (!strcmp(l->next.text.data, "vec4")) {
        DO_FVEC(bg3_lsof_dt_vec4, 4);
      } else if (!strcmp(l->next.text.data, "ivec2")) {
        DO_IVEC(bg3_lsof_dt_ivec2, 2);
      } else if (!strcmp(l->next.text.data, "ivec3")) {
        DO_IVEC(bg3_lsof_dt_ivec3, 3);
      } else if (!strcmp(l->next.text.data, "ivec4")) {
        DO_IVEC(bg3_lsof_dt_ivec4, 4);
      } else {
        return bg3_error_failed;
      }
      SLURP(rparen);
      break;
    default:
      return bg3_error_failed;
#undef DO_CONV
#undef DO_CONV_VEC
#undef DO_INT
#undef DO_UINT
#undef DO_FVEC
#undef DO_IVEC
  }
  return bg3_success;
}

static bg3_status lsof_writer_sexp_node(bg3_lsof_writer* writer,
                                        bg3_sexp_lexer* l,
                                        bg3_buffer* attr_name) {
  bg3_status status = bg3_success;
  SLURP(lparen);
  MATCH(symbol);
  bg3_lsof_writer_push_node(writer, (char*)l->next.text.data);
  SLURP(symbol);
  SLURP(lparen);
  while (l->next.type != bg3_sexp_token_type_rparen) {
    SLURP(lparen);
    MATCH(symbol);
    bg3_buffer_copy(attr_name, &l->next.text);
    SLURP(symbol);
    status = lsof_writer_sexp_attr_val(writer, l, (char*)attr_name->data);
    if (status) {
      return status;
    }
    SLURP(rparen);
  }
  SLURP(rparen);
  while (l->next.type != bg3_sexp_token_type_rparen) {
    status = lsof_writer_sexp_node(writer, l, attr_name);
    if (status) {
      return status;
    }
  }
  SLURP(rparen);
  bg3_lsof_writer_pop_node(writer);
  return status;
}

bg3_status bg3_lsof_writer_push_sexps(bg3_lsof_writer* writer,
                                      char const* data,
                                      size_t data_len) {
  bg3_status status = bg3_success;
  bg3_buffer attr_name = {};
  bg3_sexp_lexer l;
  bg3_sexp_lexer_init(&l, data, data_len);
  bg3_sexp_lexer_advance(&l);
  while (l.next.type != bg3_sexp_token_type_eof) {
    if ((status = lsof_writer_sexp_node(writer, &l, &attr_name))) {
      bg3_error("parse error near line %d\n", l.line);
      return status;
    }
  }
  return status;
}

bg3_status bg3_loca_reader_init(bg3_loca_reader* file, char* data, size_t data_len) {
  if (data_len < sizeof(bg3_loca_header)) {
    return bg3_error_failed;
  }
  memset(file, 0, sizeof(bg3_loca_reader));
  bg3_cursor c;
  bg3_cursor_init(&c, data, data_len);
  bg3_cursor_read(&c, &file->header, sizeof(file->header));
  if (file->header.magic != LIBBG3_LOCA_MAGIC) {
    return bg3_error_failed;
  }
  file->entries = (bg3_loca_reader_entry*)calloc(file->header.num_entries,
                                                 sizeof(bg3_loca_reader_entry));
  size_t data_offset = file->header.heap_offset;
  bg3_cursor heap_cursor;
  bg3_cursor_init(&heap_cursor, data, data_len);
  bg3_cursor_read(&heap_cursor, 0, file->header.heap_offset);
  for (uint32_t i = 0; i < file->header.num_entries; ++i) {
    bg3_loca_reader_entry_raw raw_entry;
    bg3_loca_reader_entry* entry = &file->entries[i];
    bg3_cursor_read(&c, &raw_entry, sizeof(raw_entry));
    raw_entry.handle[63] = '\0';
    snprintf(entry->handle, sizeof(entry->handle), "%s", raw_entry.handle);
    entry->version = raw_entry.version;
    entry->data = data + data_offset;
    entry->data_size = (((size_t)raw_entry.size_hi) << 16) | ((size_t)raw_entry.size_lo);
    bg3_cursor_read(&heap_cursor, 0, entry->data_size);
    data_offset += entry->data_size;
  }
  return bg3_success;
}

int bg3_loca_reader_dump(bg3_loca_reader* file) {
  for (uint32_t i = 0; i < file->header.num_entries; ++i) {
    printf("%s;%d %s\n", file->entries[i].handle, file->entries[i].version,
           file->entries[i].data);
  }
  return -1;
}

void bg3_loca_reader_destroy(bg3_loca_reader* file) {
  free(file->entries);
}

void bg3_loca_writer_init(bg3_loca_writer* writer) {
  memset(writer, 0, sizeof(bg3_loca_writer));
}

void bg3_loca_writer_destroy(bg3_loca_writer* writer) {
  bg3_buffer_destroy(&writer->entries);
  bg3_buffer_destroy(&writer->heap);
}

void bg3_loca_writer_push(bg3_loca_writer* writer,
                          char const* handle,
                          uint16_t version,
                          char const* text) {
  bg3_loca_reader_entry_raw entry;
  size_t len = strlen(text) + 1;
  memset(&entry, 0, sizeof(bg3_loca_reader_entry_raw));
  snprintf(entry.handle, 64, "%s", handle);
  entry.version = version;
  assert(len <= UINT32_MAX);
  entry.size_lo = len & 0xFFFF;
  entry.size_hi = len >> 16;
  bg3_buffer_push(&writer->entries, &entry, sizeof(bg3_loca_reader_entry_raw));
  bg3_buffer_push(&writer->heap, text, len);
}

bg3_status bg3_loca_writer_write_file(bg3_loca_writer* writer, char const* path) {
  bg3_mapped_file out;
  bg3_status status;
  size_t out_len = sizeof(bg3_loca_header) + writer->entries.size + writer->heap.size;
  if ((status = bg3_mapped_file_init_rw_trunc(&out, path, out_len))) {
    return status;
  }
  bg3_loca_header header = {
      .magic = LIBBG3_LOCA_MAGIC,
      .num_entries = (uint32_t)(writer->entries.size / sizeof(bg3_loca_reader_entry_raw)),
      .heap_offset = (uint32_t)(sizeof(bg3_loca_header) + writer->entries.size),
  };
  char* ptr = out.data;
  memcpy(ptr, &header, sizeof(bg3_loca_header));
  ptr += sizeof(bg3_loca_header);
  memcpy(ptr, writer->entries.data, writer->entries.size);
  ptr += writer->entries.size;
  memcpy(ptr, writer->heap.data, writer->heap.size);
  bg3_mapped_file_destroy(&out);
  return bg3_success;
}

// TODO: this format doesn't seem to make any real alignment guarantees,
// so probably everything after the layer data needs to deal with
// unaligned pointers and do copies.
bg3_status bg3_patch_file_init(bg3_patch_file* file, char* data, size_t data_len) {
  memset(file, 0, sizeof(bg3_patch_file));
  bg3_cursor c;
  bg3_cursor_init(&c, data, data_len);
  if (data_len < sizeof(bg3_patch_header)) {
    return bg3_error_failed;
  }
  bg3_cursor_read(&c, &file->header, sizeof(bg3_patch_header));
  if (file->header.magic != LIBBG3_PATCH_MAGIC) {
    return bg3_error_failed;
  }
  if (file->header.version != LIBBG3_PATCH_VERSION) {
    // there are still some non-robust patch files present, but I have
    // not found one that appears to actually be _used_. implement if needed
    return bg3_error_failed;
  }
  if (file->header.metadata_size != sizeof(bg3_patch_metadata)) {
    return bg3_error_failed;
  }
  bg3_cursor_read(&c, &file->metadata, sizeof(bg3_patch_metadata));
  file->data = data;
  file->data_len = data_len;
  file->heightfield = (float*)c.ptr;
  bg3_cursor_read(&c, 0,
                  sizeof(float) * file->metadata.local_cols * file->metadata.local_rows);
  if (file->metadata.num_holes) {
    file->holes = (uint32_t*)c.ptr;
    bg3_cursor_read(&c, 0, file->metadata.num_holes * sizeof(uint32_t));
  }
  file->layers =
      (bg3_patch_layer*)malloc(sizeof(bg3_patch_layer) * file->metadata.num_layers);
  for (int i = 0; i < file->metadata.num_layers; ++i) {
    uint32_t length;
    bg3_cursor_read(&c, &length, sizeof(uint32_t));
    char* layer_name_ptr = c.ptr;
    file->layers[i].name = strndup(layer_name_ptr, length);
    bg3_cursor_read(&c, 0, length);
    bg3_cursor_read(&c, &length, sizeof(uint32_t));
    if (length != file->metadata.tex_cols * file->metadata.tex_rows) {
      bg3_panic("layer data length has invalid size");
    }
    file->layers[i].weights = (uint8_t*)c.ptr;
    bg3_cursor_read(&c, 0, length);
  }
  uint32_t normal_map_len;
  bg3_cursor_read(&c, &normal_map_len, sizeof(uint32_t));
  bg3_bc7_block* normal_map = (bg3_bc7_block*)c.ptr;
  bg3_cursor_read(&c, 0, normal_map_len);
  int norm_rows = (file->metadata.local_rows + 3) / 4;
  int norm_cols = (file->metadata.local_cols + 3) / 4;
  if (normal_map_len == sizeof(bg3_bc7_block) * norm_rows * norm_cols) {
    file->normal_map = normal_map;
    file->normal_map_rows = norm_rows;
    file->normal_map_cols = norm_cols;
  }
  for (int i = 0; i < 2; ++i) {
    // TODO: still need to figure out the function of the bounds here and the
    // right way to read this
    if (c.ptr < c.end &&
        file->metadata.key_bounds[i].x0 < file->metadata.key_bounds[i].x1 &&
        file->metadata.key_bounds[i].y0 < file->metadata.key_bounds[i].y1) {
      file->num_keys++;
      file->keys[i].bounds = (bg3_patch_key_bounds*)c.ptr;
      bg3_cursor_read(&c, 0, 0x40);
      for (int j = 0; j < 4; ++j) {
        uint32_t length;
        bg3_cursor_read(&c, &length, sizeof(uint32_t));
        char* key_data = c.ptr;
        bg3_cursor_read(&c, 0, length);
        file->keys[i].entries[j].data = key_data;
        file->keys[i].entries[j].data_len = length;
      }
    }
  }
  return bg3_success;
}

void bg3_patch_file_destroy(bg3_patch_file* file) {
  for (uint32_t i = 0; i < file->metadata.num_layers; ++i) {
    free(file->layers[i].name);
  }
  free(file->layers);
}

bg3_status bg3_patch_file_dump(bg3_patch_file* file) {
  printf(
      "patch version %d, local (%dx%d) tex (%d,%d) global (%dx%d) chunk "
      "(%x,%x)\n",
      file->header.version, file->metadata.local_cols, file->metadata.local_rows,
      file->metadata.tex_cols, file->metadata.tex_rows, file->metadata.global_cols,
      file->metadata.global_rows, file->metadata.chunk_x, file->metadata.chunk_y);
  for (int i = 0; i < 2; ++i) {
    printf("key %d bounds %d %d %d %d\n", i, file->metadata.key_bounds[i].x0,
           file->metadata.key_bounds[i].x1, file->metadata.key_bounds[i].y0,
           file->metadata.key_bounds[i].y1);
  }
  float maxval = -1000000.0f, minval = 1000000.0f;
  for (int y = 0; y < file->metadata.local_rows; ++y) {
    for (int x = 0; x < file->metadata.local_cols; ++x) {
      float v = file->heightfield[file->metadata.local_cols * y + x];
      minval = fminf(minval, v);
      maxval = fmaxf(maxval, v);
    }
  }
  for (int y = 0; y < file->metadata.local_rows; ++y) {
    for (int x = 0; x < file->metadata.local_cols; ++x) {
      float v = file->heightfield[file->metadata.local_cols * y + x];
      printf("%6.2f ", v);
    }
    printf("\n");
  }
  printf("min %f max %f range %f\n", minval, maxval, fabs(maxval - minval));
  if (file->metadata.num_holes) {
    uint32_t guess_bit_max = file->metadata.global_rows * file->metadata.global_cols;
    printf("hole table\n");
    for (int i = 0; i < file->metadata.num_holes; ++i) {
      if ((i % 8) == 0 && i) {
        printf("\n");
      }
      printf("%08X ", file->holes[i]);
    }
    printf("\n");
  }
  for (int i = 0; i < file->metadata.num_layers; ++i) {
    printf("layer %s\n", file->layers[i].name);
    for (int y = 0; y < file->metadata.tex_rows; ++y) {
      for (int x = 0; x < file->metadata.tex_cols; ++x) {
        printf("%02X", (int)(file->layers[i].weights[y * file->metadata.tex_cols + x]));
      }
      printf("\n");
    }
  }
#if LIBBG3_CONFIG_ENABLE_BCDEC
  if (file->normal_map) {
    for (int y = 0; y < file->normal_map_rows; ++y) {
      for (int x = 0; x < file->normal_map_cols; ++x) {
        bc7_block* val = file->normal_map + (y * file->normal_map_cols + x);
        uint8_t rgba_bc7[64];
        bcdec_bc7(val, rgba_bc7, 16);
        for (int yi = 0; yi < 4; ++yi) {
          for (int xi = 0; xi < 4; ++xi) {
            int n = yi * 16 + xi * 4;
            printf("(%6.2f,%6.2f,%6.2f,%6.2f) ", rgba_bc7[n] / 255.0f * 2.0f - 1.0f,
                   rgba_bc7[n + 1] / 255.0f * 2.0f - 1.0f,
                   rgba_bc7[n + 2] / 255.0f * 2.0f - 1.0f, rgba_bc7[n + 3] / 255.0f);
          }
          printf("\n");
        }
      }
    }
  }
#endif
  for (size_t i = 0; i < file->num_keys; ++i) {
    printf("key map\n");
    for (int j = 0; j < 4; ++j) {
      int32_t x0 = file->keys[i].bounds[j].x0;
      int32_t x1 = file->keys[i].bounds[j].x1;
      int32_t y0 = file->keys[i].bounds[j].y0;
      int32_t y1 = file->keys[i].bounds[j].y1;
      int32_t w = x1 - x0;
      int32_t h = y1 - y0;
      printf("  entry %d (%zu) x0 %d x1 %d y0 %d y1 %d w %d h %d:\n", j,
             file->keys[i].entries[j].data_len, x0, x1, y0, y1, w, h);
      if (w < 0 || h < 0) {
        continue;
      }
      for (int y = 0; y < h; ++y) {
        for (int x = 0; x < w; ++x) {
          printf("%02X", (int)(file->keys[i].entries[j].data[y * w + x]));
        }
        printf("\n");
      }
    }
  }
  return bg3_success;
}

static bg3_status bg3_granny_decompress_bitknit(bg3_granny_compressor_ops const* ops,
                                                char* output,
                                                size_t output_len,
                                                char* input,
                                                size_t input_len) {
  if (!input_len && !output_len) {
    return bg3_success;
  }
  if (!ops->begin_file_decompression || !ops->decompress_incremental ||
      !ops->end_file_decompression) {
    return bg3_error_unsupported;
  }
  bool ok = true;
  char tmpbuf[0x4000];
  void* context = ops->begin_file_decompression(bg3_granny_compression_bitknit2, false,
                                                output_len, output, 0x4000, tmpbuf);
  if (!context) {
    return bg3_error_failed;
  }
  ok = ops->decompress_incremental(context, input_len, input);
  ops->end_file_decompression(context);
  return ok ? bg3_success : bg3_error_failed;
}

void bg3_granny_reader_destroy(bg3_granny_reader* reader) {
  for (uint32_t i = 0; i < reader->header.num_sections; ++i) {
    if (reader->sections[i].owned) {
      free(reader->sections[i].data);
    }
  }
  free(reader->sections);
}

bg3_status bg3_granny_reader_init(bg3_granny_reader* reader,
                                  char* data,
                                  size_t data_len,
                                  bg3_granny_compressor_ops const* compressor_ops) {
  bg3_status status = bg3_success;
  memset(reader, 0, sizeof(bg3_granny_reader));
  reader->data = data;
  reader->data_len = data_len;
  bg3_cursor c;
  bg3_cursor_init(&c, data, data_len);
  if (data_len < sizeof(bg3_granny_magic)) {
    return bg3_error_failed;
  }
  bg3_cursor_read(&c, &reader->magic, sizeof(bg3_granny_magic));
  if (reader->magic.lo != LIBBG3_GRANNY_MAGIC_LO ||
      reader->magic.hi != LIBBG3_GRANNY_MAGIC_HI) {
    return bg3_error_failed;
  }
  bg3_cursor_read(&c, &reader->header, sizeof(bg3_granny_header));
  if (reader->header.format_version != LIBBG3_GRANNY_VERSION) {
    return bg3_error_failed;
  }
  size_t section_offset = reader->header.section_table + sizeof(bg3_granny_magic);
  if (c.ptr - c.start != section_offset) {
    return bg3_error_failed;
  }
  int section_size =
      (reader->magic.header_size - section_offset) / reader->header.num_sections;
  if (section_size != sizeof(bg3_granny_section_header)) {
    return bg3_error_failed;
  }
  reader->section_headers = (bg3_granny_section_header*)c.ptr;
  reader->sections = (bg3_granny_section*)calloc(reader->header.num_sections,
                                                 sizeof(bg3_granny_section));
  for (uint32_t i = 0; i < reader->header.num_sections; ++i) {
    bg3_granny_section_header* sect = &reader->section_headers[i];
    // TODO bounds checking
    if (sect->compression) {
      void* output = calloc(1, sect->uncompressed_len);
      if (sect->compression == bg3_granny_compression_bitknit2) {
        status = bg3_granny_decompress_bitknit(
            compressor_ops, (char*)output, sect->uncompressed_len, c.start + sect->offset,
            sect->compressed_len);
      } else {
        status = bg3_error_unsupported;
      }
      if (!status) {
        reader->sections[i].data = (char*)output;
        reader->sections[i].data_len = sect->uncompressed_len;
        reader->sections[i].owned = true;
      } else {
        free(output);
        goto err_out;
      }
    } else {
      reader->sections[i].data = c.start + sect->offset;
      reader->sections[i].data_len = sect->uncompressed_len;
    }
  }
  for (uint32_t i = 0; i < reader->header.num_sections; ++i) {
    bg3_granny_section_header* sect = &reader->section_headers[i];
    bool owns_fixups = false;
    bg3_granny_fixup* fixups;
    if (sect->compression == bg3_granny_compression_bitknit2) {
      size_t fixups_len = sect->num_fixups * sizeof(bg3_granny_fixup);
      fixups = (bg3_granny_fixup*)calloc(1, fixups_len);
      owns_fixups = true;
      bg3_cursor_seek(&c, sect->fixups_offset);
      uint32_t compressed_len;
      bg3_cursor_read(&c, &compressed_len, sizeof(uint32_t));
      if ((status = bg3_granny_decompress_bitknit(compressor_ops, (char*)fixups,
                                                  fixups_len, c.ptr, compressed_len))) {
        free(fixups);
        goto err_out;
      }
    } else {
      fixups = (bg3_granny_fixup*)(c.start + sect->fixups_offset);
    }
    for (uint32_t fixup_idx = 0; fixup_idx < sect->num_fixups; ++fixup_idx) {
      bg3_granny_fixup* r = fixups + fixup_idx;
      uint64_t resolved = (uint64_t)reader->sections[r->ptr.section].data + r->ptr.offset;
      memcpy(reader->sections[i].data + r->section_offset, &resolved, sizeof(uint64_t));
    }
    if (owns_fixups) {
      free(fixups);
    }
  }
  return status;
err_out:
  bg3_granny_reader_destroy(reader);
  return status;
}

bg3_granny_type_info* bg3_granny_reader_get_root_type(bg3_granny_reader* reader) {
  bg3_cursor c;
  bg3_granny_section_ptr root_type = reader->header.root_type;
  bg3_granny_section* section = &reader->sections[root_type.section];
  bg3_cursor_init(&c, section->data, section->data_len);
  bg3_cursor_seek(&c, root_type.offset);
  return (bg3_granny_type_info*)c.ptr;
}

void* bg3_granny_reader_get_root(bg3_granny_reader* reader) {
  bg3_granny_section_ptr root_type = reader->header.root_type;
  bg3_granny_section* section = &reader->sections[root_type.section];
  void* root = (void*)(reader->sections[reader->header.root_obj.section].data +
                       reader->header.root_obj.offset);
  return root;
}

bg3_status bg3_gts_reader_init(bg3_gts_reader* reader, char* data, size_t data_len) {
  memset(reader, 0, sizeof(bg3_gts_reader));
  reader->data = data;
  reader->data_len = data_len;
  if (data_len < sizeof(bg3_gts_header)) {
    return bg3_error_bad_magic;
  }
  bg3_cursor c;
  bg3_cursor_init(&c, data, data_len);
  bg3_cursor_read(&c, &reader->header, sizeof(bg3_gts_header));
  if (reader->header.magic != LIBBG3_GTS_MAGIC) {
    return bg3_error_bad_magic;
  }
  if (reader->header.version != LIBBG3_GTS_VERSION) {
    return bg3_error_bad_version;
  }
  return bg3_success;
}

void bg3_gts_reader_destroy(bg3_gts_reader* reader) {
  // nothing to do
}

static void bg3__gdex_dump(bg3_indent_buffer* ibuf,
                           char const* base,
                           char const* items,
                           char const* items_end) {
  while (items < items_end) {
    bg3_gdex_item const* item = (bg3_gdex_item const*)items;
    bg3_ibuf_printf(ibuf, "[" LIBBG3_FOURCC_FMT "]: %08zX %d %d %08X 0x%08X len: %lld\n",
                    LIBBG3_FOURCC_FMT_ARGS(item->tag), items - base, (int)item->type,
                    (int)item->flag, (int)item->length_lo,
                    item->flag & 1 ? bg3_gdex_item_extended_length(item) : 0,
                    bg3_gdex_item_length(item));
    bg3_ibuf_push(ibuf, 4);
    if (item->type == bg3_gdex_item_container) {
      bg3__gdex_dump(ibuf, base, items + bg3_gdex_item_header_length(item),
                     items + bg3_gdex_item_length(item));
    }
    bg3_ibuf_pop(ibuf);
    items += bg3_gdex_item_length(item);
  }
}

bg3_gdex_item const* bg3_gdex_item_find_child(bg3_gdex_item const* parent, uint32_t tag) {
  bg3_gdex_iter iter;
  bg3_gdex_iter_init(&iter, parent);
  bg3_gdex_item* child;
  while ((child = bg3_gdex_iter_next(&iter))) {
    if (child->tag == tag) {
      return child;
    }
  }
  return 0;
}

void bg3_gts_reader_dump(bg3_gts_reader* reader) {
  printf("GTS version %d header %zu\n", reader->header.version, sizeof(reader->header));
  printf("unk offset %08llX\n", reader->header.levels_offset);
  printf("unk offset 2 %08llX\n", reader->header.thumbnails_offset);
  if (reader->header.thumbnails_offset) {
    bg3_gts_thumbnails_entry* thumb =
        (bg3_gts_thumbnails_entry*)(reader->data + reader->header.thumbnails_offset +
                                    0xC);
    uint32_t len;
    memcpy(&len, reader->data + reader->header.thumbnails_offset, sizeof(uint32_t));
    printf("thumbnail table # elements: %d (sizeof %zu)\n", len,
           sizeof(bg3_gts_thumbnails_entry));
    for (uint32_t i = 0; i < len; ++i) {
      char tmpbuf[48];
      bg3_uuid_to_string(&thumb[i].uuid, tmpbuf);
      printf("%s: %016llX %08X %08X (%d, %d)\n", tmpbuf, thumb[i].offset,
             thumb[i].thumbnail_length, thumb[i].miptail_length, thumb[i].width,
             thumb[i].height);
    }
  }
  printf("layers %d\n", reader->header.num_layers);
  printf("mip levels %d\n", reader->header.num_levels);
  printf("tile width %d tile height %d\n", reader->header.height, reader->header.width);
  printf("num param blocks %d\n", reader->header.num_parameter_blocks);
  printf("gdex offset (offset %zd) %016llX len %08X\n",
         offsetof(bg3_gts_header, gdex_offset), reader->header.gdex_offset,
         reader->header.gdex_len);
  LIBBG3_CHECK(reader->header.gdex_offset % 4 == 0, "gdex offset not aligned");
  LIBBG3_CHECK(reader->header.gdex_offset < reader->data_len,
               "gdex offset out of bounds");
  LIBBG3_CHECK(reader->header.gdex_offset + reader->header.gdex_len <= reader->data_len,
               "gdex data out of bounds");
  char* gdex = reader->data + reader->header.gdex_offset;
  bg3_gdex_item* gdex_root = (bg3_gdex_item*)gdex;
  bg3_gdex_item const* item = bg3_gdex_item_find_child(gdex_root, bg3_gdex_tag_atls);
  item = bg3_gdex_item_find_child(item, bg3_gdex_tag_txts);
  bg3_gdex_iter iter;
  bg3_gdex_iter_init(&iter, item);
  bg3_gdex_item* tex_item;
  int num_textures = 0;
  while ((tex_item = bg3_gdex_iter_next(&iter))) {
    if (tex_item->tag == bg3_gdex_tag_txtr) {
      num_textures++;
    }
  }
  printf("num_textures: %d\n", num_textures);
  bg3_indent_buffer ibuf;
  bg3_ibuf_init(&ibuf);
  bg3__gdex_dump(&ibuf, reader->data, gdex, gdex + reader->header.gdex_len);
  printf("%s\n", ibuf.output.data);
  for (size_t i = 0, offset = reader->header.levels_offset; i < reader->header.num_levels;
       ++i, offset += sizeof(bg3_gts_level_header)) {
    bg3_gts_level_header header;
    memcpy(&header, reader->data + offset, sizeof(bg3_gts_level_header));
    printf("level %zd: %d %d %016llX\n", i, header.x, header.y, header.offset);
  }
  for (size_t i = 0, offset = reader->header.parameter_blocks_offset;
       i < reader->header.num_parameter_blocks;
       ++i, offset += sizeof(bg3_gts_parameter_block_header)) {
    bg3_gts_parameter_block_header header;
    memcpy(&header, reader->data + offset, sizeof(bg3_gts_parameter_block_header));
    printf("param block %zd: %08X %08X %d %016llX\n", i, header.unk0[0], header.unk0[1],
           header.data_len, header.data_offset);
  }
  bg3_ibuf_destroy(&ibuf);
}

void bg3_sexp_token_copy(bg3_sexp_token* dest, bg3_sexp_token* src) {
  assert(dest != src);
  dest->type = src->type;
  bg3_buffer_copy(&dest->text, &src->text);
  dest->int_val = src->int_val;
  dest->line = src->line;
  dest->col = src->col;
  dest->len = src->len;
}

void bg3_sexp_lexer_copy(bg3_sexp_lexer* dest, bg3_sexp_lexer* src) {
  assert(dest != src);
  bg3_sexp_token_copy(&dest->next, &src->next);
  dest->line = src->line;
  dest->col = src->col;
  dest->c = src->c;
}

void bg3_sexp_lexer_init(bg3_sexp_lexer* lexer, char const* data, size_t data_len) {
  memset(lexer, 0, sizeof(bg3_sexp_lexer));
  lexer->line = 1;
  lexer->col = 0;
  bg3_cursor_init(&lexer->c, (char*)data, data_len);
}

void bg3_sexp_lexer_init_cstr(bg3_sexp_lexer* lexer, char const* text) {
  bg3_sexp_lexer_init(lexer, text, strlen(text));
}

void bg3_sexp_lexer_destroy(bg3_sexp_lexer* lexer) {
  bg3_buffer_destroy(&lexer->next.text);
}

static void sexp_lexer_begin_token(bg3_sexp_lexer* lexer, bg3_sexp_token_type type) {
  lexer->next.text.size = 0;
  lexer->next.type = type;
  lexer->next.line = lexer->line;
  lexer->next.col = lexer->col;
}

void bg3_sexp_lexer_advance(bg3_sexp_lexer* lexer) {
  enum {
    whitespace,
    comment,
    after_cr,
    after_lf,
    symbol,
    integer,
    decimal,
    string,
    string_escape,
    done,
  } state = whitespace;
#define CONSUME(new_state) \
  {                        \
    state = new_state;     \
    break;                 \
  }
#define REPARSE(new_state) \
  {                        \
    state = new_state;     \
    continue;              \
  }
  sexp_lexer_begin_token(lexer, bg3_sexp_token_type_eof);
  while (lexer->c.ptr < lexer->c.end && state != done) {
    char c = *lexer->c.ptr;
    switch (state) {
      case whitespace:
        if (c == ';') {
          REPARSE(comment);
        }
        if (c == '\n' || c == '\r') {
          lexer->line++;
          lexer->col = 0;
          CONSUME(c == '\n' ? after_lf : after_cr);
        }
        if (isspace(c)) {
          CONSUME(whitespace);
        }
        if (isdigit(c) || c == '-') {
          sexp_lexer_begin_token(lexer, bg3_sexp_token_type_integer);
          REPARSE(integer);
        }
        if (c == '\"') {
          state = string;
          sexp_lexer_begin_token(lexer, bg3_sexp_token_type_string);
          CONSUME(string);
        }
        if (c == '(' || c == '[') {
          sexp_lexer_begin_token(lexer, bg3_sexp_token_type_lparen);
          CONSUME(done);
        }
        if (c == ')' || c == ']') {
          sexp_lexer_begin_token(lexer, bg3_sexp_token_type_rparen);
          CONSUME(done);
        }
        if (c == '#') {
          sexp_lexer_begin_token(lexer, bg3_sexp_token_type_hash);
          CONSUME(done);
        }
        if (c != '.' && c != '{' && c != '}') {
          sexp_lexer_begin_token(lexer, bg3_sexp_token_type_symbol);
          REPARSE(symbol);
        }
        sexp_lexer_begin_token(lexer, bg3_sexp_token_type_invalid);
        REPARSE(done);
      case comment:
        if (c == '\n' || c == '\r') {
          REPARSE(whitespace);
        }
        CONSUME(comment);
      case after_cr:
        if (c == '\n') {
          lexer->col--;
          CONSUME(whitespace);
        }
        REPARSE(whitespace);
      case after_lf:
        if (c == '\r') {
          lexer->col--;
          CONSUME(whitespace);
        }
        REPARSE(whitespace);
      case symbol:
        if (isspace(c) || c == '\"' || c == '{' || c == '}' || c == '#' || c == '[' ||
            c == ']' || c == '(' || c == ')' || c == ';') {
          REPARSE(done);
        }
        bg3_buffer_putchar(&lexer->next.text, c);
        CONSUME(symbol);
      case integer:
        if (c == '.') {
          lexer->next.type = bg3_sexp_token_type_decimal;
          bg3_buffer_putchar(&lexer->next.text, '.');
          CONSUME(decimal);
        }
        // fall through
      case decimal:
        if (isdigit(c) || (c == '-' && lexer->next.text.size == 0)) {
          bg3_buffer_putchar(&lexer->next.text, c);
          CONSUME(state);
        }
        REPARSE(done);
      case string:
        if (c == '\\') {
          CONSUME(string_escape);
        }
        if (c == '"') {
          CONSUME(done);
        }
        if (c == '\r' || c == '\n') {
          // no multi-line strings atm
          sexp_lexer_begin_token(lexer, bg3_sexp_token_type_invalid);
          REPARSE(done);
        }
        bg3_buffer_putchar(&lexer->next.text, c);
        CONSUME(string);
      case string_escape:
        if (c == '\n') {
          bg3_buffer_putchar(&lexer->next.text, '\n');
        } else if (c == '\r') {
          bg3_buffer_putchar(&lexer->next.text, '\r');
        } else {
          bg3_buffer_putchar(&lexer->next.text, c);
        }
        CONSUME(string);
      default:
        assert(false && "unreachable");
        break;
    }
#undef CONSUME
#undef REPARSE
    lexer->col++;
    lexer->c.ptr++;
  }
  bg3_buffer_putchar(&lexer->next.text, 0);
  lexer->next.text.size--;
  if (lexer->next.type == bg3_sexp_token_type_integer) {
    lexer->next.int_val = strtoll(lexer->next.text.data, 0, 10);
  } else if (lexer->next.type == bg3_sexp_token_type_decimal) {
    lexer->next.float_val = strtod(lexer->next.text.data, 0);
  }
}

void bg3_ibuf_init(bg3_indent_buffer* buf) {
  memset(buf, 0, sizeof(bg3_indent_buffer));
}

void bg3_ibuf_destroy(bg3_indent_buffer* buf) {
  bg3_buffer_destroy(&buf->stack);
  bg3_buffer_destroy(&buf->tmp);
  bg3_buffer_destroy(&buf->output);
}

void bg3_ibuf_clear(bg3_indent_buffer* buf) {
  buf->stack.size = 0;
  buf->output.size = 0;
  buf->tmp.size = 0;
  buf->line_len = 0;
}

uint32_t bg3_ibuf_get_indent(bg3_indent_buffer* buf) {
  if (buf->stack.size) {
    size_t depth = buf->stack.size / sizeof(uint32_t);
    uint32_t* items = (uint32_t*)buf->stack.data;
    return items[depth - 1];
  }
  return 0;
}

uint32_t bg3_ibuf_get_next_col(bg3_indent_buffer* buf) {
  return buf->line_len ? buf->line_len : bg3_ibuf_get_indent(buf);
}

void bg3_ibuf_push_align(bg3_indent_buffer* buf) {
  bg3_ibuf_push(buf, buf->line_len - LIBBG3_MIN(buf->line_len, bg3_ibuf_get_indent(buf)));
}

void bg3_ibuf_push(bg3_indent_buffer* buf, uint32_t width) {
  width += bg3_ibuf_get_indent(buf);
  bg3_buffer_push(&buf->stack, &width, sizeof(uint32_t));
}

void bg3_ibuf_pop(bg3_indent_buffer* buf) {
  bg3_buffer_pop(&buf->stack, sizeof(uint32_t));
}

static void ibuf_putchar(bg3_indent_buffer* buf, char c) {
  if (c == '\n') {
    buf->line_len = 0;
  } else if (!buf->line_len) {
    uint32_t level = bg3_ibuf_get_indent(buf);
    for (uint32_t i = 0; i < level; ++i) {
      bg3_buffer_putchar(&buf->output, ' ');
    }
    buf->line_len = level;
  }
  if (c != '\n') {
    buf->line_len++;
  }
  bg3_buffer_putchar(&buf->output, c);
}

void bg3_ibuf_fresh_line(bg3_indent_buffer* buf) {
  if (buf->line_len) {
    ibuf_putchar(buf, '\n');
  }
}

void bg3_ibuf_vprintf(bg3_indent_buffer* buf, char const* fmt, va_list args) {
  buf->tmp.size = 0;
  bg3_buffer_vprintf(&buf->tmp, fmt, args);
  for (int i = 0; i < buf->tmp.size; ++i) {
    ibuf_putchar(buf, buf->tmp.data[i]);
  }
}

void bg3_ibuf_printf(bg3_indent_buffer* buf, char const* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  bg3_ibuf_vprintf(buf, fmt, ap);
  va_end(ap);
}

typedef struct index_pak_work {
  char* name;
  bool failed;
  bg3_mapped_file mapped;
  bg3_lspk_file file;
} index_pak_work;

typedef struct index_work_item {
  size_t pak_idx;
  bg3_lspk_manifest_entry* entry;
} index_work_item;

typedef struct index_symtab_entry {
  uint32_t item_idx;
  uint32_t item_val;
  uint32_t prev_idx;
  uint32_t next_idx;
} index_symtab_entry;

typedef struct index_symtab {
  bg3_hash lookup;
  size_t num_entries;
  size_t cap_entries;
  index_symtab_entry* entries;
} index_symtab;

typedef struct index_per_thread {
  bg3_arena tmp;
  size_t num_items;
  size_t cap_items;
  index_work_item* items;
  index_symtab symtab;
  size_t num_merge_entries;
  bg3_hash_entry* merge_entries;
  bool owns_merge_entries;
} index_per_thread;

typedef struct index_global {
  int argc;
  char const** argv;
  bool failed;
  size_t num_paks;
  size_t cap_paks;
  index_pak_work* paks;
  size_t num_items;
  index_work_item* items;
  index_per_thread* threads;
  size_t num_merge_buffer_entries_per_side;
  bg3_hash_entry* merge_buffer;
} index_global;

static void index_symtab_init(index_symtab* symtab, bg3_arena* a) {
  bg3_hash_init(&symtab->lookup, &bg3_symtab_case_hash_ops, a);
}

static void index_symtab_destroy(index_symtab* symtab) {
  bg3_hash_destroy(&symtab->lookup);
}

static int index_lookup_compare(void const* lhs, void const* rhs) {
  bg3_hash_entry const* left = (bg3_hash_entry const*)lhs;
  bg3_hash_entry const* right = (bg3_hash_entry const*)rhs;
  bool is_left_dead =
      left->key == LIBBG3_HASH_TOMBSTONE_VALUE || left->key == LIBBG3_HASH_EMPTY_VALUE;
  bool is_right_dead =
      right->key == LIBBG3_HASH_TOMBSTONE_VALUE || right->key == LIBBG3_HASH_EMPTY_VALUE;
  if (!is_left_dead && is_right_dead) {
    return -1;
  } else if (is_left_dead && !is_right_dead) {
    return 1;
  } else if (is_left_dead && is_right_dead) {
    return 0;
  }
  return strcmp((char const*)left->key, (char const*)right->key);
}

#define PACK_SYMVAL(x)   (assert((uintptr_t)(x) <= UINT32_MAX), (uint32_t)(uintptr_t)(x))
#define UNPACK_SYMVAL(x) ((void*)(uintptr_t)(x))

static index_symtab_entry* index_symtab_get_global(index_global* global, void* symval) {
  return &global->threads[LIBBG3_SYMBOL_TYPE_OF(symval)]
              .symtab.entries[LIBBG3_SYMBOL_INDEX_OF(symval)];
}

static void index_symtab_link_symbols(index_global* global,
                                      void* left_symval,
                                      void* right_symval) {
  index_symtab_entry* left = index_symtab_get_global(global, left_symval);
  index_symtab_entry* right = index_symtab_get_global(global, right_symval);
  index_symtab_entry* right_prev =
      index_symtab_get_global(global, UNPACK_SYMVAL(right->prev_idx));
  index_symtab_entry* left_next =
      index_symtab_get_global(global, UNPACK_SYMVAL(left->next_idx));
  left_next->prev_idx = right->prev_idx;
  right_prev->next_idx = left->next_idx;
  left->next_idx = PACK_SYMVAL(right_symval);
  right->prev_idx = PACK_SYMVAL(left_symval);
}

// destructively modifies str.
static void index_symtab_enter_string(index_symtab* symtab,
                                      index_global* global,
                                      size_t item_idx,
                                      int thread_num,
                                      char* str,
                                      bool case_convert,
                                      uint32_t item_val) {
  if (*str == '\0') {
    return;
  }
  if (case_convert) {
    for (char* p = str; *p; ++p) {
      *p = tolower(*p);
    }
  }
  assert(symtab->num_entries <= 0xFFFFFF);
  void* symval = LIBBG3_MAKE_SYMBOL_VALUE(thread_num, symtab->num_entries);
  index_symtab_entry entry = {
      .item_idx = (uint32_t)item_idx,
      .item_val = item_val,
      .prev_idx = PACK_SYMVAL(symval),
      .next_idx = PACK_SYMVAL(symval),
  };
  LIBBG3_ARRAY_PUSH((bg3_arena*)symtab->lookup.user_data, symtab, entries, entry);
  bg3_hash_entry* existing;
  if (!bg3_hash_try_set(&symtab->lookup, str, symval, &existing)) {
    index_symtab_link_symbols(global, existing->value, symval);
  }
}

static void index_symtab_enter_attr(index_symtab* symtab,
                                    index_global* global,
                                    bg3_lsof_reader* reader,
                                    size_t item_idx,
                                    int thread_num,
                                    size_t node_idx,
                                    size_t attr_idx,
                                    size_t attr_idx_in_node,
                                    bg3_lsof_attr_wide* attr) {
  if (attr_idx_in_node > 255) {
    return;
  }
  bool is_wide =
      LIBBG3_IS_SET(reader->header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS);
  uint32_t item_val = (node_idx << 8) | attr_idx;
  size_t offset = is_wide ? attr->value : reader->value_offsets[attr_idx];
  char* raw_attr = reader->value_table_raw + offset;
  char tmpbuf[48];
  switch (attr->type) {
    case bg3_lsof_dt_fixedstring:
    case bg3_lsof_dt_lsstring:
      index_symtab_enter_string(symtab, global, item_idx, thread_num, raw_attr, true,
                                item_val);
      break;
    case bg3_lsof_dt_translatedstring: {
      uint16_t version;
      uint32_t string_len;
      memcpy(&version, raw_attr, sizeof(uint16_t));
      memcpy(&string_len, raw_attr + 2, sizeof(uint32_t));
      string_len = LIBBG3_MIN(string_len, 47);
      memcpy(tmpbuf, raw_attr + 6, string_len);
      tmpbuf[string_len] = 0;
      if (*tmpbuf == 'h') {
        index_symtab_enter_string(symtab, global, item_idx, thread_num, tmpbuf, false,
                                  item_val);
      }
      break;
    }
    case bg3_lsof_dt_uuid: {
      bg3_uuid id;
      if (attr->length != sizeof(bg3_uuid)) {
        break;
      }
      memcpy(&id, raw_attr, sizeof(id));
      bg3_uuid_to_string(&id, tmpbuf);
      index_symtab_enter_string(symtab, global, item_idx, thread_num, tmpbuf, false,
                                item_val);
      break;
    }
  }
}

static int index_worker(bg3_parallel_for_thread* tcb) {
  index_global* global = (index_global*)tcb->user_data;
  index_per_thread* local = global->threads + tcb->thread_num;
  bg3_arena_init(&local->tmp, 1024 * 1024, 1024);
  // Phase 1: gather pak files
  if (!tcb->thread_num) {
    for (int i = 1; i < global->argc - 1; ++i) {
      DIR* dir = opendir(global->argv[i]);
      if (!dir) {
        perror("opendir");
        global->failed = true;
      } else {
        struct dirent* de;
        while ((de = readdir(dir))) {
          if (bg3_strcasesuffix(de->d_name, ".pak")) {
            index_pak_work work = {
                .name =
                    bg3_arena_sprintf(&local->tmp, "%s/%s", global->argv[i], de->d_name),
            };
            LIBBG3_ARRAY_PUSH(&local->tmp, global, paks, work);
          }
        }
        closedir(dir);
      }
    }
  }
  bg3_sync_threads(tcb);
  if (global->failed) {
    return (int)bg3_error_failed;
  }
  // Phase 2: load pak files
  for (int i = tcb->thread_num; i < global->num_paks; i += tcb->thread_count) {
    index_pak_work* pak_work = global->paks + i;
    if (bg3_mapped_file_init_ro(&pak_work->mapped, pak_work->name)) {
      pak_work->failed = true;
    }
    if (!pak_work->failed && bg3_lspk_file_init(&pak_work->file, &pak_work->mapped)) {
      bg3_mapped_file_destroy(&pak_work->mapped);
      pak_work->failed = true;
    }
    if (!pak_work->failed) {
      for (size_t j = 0; j < pak_work->file.num_files; ++j) {
        bg3_lspk_manifest_entry* entry = pak_work->file.manifest + j;
        if (bg3_strcasesuffix(entry->name, ".lsf") ||
            bg3_strcasesuffix(entry->name, ".loca")) {
          index_work_item work = {.pak_idx = (size_t)i, .entry = entry};
          LIBBG3_ARRAY_PUSH(&local->tmp, local, items, work);
        }
      }
    }
  }
  bg3_sync_threads(tcb);
  // Phase 3: gather global file list
  if (!tcb->thread_num) {
    size_t total_entries = 0, next_entry = 0;
    for (int i = 0; i < tcb->thread_count; ++i) {
      total_entries += global->threads[i].num_items;
    }
    index_work_item* global_items = (index_work_item*)bg3_arena_alloc(
        &local->tmp, sizeof(index_work_item) * total_entries);
    for (int i = 0; i < tcb->thread_count; ++i) {
      memcpy(global_items + next_entry, global->threads[i].items,
             sizeof(index_work_item) * global->threads[i].num_items);
      next_entry += global->threads[i].num_items;
    }
    global->num_items = total_entries;
    global->items = global_items;
  }
  bg3_sync_threads(tcb);
  // Phase 4: build per-thread indices
  index_symtab_init(&local->symtab, &local->tmp);
  for (int i = tcb->thread_num; i < global->num_items; i += tcb->thread_count) {
    bg3_lspk_file* lspk = &global->paks[global->items[i].pak_idx].file;
    bg3_lspk_manifest_entry* entry = global->items[i].entry;
    char* data = 0;
    size_t data_len = 0;
    bool owns_data = false;
    if (LIBBG3_LSPK_ENTRY_COMPRESSION_METHOD(entry->compression)) {
      if (bg3_lspk_file_extract(lspk, entry, 0, &data_len) != bg3_error_overflow) {
        goto file_out;
      }
      data = (char*)malloc(data_len);
      owns_data = true;
      if (bg3_lspk_file_extract(lspk, entry, data, &data_len)) {
        goto file_out;
      }
    } else {
      size_t entry_offset = ((size_t)entry->offset_hi << 32) | entry->offset_lo;
      data_len = entry->compressed_size;
      data = lspk->mapped->data + entry_offset;
    }
    if (bg3_strcasesuffix(entry->name, ".lsf")) {
      bg3_lsof_reader reader;
      if (bg3_lsof_reader_init(&reader, data, data_len)) {
        goto file_out;
      }
      bg3_lsof_reader_ensure_value_offsets(&reader);
      bool is_wide =
          LIBBG3_IS_SET(reader.header.flags, LIBBG3_LSOF_FLAG_HAS_SIBLING_POINTERS);
      for (size_t node_idx = 0; node_idx < reader.num_nodes; ++node_idx) {
        bg3_lsof_node_wide node;
        bg3_lsof_reader_get_node(&reader, &node, node_idx);
        size_t attr_idx = node.attrs;
        size_t attr_index_in_node = 0;
        while (attr_idx != -1) {
          bg3_lsof_attr_wide attr;
          bg3_lsof_reader_get_attr(&reader, &attr, attr_idx);
          if (!is_wide && attr.owner != node_idx) {
            break;
          }
          index_symtab_enter_attr(&local->symtab, global, &reader, i, tcb->thread_num,
                                  node_idx, attr_idx, attr_index_in_node, &attr);
          if (!is_wide) {
            attr_idx++;
            if (attr_idx >= reader.num_attrs) {
              attr_idx = -1;
            }
          } else {
            attr_idx = attr.next;
          }
          attr_index_in_node++;
        }
      }
      bg3_lsof_reader_destroy(&reader);
    } else if (bg3_strcasesuffix(entry->name, ".loca")) {
      bg3_loca_reader reader;
      if (bg3_loca_reader_init(&reader, data, data_len)) {
        goto file_out;
      }
      for (uint32_t entry_idx = 0; entry_idx < reader.header.num_entries; ++entry_idx) {
        index_symtab_enter_string(&local->symtab, global, i, tcb->thread_num,
                                  reader.entries[entry_idx].handle, true, entry_idx);
        index_symtab_enter_string(&local->symtab, global, i, tcb->thread_num,
                                  reader.entries[entry_idx].data, true, entry_idx);
      }
      bg3_loca_reader_destroy(&reader);
    } else {
      bg3_panic("collected a file extension we don't know how to handle");
    }
  file_out:
    if (owns_data) {
      free(data);
    }
  }
  // yoink the buffer out of the hash table
  qsort(local->symtab.lookup.entries, local->symtab.lookup.table_size,
        sizeof(bg3_hash_entry), index_lookup_compare);
  local->num_merge_entries = local->symtab.lookup.num_keys;
  local->merge_entries = local->symtab.lookup.entries;
  local->owns_merge_entries = true;
  local->symtab.lookup.entries = 0;
  local->symtab.lookup.table_size = 0;
  local->symtab.lookup.num_keys = 0;
  bg3_sync_threads(tcb);
  // Phase 5: Merge setup: allocate the merge buffer
  if (!tcb->thread_num) {
    size_t total_entries = 0;
    for (int i = 0; i < tcb->thread_count; ++i) {
      total_entries += global->threads[i].num_merge_entries;
    }
    global->num_merge_buffer_entries_per_side = total_entries;
    global->merge_buffer = (bg3_hash_entry*)bg3_arena_alloc(
        &local->tmp, total_entries * 2 * sizeof(bg3_hash_entry));
  }
  // Phase 6: Merge per-thread sorted entry arrays
  int num_streams = bg3__next_power_of_2(tcb->thread_count);
  for (int stride = 2, step = 0; num_streams > 1;
       stride <<= 1, num_streams >>= 1, step++) {
    bg3_sync_threads(tcb);  // wait for streams to be ready
    int left_stream = tcb->thread_num * stride, right_stream = left_stream + (stride / 2);
    size_t new_num_merge_entries = 0;
    bg3_hash_entry* new_merge_entries = 0;
    if (left_stream < tcb->thread_count && right_stream < tcb->thread_count) {
      bg3_hash_entry* output = global->merge_buffer;
      if (step & 1) {
        output += global->num_merge_buffer_entries_per_side;
      }
      for (int i = 0; i < tcb->thread_num; ++i) {
        int other_left = i * stride, other_right = other_left + (stride / 2);
        output += global->threads[other_left].num_merge_entries;
        output += global->threads[other_right].num_merge_entries;
      }
      bg3_hash_entry* output_base = output;
      index_per_thread* left_thread = global->threads + left_stream;
      index_per_thread* right_thread = global->threads + right_stream;
      bg3_hash_entry* left_input = left_thread->merge_entries;
      bg3_hash_entry* left_input_end = left_input + left_thread->num_merge_entries;
      bg3_hash_entry* right_input = right_thread->merge_entries;
      bg3_hash_entry* right_input_end = right_input + right_thread->num_merge_entries;
      while (left_input < left_input_end && right_input < right_input_end) {
        int rel = strcmp((char const*)left_input->key, (char const*)right_input->key);
        if (rel < 0) {
          *(output++) = *(left_input++);
        } else if (rel > 0) {
          *(output++) = *(right_input++);
        } else {
          index_symtab_link_symbols(global, left_input->value, right_input->value);
          *(output++) = *(left_input++);
          right_input++;
        }
      }
      size_t remainder = 0;
      if (left_input < left_input_end) {
        remainder = left_input_end - left_input;
        memcpy(output, left_input, remainder * sizeof(bg3_hash_entry));
      } else if (right_input < right_input_end) {
        remainder = right_input_end - right_input;
        memcpy(output, right_input, remainder * sizeof(bg3_hash_entry));
      }
      output += remainder;
      new_merge_entries = output_base;
      new_num_merge_entries = output - output_base;
    }
    if (new_merge_entries) {
      index_per_thread* left_thread = global->threads + left_stream;
      index_per_thread* right_thread = global->threads + right_stream;
      if (left_thread->owns_merge_entries) {
        free(left_thread->merge_entries);
        left_thread->owns_merge_entries = false;
      }
      if (right_thread->owns_merge_entries) {
        free(right_thread->merge_entries);
        right_thread->owns_merge_entries = false;
      }
      left_thread->merge_entries = new_merge_entries;
      left_thread->num_merge_entries = new_num_merge_entries;
      right_thread->merge_entries = 0;
      right_thread->num_merge_entries = 0;
    }
  }
  return 0;
}

// TODO: make this into an api
bg3_status bg3_index_build(int argc, char const** argv) {
  if (argc < 3) {
    fprintf(stderr, "syntax: %s <data path>... <index file>\n", argv[0]);
    return bg3_error_failed;
  }
  int nthreads = LIBBG3_MIN(128, 2 * bg3_parallel_for_ncpu());
  index_global global = {.argc = argc, .argv = argv};
  global.threads = (index_per_thread*)alloca(sizeof(index_per_thread) * nthreads);
  memset(global.threads, 0, sizeof(index_per_thread) * nthreads);
  bg3_parallel_for_n(index_worker, &global, nthreads);
  // Phase 7: linearize the index
  bg3_buffer entry_heap = {};
  bg3_buffer string_heap = {};
  bg3_buffer match_heap = {};
  for (size_t i = 0; i < global.threads[0].num_merge_entries; ++i) {
    bg3_hash_entry* entry = global.threads[0].merge_entries + i;
    bg3_index_entry ie = {
        .string_offset = (uint32_t)string_heap.size,
        .string_len = (uint32_t)strlen((char const*)entry->key),
        .match_index = (uint32_t)(match_heap.size / sizeof(bg3_index_match_entry)),
    };
    void *symval = entry->value, *start = symval;
    do {
      index_symtab_entry* se = index_symtab_get_global(&global, symval);
      bg3_index_match_entry me = {
          .file_idx = se->item_idx,
          .value = se->item_val,
      };
      ie.match_len++;
      bg3_buffer_push(&match_heap, &me, sizeof(bg3_index_match_entry));
      symval = UNPACK_SYMVAL(se->next_idx);
    } while (symval != start);
    bg3_buffer_push(&entry_heap, &ie, sizeof(bg3_index_entry));
    bg3_buffer_push(&string_heap, entry->key, ie.string_len);
  }
  size_t mapped_size = sizeof(bg3_index_header) +
                       global.num_paks * sizeof(bg3_index_pak_entry) +
                       global.num_items * sizeof(bg3_index_file_entry) + entry_heap.size +
                       string_heap.size + match_heap.size;
  // Phase 8: write output file
  bg3_mapped_file output;
  if (bg3_mapped_file_init_rw_trunc(&output, argv[argc - 1], mapped_size)) {
    perror("mapped_file_init_rw_trunc");
    return bg3_error_failed;
  }
  bg3_index_header* header = (bg3_index_header*)output.data;
  header->magic = LIBBG3_INDEX_MAGIC;
  header->version = LIBBG3_INDEX_VERSION;
  header->num_paks = global.num_paks;
  header->num_files = global.num_items;
  header->num_entries = entry_heap.size / sizeof(bg3_index_entry);
  header->num_matches = match_heap.size / sizeof(bg3_index_match_entry);
  header->strings_len = string_heap.size;
  bg3_index_pak_entry* paks = (bg3_index_pak_entry*)(header + 1);
  for (uint32_t i = 0; i < header->num_paks; ++i) {
    snprintf(paks[i].name, sizeof(paks[i].name), "%s", global.paks[i].name);
  }
  bg3_index_file_entry* files = (bg3_index_file_entry*)(paks + header->num_paks);
  for (uint32_t i = 0; i < header->num_files; ++i) {
    files[i].pak_idx = global.items[i].pak_idx;
    snprintf(files[i].name, sizeof(files[i].name), "%s", global.items[i].entry->name);
  }
  bg3_index_entry* entries = (bg3_index_entry*)(files + header->num_files);
  memcpy(entries, entry_heap.data, entry_heap.size);
  bg3_index_match_entry* matches =
      (bg3_index_match_entry*)(entries + header->num_entries);
  memcpy(matches, match_heap.data, match_heap.size);
  char* strings = (char*)(matches + header->num_matches);
  memcpy(strings, string_heap.data, string_heap.size);
  bg3_mapped_file_destroy(&output);
  return bg3_error_failed;
}

bg3_status bg3_index_reader_init(bg3_index_reader* reader, char* data, size_t data_len) {
  memset(reader, 0, sizeof(bg3_index_reader));
  if (data_len < sizeof(bg3_index_header)) {
    return bg3_error_bad_magic;
  }
  memcpy(&reader->header, data, sizeof(bg3_index_header));
  if (reader->header.magic != LIBBG3_INDEX_MAGIC) {
    return bg3_error_bad_magic;
  }
  if (reader->header.version != LIBBG3_INDEX_VERSION) {
    return bg3_error_bad_version;
  }
  reader->paks = (bg3_index_pak_entry*)(data + sizeof(bg3_index_header));
  reader->files = (bg3_index_file_entry*)(reader->paks + reader->header.num_paks);
  reader->entries = (bg3_index_entry*)(reader->files + reader->header.num_files);
  reader->matches =
      (bg3_index_match_entry*)(reader->entries + reader->header.num_entries);
  reader->strings = (char*)(reader->matches + reader->header.num_matches);
  return bg3_success;
}

void bg3_index_reader_destroy(bg3_index_reader* reader) {
  // nothing to do
}

bg3_index_entry* bg3_index_reader_find_entry(bg3_index_reader* reader,
                                             uint32_t string_idx) {
  if (!reader->header.num_entries) {
    return 0;
  }
  uint32_t lo = 0, hi = reader->header.num_entries - 1;
  while (lo <= hi) {
    uint32_t mid = lo + ((hi - lo) / 2);
    bg3_index_entry* entry = reader->entries + mid;
    uint32_t upper_bound = entry->string_offset + entry->string_len - 1;
    uint32_t lower_bound = entry->string_offset;
    if (string_idx > upper_bound) {
      lo = mid + 1;
    } else if (string_idx < lower_bound) {
      hi = mid - 1;
    } else {
      return entry;
    }
  }
  return 0;
}

typedef struct index_search_thread {
  bg3_arena tmp;
  bg3_index_reader* reader;
  char const* needle;
  size_t num_entries;
  size_t cap_entries;
  bg3_index_entry** entries;
} index_search_thread;

static int bg3_index_reader_search_worker(bg3_parallel_for_thread* tcb) {
  index_search_thread* local = ((index_search_thread*)tcb->user_data) + tcb->thread_num;
  char const* needle = local->needle;
  int nlen = strlen(local->needle);
  uint32_t chunk_size = local->reader->header.strings_len / tcb->thread_count;
  uint32_t offset = chunk_size * tcb->thread_num;
  uint32_t end =
      LIBBG3_MIN(local->reader->header.strings_len, offset + chunk_size + nlen);
  char const* haystack = local->reader->strings + offset;
  int hlen = end - offset;
  int skip[256], i, j, k;
  if (!nlen || nlen > hlen) {
    return (int)bg3_success;
  }
  for (i = 0; i < 256; ++i) {
    skip[i] = nlen;
  }
  for (i = 0; i < nlen - 1; ++i) {
    skip[needle[i] & 0xFF] = nlen - i - 1;
  }
  k = nlen - 1;
  while (k < hlen) {
    for (j = nlen - 1, i = k; j >= 0 && needle[j] == haystack[i]; --j, --i)
      ;
    if (j == -1) {
      bg3_index_entry* entry = bg3_index_reader_find_entry(local->reader, offset + i + 1);
      assert(entry);
      if (offset + i + 1 <= entry->string_offset + entry->string_len) {
        LIBBG3_ARRAY_PUSH(&local->tmp, local, entries, entry);
      }
      k += nlen;
    } else {
      k += skip[haystack[k] & 0xFF];
    }
  }
  return (int)bg3_success;
}

void bg3_index_reader_query(bg3_index_reader* reader,
                            bg3_index_search_results* results,
                            char const* query) {
  int nthreads = bg3_parallel_for_ncpu();
  index_search_thread* threads =
      (index_search_thread*)alloca(nthreads * sizeof(index_search_thread));
  memset(threads, 0, sizeof(index_search_thread) * nthreads);
  char* term = strdup(query);
  for (char* p = term; *p; ++p) {
    *p = tolower(*p);
  }
  for (int i = 0; i < nthreads; ++i) {
    bg3_arena_init(&threads[i].tmp, 1024 * 1024, 1024);
    threads[i].needle = term;
    threads[i].reader = reader;
  }
  bg3_parallel_for(bg3_index_reader_search_worker, threads);
  memset(results, 0, sizeof(bg3_index_search_results));
  for (int i = 0; i < nthreads; ++i) {
    for (size_t j = 0; j < threads[i].num_entries; ++j) {
      results->num_hits += threads[i].entries[j]->match_len;
    }
  }
  results->hits =
      (bg3_index_search_hit*)calloc(results->num_hits, sizeof(bg3_index_search_hit));
  int next_hit = 0;
  for (int i = 0; i < nthreads; ++i) {
    for (size_t j = 0; j < threads[i].num_entries; ++j) {
      bg3_index_entry* entry = threads[i].entries[j];
      for (size_t k = 0; k < entry->match_len; ++k) {
        bg3_index_search_hit* hit = results->hits + next_hit++;
        bg3_index_match_entry* match_entry = reader->matches + entry->match_index + k;
        hit->file = reader->files + match_entry->file_idx;
        hit->pak = reader->paks + hit->file->pak_idx;
        hit->value = match_entry->value;
      }
    }
  }
  for (int i = 0; i < nthreads; ++i) {
    bg3_arena_destroy(&threads[i].tmp);
  }
  free(term);
}

void bg3_index_search_results_destroy(bg3_index_search_results* results) {
  free(results->hits);
}

static uint32_t aigrid_uuid_hash(bg3_uuid* id) {
  union {
    bg3_uuid id;
    struct {
      uint64_t lo;
      uint64_t hi;
    };
  } u;
  u.id = *id;
  uint64_t xor64 = u.lo ^ u.hi;
  uint32_t xor32 = ((uint32_t)(xor64 >> 32)) ^ ((uint32_t)xor64);
  return xor32;
}

bg3_status bg3_aigrid_file_init(bg3_aigrid_file* file, char* data, size_t data_len) {
  bg3_aigrid_file_init_new(file);
  bg3_cursor_init(&file->c, data, data_len);
  if (data_len < sizeof(bg3_aigrid_header)) {
    return bg3_error_bad_version;
  }
  bg3_cursor_read(&file->c, &file->header, sizeof(bg3_aigrid_header));
  if (file->header.version != LIBBG3_AIGRID_VERSION) {
    return bg3_error_bad_version;
  }
  bg3_cursor_read(&file->c, file->file_uuid, LIBBG3_UUID_STRING_LEN);
  bg3_cursor_read(&file->c, &file->num_subgrids, sizeof(uint32_t));
  file->cap_subgrids = file->num_subgrids;
  file->subgrids = (bg3_aigrid_subgrid*)bg3_arena_calloc(&file->alloc, file->num_subgrids,
                                                         sizeof(bg3_aigrid_subgrid));
  for (uint32_t i = 0; i < file->num_subgrids; ++i) {
    bg3_aigrid_subgrid* subgrid = file->subgrids + i;
    bg3_cursor_read(&file->c, &subgrid->header, sizeof(bg3_aigrid_subgrid_header));
    bg3_cursor_read(&file->c, subgrid->object_uuid, LIBBG3_UUID_STRING_LEN);
    bg3_cursor_read(&file->c, subgrid->template_uuid, LIBBG3_UUID_STRING_LEN);
    uint32_t uncompressed_len, compressed_len;
    bg3_cursor_read(&file->c, &uncompressed_len, sizeof(uncompressed_len));
    bg3_cursor_read(&file->c, &compressed_len, sizeof(compressed_len));
    unsigned long src_len = compressed_len, need_len = uncompressed_len;
    uint8_t* inflate_tmp = (uint8_t*)malloc(uncompressed_len);
    uint8_t* compressed_data = (uint8_t*)file->c.ptr;
    bg3_cursor_read(&file->c, 0, compressed_len);
    if (mz_uncompress2(inflate_tmp, &need_len, compressed_data, &src_len) == MZ_OK) {
      int lz4_uncompressed_len =
          subgrid->header.width * subgrid->header.height * sizeof(bg3_aigrid_tile);
      subgrid->tiles =
          (bg3_aigrid_tile*)bg3_arena_alloc(&file->alloc, lz4_uncompressed_len);
      int status = LZ4_decompress_safe((char*)inflate_tmp, (char*)subgrid->tiles,
                                       uncompressed_len, lz4_uncompressed_len);
      if (status <= 0) {
        free(subgrid->tiles);
        subgrid->tiles = 0;
      }
    }
    free(inflate_tmp);
  }
  bg3_cursor_read(&file->c, &file->num_layers, sizeof(uint32_t));
  file->cap_layers = file->num_layers;
  file->layers = (bg3_aigrid_layer*)bg3_arena_calloc(&file->alloc, file->num_layers,
                                                     sizeof(bg3_aigrid_layer));
  for (uint32_t i = 0; i < file->num_layers; ++i) {
    bg3_aigrid_layer* layer = file->layers + i;
    bg3_cursor_read(&file->c, &layer->level_template, sizeof(bg3_uuid));
    bg3_cursor_read(&file->c, &layer->num_entries, sizeof(uint32_t));
    layer->cap_entries = layer->num_entries;
    layer->entries = (bg3_aigrid_layer_entry*)bg3_arena_calloc(
        &file->alloc, layer->num_entries, sizeof(bg3_aigrid_layer));
    char tmpbuf[48];
    bg3_uuid_to_string(&layer->level_template, tmpbuf);
    bg3_cursor_read(&file->c, layer->entries,
                    layer->num_entries * sizeof(bg3_aigrid_layer_entry));
  }
  assert(file->c.ptr == file->c.end);
  return bg3_success;
}

static inline int16_t quantize_float_int16(float float_val) {
  return (int16_t)(float_val * 100.0f * 0.5f + 0.5f);
}

void bg3_aigrid_file_destroy(bg3_aigrid_file* file) {
  bg3_arena_destroy(&file->alloc);
}

void bg3_aigrid_file_init_new(bg3_aigrid_file* file) {
  memset(file, 0, sizeof(bg3_aigrid_file));
  file->header.version = LIBBG3_AIGRID_VERSION;
  bg3_arena_init(&file->alloc, 1024 * 1024, 1024);
}

bg3_aigrid_subgrid* bg3_aigrid_file_create_subgrid(bg3_aigrid_file* file,
                                                   uint32_t width,
                                                   uint32_t height,
                                                   bg3_uuid* object_uuid,
                                                   bg3_uuid* template_uuid,
                                                   int16_t tile_x,
                                                   int16_t tile_y,
                                                   bg3_vec3 world_pos) {
  union {
    struct {
      int16_t x, y;
    };
    uint32_t uval;
  } subgrid_id_offset;
  subgrid_id_offset.x = tile_x;
  subgrid_id_offset.y = tile_y;
  bg3_aigrid_subgrid sg = {
      .header =
          {
              .subgrid_id = aigrid_uuid_hash(object_uuid) + subgrid_id_offset.uval,
              .width = width,
              .height = height,
              .x = roundf(world_pos[0] * 2.f) * 0.5f,
              .y = world_pos[1],
              .z = roundf(world_pos[2] * 2.f) * 0.5f,
          },
      .tiles = (bg3_aigrid_tile*)bg3_arena_calloc(&file->alloc, width * height,
                                                  sizeof(bg3_aigrid_tile)),
  };
  char tmpbuf[48];
  bg3_uuid_to_string(object_uuid, tmpbuf);
  snprintf(sg.object_uuid, LIBBG3_UUID_STRING_LEN, "%s", tmpbuf);
  bg3_uuid_to_string(template_uuid, tmpbuf);
  snprintf(sg.template_uuid, LIBBG3_UUID_STRING_LEN, "%s", tmpbuf);
  LIBBG3_ARRAY_PUSH(&file->alloc, file, subgrids, sg);
  return &file->subgrids[file->num_subgrids - 1];
}

bg3_status bg3_aigrid_file_write(bg3_aigrid_file* file, char const* path) {
  bg3_status status = bg3_success;
  bg3_buffer out = {};
  bg3_buffer_push(&out, &file->header, sizeof(bg3_aigrid_header));
  bg3_buffer_push(&out, file->file_uuid, LIBBG3_UUID_STRING_LEN);
  bg3_buffer_push(&out, &file->num_subgrids, sizeof(uint32_t));
  for (uint32_t i = 0; i < file->num_subgrids; ++i) {
    bg3_aigrid_subgrid* subgrid = file->subgrids + i;
    bg3_buffer_push(&out, &subgrid->header, sizeof(bg3_aigrid_subgrid_header));
    bg3_buffer_push(&out, subgrid->object_uuid, LIBBG3_UUID_STRING_LEN);
    bg3_buffer_push(&out, subgrid->template_uuid, LIBBG3_UUID_STRING_LEN);
    int src_size =
        sizeof(bg3_aigrid_tile) * subgrid->header.width * subgrid->header.height;
    int lz4_bound = LZ4_compressBound(src_size);
    char* lz4_compress_buf = (char*)malloc(lz4_bound);
    int lz4_result = LZ4_compress_default((char*)subgrid->tiles, lz4_compress_buf,
                                          src_size, lz4_bound);
    if (lz4_result < 0) {
      free(lz4_compress_buf);
      status = bg3_error_failed;
      goto out_free_buf;
    }
    mz_ulong deflate_len = mz_compressBound(lz4_result);
    uint8_t* deflate_compress_buf = (uint8_t*)malloc(deflate_len);
    int deflate_status = mz_compress(deflate_compress_buf, &deflate_len,
                                     (uint8_t*)lz4_compress_buf, lz4_result);
    free(lz4_compress_buf);
    if (deflate_status != MZ_OK) {
      free(deflate_compress_buf);
      status = bg3_error_failed;
      goto out_free_buf;
    }
    bg3_buffer_push(&out, &lz4_result, sizeof(uint32_t));
    bg3_buffer_push(&out, &deflate_len, sizeof(uint32_t));
    bg3_buffer_push(&out, deflate_compress_buf, deflate_len);
    free(deflate_compress_buf);
  }
  bg3_buffer_push(&out, &file->num_layers, sizeof(uint32_t));
  for (uint32_t i = 0; i < file->num_layers; ++i) {
    bg3_aigrid_layer* layer = file->layers + i;
    bg3_buffer_push(&out, &layer->level_template, sizeof(bg3_uuid));
    bg3_buffer_push(&out, &layer->num_entries, sizeof(uint32_t));
    bg3_buffer_push(&out, layer->entries,
                    sizeof(bg3_aigrid_layer_entry) * layer->num_entries);
  }
  bg3_mapped_file mapped;
  if ((status = bg3_mapped_file_init_rw_trunc(&mapped, path, out.size))) {
    goto out_free_buf;
  }
  memcpy(mapped.data, out.data, out.size);
  bg3_mapped_file_destroy(&mapped);
out_free_buf:
  bg3_buffer_destroy(&out);
  return status;
}

void bg3_aigrid_file_cook_patch(bg3_aigrid_file* file,
                                bg3_uuid* object_uuid,
                                bg3_vec3 world_pos,
                                bg3_patch_file* patch) {
  float minval = INFINITY;
  for (size_t i = 0; i < patch->metadata.local_cols * patch->metadata.local_rows; ++i) {
    minval = fminf(minval, patch->heightfield[i]);
  }
  bg3_uuid zero_uuid = {};
  bg3_vec3 base_pos = {world_pos[0] + patch->metadata.chunk_x * 64.0f,
                       world_pos[1] + minval,
                       world_pos[2] + patch->metadata.chunk_y * 64.0f};
  bg3_aigrid_subgrid* subgrid = bg3_aigrid_file_create_subgrid(
      file, patch->metadata.tex_cols * 2, patch->metadata.tex_rows * 2, object_uuid,
      &zero_uuid, patch->metadata.chunk_x, patch->metadata.chunk_y, base_pos);
  for (uint32_t y = 0; y < subgrid->header.height; ++y) {
    for (uint32_t x = 0; x < subgrid->header.width; ++x) {
      bg3_aigrid_tile* tile = &subgrid->tiles[y * subgrid->header.width + x];
      int patch_y0 = y / 2, patch_y1 = patch_y0 + 1;
      int patch_x0 = x / 2, patch_x1 = patch_x0 + 1;
      float offset_y = (y % 2 + 1) * 0.25f;
      float offset_x = (x % 2 + 1) * 0.25f;
      float sample_x0y0 =
          patch->heightfield[patch_y0 * patch->metadata.local_cols + patch_x0];
      float sample_x0y1 =
          patch->heightfield[patch_y1 * patch->metadata.local_cols + patch_x0];
      float sample_x1y0 =
          patch->heightfield[patch_y0 * patch->metadata.local_cols + patch_x1];
      float sample_x1y1 =
          patch->heightfield[patch_y1 * patch->metadata.local_cols + patch_x1];
      float lerp_y0 = sample_x0y0 * offset_x + sample_x1y0 * (1.0f - offset_x);
      float lerp_y1 = sample_x0y1 * offset_x + sample_x1y1 * (1.0f - offset_x);
      float bilerp = lerp_y0 * offset_y + lerp_y1 * (1.0f - offset_y);
      // The 0.1f slack seems to help dropped/thrown items not woopsie through
      // the ground while also not making the walk destination marker get
      // clipped. There's probably a more principled fix for this!
      tile->height = tile->bottom = quantize_float_int16(0.1f + bilerp - minval);
      assert(tile->height >= 0);
      tile->metadata_idx = -1;
      tile->surface = -1;
    }
  }
}

void bg3_aigrid_file_dump(bg3_aigrid_file* file) {
  printf("aigrid version %d with %d subgrids and %d layers\n", file->header.version,
         file->num_subgrids, file->num_layers);
  for (uint32_t i = 0; i < file->num_subgrids; ++i) {
    bg3_aigrid_subgrid* subgrid = file->subgrids + i;
    printf("subgrid %08X uuid %s template %s tiles (%dx%d) world_pos (%f,%f,%f)\n",
           subgrid->header.subgrid_id, subgrid->object_uuid, subgrid->template_uuid,
           subgrid->header.width, subgrid->header.height, subgrid->header.x,
           subgrid->header.y, subgrid->header.z);
    for (uint32_t y = 0; y < subgrid->header.height; ++y) {
      for (uint32_t x = 0; x < subgrid->header.width; ++x) {
        bg3_aigrid_tile* tile = &subgrid->tiles[y * subgrid->header.width + x];
        printf("(%03d,%03d) %016" PRIX64 " %6.2f %6.2f %5d %5d | ", x, y, tile->state,
               ((float)tile->height) / 50.f, ((float)tile->bottom) / 50.f,
               tile->metadata_idx, tile->surface);
      }
      printf("\n");
    }
  }
  for (uint32_t i = 0; i < file->num_layers; ++i) {
    bg3_aigrid_layer* layer = file->layers + i;
    char tmpbuf[48];
    bg3_uuid_to_string(&layer->level_template, tmpbuf);
    printf("layer %s num_entries %d\n", tmpbuf, layer->num_entries);
    for (uint32_t j = 0; j < layer->num_entries; ++j) {
      bg3_aigrid_layer_entry* entry = layer->entries + j;
      printf("%5d %5d %08X %016" PRIX64 " %10f %08X\n", entry->x, entry->y,
             entry->subgrid_id, entry->state, entry->height, entry->unused);
    }
  }
}

/// Osiris Implementation

static inline void osiris_save_get_u8(bg3_osiris_save* save, uint8_t* out) {
  bg3_cursor_read(&save->c, out, 1);
}

static inline void osiris_save_get_i8(bg3_osiris_save* save, int8_t* out) {
  bg3_cursor_read(&save->c, out, 1);
}

static inline void osiris_save_get_u16(bg3_osiris_save* save, uint16_t* out) {
  bg3_cursor_read(&save->c, out, 2);
}

static inline void osiris_save_get_u32(bg3_osiris_save* save, uint32_t* out) {
  bg3_cursor_read(&save->c, out, 4);
}

static inline void osiris_save_get_u64(bg3_osiris_save* save, uint64_t* out) {
  bg3_cursor_read(&save->c, out, 8);
}

static void osiris_save_get_string(bg3_osiris_save* save, bg3_buffer* out) {
  out->size = 0;
  while (save->c.ptr < save->c.end) {
    uint8_t c = *save->c.ptr ^ save->string_mask;
    save->c.ptr++;
    // put the nul in the buffer for ez c compat
    bg3_buffer_putchar(out, c);
    if (!c) {
      out->size--;
      break;
    }
  }
}

void bg3_osiris_save_destroy(bg3_osiris_save* save) {
  bg3_arena_destroy(&save->alloc);
  bg3_buffer_destroy(&save->out);
  bg3_ibuf_destroy(&save->text_out);
}

static int osiris_type_info_compare(void const* lhs, void const* rhs) {
  bg3_osiris_type_info* til = (bg3_osiris_type_info*)lhs;
  bg3_osiris_type_info* tir = (bg3_osiris_type_info*)rhs;
  return (int)til->index - (int)tir->index;
}

static int osiris_enum_info_compare(void const* lhs, void const* rhs) {
  bg3_osiris_enum_info* til = (bg3_osiris_enum_info*)lhs;
  bg3_osiris_enum_info* tir = (bg3_osiris_enum_info*)rhs;
  return (int)til->index - (int)tir->index;
}

static int osiris_enum_entry_compare(void const* lhs, void const* rhs) {
  bg3_osiris_enum_entry* til = (bg3_osiris_enum_entry*)lhs;
  bg3_osiris_enum_entry* tir = (bg3_osiris_enum_entry*)rhs;
  return (int64_t)til->value - (int64_t)tir->value;
}

static void osiris_save_debug_(bg3_osiris_save* save, char const* function, int line) {
  printf("%s:%d %08X\n", function, line,
         (int)(intptr_t)save->c.ptr - (int)(intptr_t)save->c.start);
  bg3_hex_dump(save->c.ptr, 0x80);
  bg3_panic("osiris save corrupted");
}

#define osiris_save_debug(save) osiris_save_debug_(save, __FUNCTION__, __LINE__)

static void osiris_save_get_value(bg3_osiris_save* save,
                                  bg3_buffer* tmp,
                                  bg3_osiris_variant* out) {
  uint8_t encoding;
  bg3_cursor_read(&save->c, &encoding, 1);
  if (encoding == 'e') {
    uint16_t index;
    osiris_save_get_u16(save, &index);
    *out = (bg3_osiris_variant){.type = bg3_osiris_prim_type_enum, .index = index};
    osiris_save_get_string(save, tmp);
    out->string = bg3_arena_strdup(&save->alloc, tmp->data);
  } else if (encoding == '1') {
#if 0
        uint16_t unk1;
        uint32_t unk2;
        cursor_read(&save->c, &unk1, sizeof(uint16_t));
        cursor_read(&save->c, &unk2, sizeof(uint32_t));
        printf("  paramtype0_0: unk1 %04X(!!) unk2 %08X\n", unk1, unk2);
#endif
    // This does not seem to be used in BG3.
    osiris_save_debug(save);
  } else if (encoding == '0') {
    uint16_t type_idx;
    bg3_cursor_read(&save->c, &type_idx, sizeof(uint16_t));
    if (!type_idx) {
      *out = (bg3_osiris_variant){.type = bg3_osiris_prim_type_undef, .index = type_idx};
      return;
    }
    bg3_osiris_type_info* value_type = &save->type_infos[type_idx - 1];
    while (value_type->alias_index) {
      value_type = &save->type_infos[value_type->alias_index - 1];
    }
    *out = (bg3_osiris_variant){.type = (bg3_osiris_prim_type)value_type->index,
                                .index = type_idx};
    switch (value_type->index) {
      case bg3_osiris_prim_type_integer:
        osiris_save_get_u32(save, (uint32_t*)&out->integer);
        break;
      case bg3_osiris_prim_type_integer64:
        osiris_save_get_u64(save, (uint64_t*)&out->integer64);
        break;
      case bg3_osiris_prim_type_real:
        // punned through union
        osiris_save_get_u32(save, (uint32_t*)&out->integer);
        break;
      case bg3_osiris_prim_type_string:
      case bg3_osiris_prim_type_guidstring: {
        uint8_t is_set;
        bg3_cursor_read(&save->c, &is_set, 1);
        if (is_set) {
          osiris_save_get_string(save, tmp);
          out->string = bg3_arena_strdup(&save->alloc, tmp->data);
        }
        break;
      }
      default:
        osiris_save_debug(save);
    }
  } else {
    osiris_save_debug(save);
  }
}

static void osiris_save_get_binding0(bg3_osiris_save* save,
                                     bg3_buffer* tmp,
                                     bg3_osiris_binding* out) {
  osiris_save_get_value(save, tmp, &out->value);
  osiris_save_get_u8(save, &out->is_grounded);
  osiris_save_get_u8(save, &out->unused0);
  osiris_save_get_u8(save, &out->is_variable_again);
}

static void osiris_save_get_binding1(bg3_osiris_save* save, bg3_osiris_binding* out) {
  osiris_save_get_u8(save, &out->index);
  osiris_save_get_u8(save, &out->is_dead);
  osiris_save_get_u8(save, &out->is_live);
}

static void osiris_save_get_binding(bg3_osiris_save* save,
                                    bg3_buffer* tmp,
                                    bg3_osiris_binding* out) {
  bg3_cursor_read(&save->c, &out->is_variable, 1);
  if (out->is_variable > 1) {
    osiris_save_debug(save);
  }
  osiris_save_get_binding0(save, tmp, out);
  if (out->is_variable == 1) {
    osiris_save_get_binding1(save, out);
  }
}

static void osiris_save_get_action_list(bg3_osiris_save* save,
                                        bg3_buffer* tmp,
                                        uint32_t* num_actions,
                                        bg3_osiris_action** actions) {
  bg3_cursor_read(&save->c, num_actions, sizeof(uint32_t));
  *actions = (bg3_osiris_action*)bg3_arena_calloc(&save->alloc, *num_actions,
                                                  sizeof(bg3_osiris_action));
  for (uint32_t j = 0; j < *num_actions; ++j) {
    bg3_osiris_action* a = *actions + j;
    osiris_save_get_string(save, tmp);
    if (*tmp->data) {
      a->function = strdup(tmp->data);
      uint8_t has_arguments;
      osiris_save_get_u8(save, &has_arguments);
      if (has_arguments) {
        osiris_save_get_u8(save, &a->num_arguments);
        a->arguments = (bg3_osiris_binding*)bg3_arena_calloc(
            &save->alloc, a->num_arguments, sizeof(bg3_osiris_binding));
        for (uint8_t k = 0; k < a->num_arguments; ++k) {
          bg3_osiris_binding* b = a->arguments + k;
          osiris_save_get_binding(save, tmp, b);
        }
      }
      osiris_save_get_u8(save, &a->retract);
    }
    bg3_cursor_read(&save->c, &a->completed_goal_id, 4);
  }
}

static void osiris_save_get_rete_node_edge(bg3_osiris_save* save,
                                           bg3_osiris_rete_node_edge* edge) {
  osiris_save_get_u32(save, &edge->node_id);
  osiris_save_get_u32(save, (uint32_t*)&edge->direction);
  osiris_save_get_u32(save, &edge->goal_id);
}

static void osiris_save_get_operator_common(bg3_osiris_save* save,
                                            bg3_osiris_rete_node_edge* child,
                                            bg3_osiris_rete_node_parent* parent) {
  osiris_save_get_rete_node_edge(save, child);
  osiris_save_get_u32(save, &parent->node_id);
  osiris_save_get_u32(save, &parent->adaptor);
  osiris_save_get_u32(save, &parent->db_node);
  osiris_save_get_rete_node_edge(save, &parent->db_edge);
  osiris_save_get_i8(save, &parent->db_distance);
}

void bg3_osiris_save_init(bg3_osiris_save* save) {
  memset(save, 0, sizeof(bg3_osiris_save));
  bg3_arena_init(&save->alloc, 1024 * 1024, 1024);
  bg3_buffer_init(&save->out);
  bg3_ibuf_init(&save->text_out);
}

bg3_status bg3_osiris_save_init_binary(bg3_osiris_save* save,
                                       char* data,
                                       size_t data_len) {
  bg3_osiris_save_init(save);
  bg3_cursor_init(&save->c, data, data_len);
  char must_be_zero = 1;
  bg3_cursor_read(&save->c, &must_be_zero, 1);
  if (must_be_zero) {
    bg3_osiris_save_destroy(save);
    return bg3_error_failed;
  }
  bg3_buffer tmp = {};
  osiris_save_get_string(save, &tmp);
  save->version = bg3_arena_strdup(&save->alloc, tmp.data);
  bg3_cursor_read(&save->c, &save->version_major, 1);
  bg3_cursor_read(&save->c, &save->version_minor, 1);
  if (save->version_major != LIBBG3_OSIRIS_VERSION_MAJOR ||
      save->version_minor != LIBBG3_OSIRIS_VERSION_MINOR) {
    bg3_osiris_save_destroy(save);
    bg3_buffer_destroy(&tmp);
    return bg3_error_failed;
  }
  bg3_cursor_read(&save->c, &save->is_big_endian, 1);
  if (save->is_big_endian) {
    bg3_panic("no");  // maybe if powerpc miraculously comes back
  }
  bg3_cursor_read(&save->c, &save->unk0, 1);
  bg3_cursor_read(&save->c, save->story_version, 0x80);
  bg3_cursor_read(&save->c, &save->debug_flags, sizeof(uint32_t));
  bg3_cursor_read(&save->c, &save->num_type_infos, sizeof(uint32_t));
  save->string_mask =
      LIBBG3_OSIRIS_STRING_MASK;  // i wonder if some middlebox caused this
  bg3_osiris_type_info* type_infos = (bg3_osiris_type_info*)bg3_arena_calloc(
      &save->alloc, save->num_type_infos, sizeof(bg3_osiris_type_info));
  for (uint32_t i = 0; i < save->num_type_infos; ++i) {
    osiris_save_get_string(save, &tmp);
    type_infos[i].name = bg3_arena_strdup(&save->alloc, tmp.data);
    bg3_cursor_read(&save->c, &type_infos[i].index, 1);
    bg3_cursor_read(&save->c, &type_infos[i].alias_index, 1);
  }
  qsort(type_infos, save->num_type_infos, sizeof(bg3_osiris_type_info),
        osiris_type_info_compare);
  save->type_infos = type_infos;
  bg3_cursor_read(&save->c, &save->num_enums, sizeof(uint32_t));
  bg3_osiris_enum_info* enums = (bg3_osiris_enum_info*)bg3_arena_calloc(
      &save->alloc, save->num_enums, sizeof(bg3_osiris_enum_info));
  for (uint32_t i = 0; i < save->num_enums; ++i) {
    bg3_cursor_read(&save->c, &enums[i].index, sizeof(uint16_t));
    bg3_cursor_read(&save->c, &enums[i].num_entries, sizeof(uint32_t));
    enums[i].entries = (bg3_osiris_enum_entry*)bg3_arena_calloc(
        &save->alloc, enums[i].num_entries, sizeof(bg3_osiris_enum_entry));
    for (uint32_t j = 0; j < enums[i].num_entries; ++j) {
      osiris_save_get_string(save, &tmp);
      enums[i].entries[j].name = bg3_arena_strdup(&save->alloc, tmp.data);
      bg3_cursor_read(&save->c, &enums[i].entries[j].value, sizeof(uint64_t));
    }
    qsort(enums[i].entries, enums[i].num_entries, sizeof(bg3_osiris_enum_entry),
          osiris_enum_entry_compare);
    save->type_infos[enums[i].index - 1].enum_index = i + 1;
  }
  qsort(enums, save->num_enums, sizeof(bg3_osiris_enum_info), osiris_enum_info_compare);
  save->enums = enums;
  bg3_cursor_read(&save->c, &save->num_div_objects, sizeof(uint32_t));
  if (save->num_div_objects) {
    bg3_panic("DIV object section is not supported");
  }
  bg3_cursor_read(&save->c, &save->num_functions, sizeof(uint32_t));
  save->functions = (bg3_osiris_function_info*)bg3_arena_calloc(
      &save->alloc, save->num_functions, sizeof(bg3_osiris_function_info));
  for (uint32_t i = 0; i < save->num_functions; ++i) {
    bg3_osiris_function_info* fn = &save->functions[i];
    osiris_save_get_u32(save, &fn->line);
    osiris_save_get_u32(save, &fn->num_conds);
    osiris_save_get_u32(save, &fn->num_actions);
    osiris_save_get_u32(save, &fn->rete_node);
    osiris_save_get_u8(save, (uint8_t*)&fn->type);
    osiris_save_get_u32(save, &fn->sys_opcode);
    osiris_save_get_u32(save, &fn->unused0);
    osiris_save_get_u32(save, &fn->div_opcode);
    osiris_save_get_u32(save, &fn->is_external);
    osiris_save_get_string(save, &tmp);
    fn->name = bg3_arena_strdup(&save->alloc, tmp.data);
    // the length field is always longer than the data 🤣
    uint32_t out_mask_len;
    bg3_cursor_read(&save->c, &out_mask_len, sizeof(uint32_t));
    if (out_mask_len > 4) {
      osiris_save_debug(save);
    }
    bg3_cursor_read(&save->c, &fn->out_mask, out_mask_len);
    bg3_cursor_read(&save->c, &fn->num_params, 1);
    if (fn->num_params) {
      fn->params =
          (uint16_t*)bg3_arena_calloc(&save->alloc, fn->num_params, sizeof(uint16_t));
      for (uint32_t j = 0; j < fn->num_params; ++j) {
        osiris_save_get_u16(save, fn->params + j);
      }
    }
  }
  bg3_cursor_read(&save->c, &save->num_rete_nodes, sizeof(uint32_t));
  save->rete_nodes = (bg3_osiris_rete_node*)bg3_arena_calloc(
      &save->alloc, save->num_rete_nodes, sizeof(bg3_osiris_rete_node));
  for (uint32_t i = 0; i < save->num_rete_nodes; ++i) {
    bg3_osiris_rete_node* n = &save->rete_nodes[i];
    uint8_t node_type;
    bg3_cursor_read(&save->c, &node_type, sizeof(uint8_t));
    n->type = (bg3_osiris_rete_node_type)node_type;
    bg3_cursor_read(&save->c, &n->node_id, sizeof(uint32_t));
    bg3_cursor_read(&save->c, &n->db, sizeof(uint32_t));
    osiris_save_get_string(save, &tmp);
    if (*tmp.data) {
      n->name = bg3_arena_strdup(&save->alloc, tmp.data);
      bg3_cursor_read(&save->c, &n->arity, sizeof(uint8_t));
    }
    switch (n->type) {
      case bg3_osiris_rete_node_db:
      case bg3_osiris_rete_node_event: {
        bg3_cursor_read(&save->c, &n->trigger.num_children, sizeof(uint32_t));
        n->trigger.children = (bg3_osiris_rete_node_edge*)bg3_arena_calloc(
            &save->alloc, n->trigger.num_children, sizeof(bg3_osiris_rete_node_edge));
        for (uint32_t j = 0; j < n->trigger.num_children; ++j) {
          osiris_save_get_rete_node_edge(save, &n->trigger.children[j]);
        }
        break;
      }
      case bg3_osiris_rete_node_div_query:
      case bg3_osiris_rete_node_sys_query:
      case bg3_osiris_rete_node_query: {
        break;
      }
      case bg3_osiris_rete_node_join_and:
      case bg3_osiris_rete_node_join_and_not: {
        osiris_save_get_rete_node_edge(save, &n->join.child);
        osiris_save_get_u32(save, &n->join.left_parent.node_id);
        osiris_save_get_u32(save, &n->join.right_parent.node_id);
        osiris_save_get_u32(save, &n->join.left_parent.adaptor);
        osiris_save_get_u32(save, &n->join.right_parent.adaptor);
        osiris_save_get_u32(save, &n->join.left_parent.db_node);
        osiris_save_get_rete_node_edge(save, &n->join.left_parent.db_edge);
        osiris_save_get_i8(save, &n->join.left_parent.db_distance);
        osiris_save_get_u32(save, &n->join.right_parent.db_node);
        osiris_save_get_rete_node_edge(save, &n->join.right_parent.db_edge);
        osiris_save_get_i8(save, &n->join.right_parent.db_distance);
        break;
      }
      case bg3_osiris_rete_node_compare: {
        osiris_save_get_operator_common(save, &n->compare.child, &n->compare.parent);
        bg3_cursor_read(&save->c, &n->compare.left_var, 1);
        bg3_cursor_read(&save->c, &n->compare.right_var, 1);
        osiris_save_get_value(save, &tmp, &n->compare.left_value);
        osiris_save_get_value(save, &tmp, &n->compare.right_value);
        bg3_cursor_read(&save->c, &n->compare.opcode, 4);
        break;
      }
      case bg3_osiris_rete_node_terminal: {
        osiris_save_get_operator_common(save, &n->terminal.child, &n->terminal.parent);
        osiris_save_get_action_list(save, &tmp, &n->terminal.num_actions,
                                    &n->terminal.actions);
        bg3_cursor_read(&save->c, &n->terminal.num_vars, 1);
        if (n->terminal.num_vars) {
          n->terminal.vars = (bg3_osiris_binding*)bg3_arena_calloc(
              &save->alloc, n->terminal.num_vars, sizeof(bg3_osiris_binding));
          for (uint8_t j = 0; j < n->terminal.num_vars; ++j) {
            bg3_osiris_binding* p = n->terminal.vars + j;
            bg3_cursor_read(&save->c, &p->is_variable, 1);
            if (p->is_variable != 1) {
              osiris_save_debug(save);
            }
            osiris_save_get_binding0(save, &tmp, p);
            osiris_save_get_binding1(save, p);
          }
        }
        bg3_cursor_read(&save->c, &n->terminal.line, 4);
        bg3_cursor_read(&save->c, &n->terminal.is_query, 1);
        break;
      }
      default:
        osiris_save_debug(save);
    }
  }
  bg3_cursor_read(&save->c, &save->num_rete_adaptors, sizeof(uint32_t));
  save->rete_adaptors = (bg3_osiris_rete_adaptor*)bg3_arena_calloc(
      &save->alloc, save->num_rete_adaptors, sizeof(bg3_osiris_rete_adaptor));
  for (uint32_t i = 0; i < save->num_rete_adaptors; ++i) {
    bg3_osiris_rete_adaptor* a = save->rete_adaptors + i;
    osiris_save_get_u32(save, &a->adaptor_id);
    osiris_save_get_u8(save, &a->num_values);
    if (a->num_values) {
      a->values = (bg3_osiris_rete_adaptor_value*)bg3_arena_calloc(
          &save->alloc, a->num_values, sizeof(bg3_osiris_rete_adaptor_value));
      for (uint8_t j = 0; j < a->num_values; ++j) {
        bg3_osiris_rete_adaptor_value* av = a->values + j;
        osiris_save_get_u8(save, &av->index);
        osiris_save_get_value(save, &tmp, &av->value);
      }
    }
    osiris_save_get_u8(save, &a->num_vars);
    if (a->num_vars) {
      a->vars = (uint8_t*)bg3_arena_calloc(&save->alloc, a->num_vars, sizeof(uint8_t));
      bg3_cursor_read(&save->c, a->vars, a->num_vars);
    }
    osiris_save_get_u8(save, &a->num_pairs);
    if (a->num_pairs) {
      a->pairs = (bg3_osiris_rete_adaptor_pair*)bg3_arena_calloc(
          &save->alloc, a->num_pairs, sizeof(bg3_osiris_rete_adaptor_pair));
      bg3_cursor_read(&save->c, a->pairs, sizeof(uint8_t) * 2 * a->num_pairs);
    }
  }
  bg3_cursor_read(&save->c, &save->num_dbs, sizeof(uint32_t));
  save->dbs = (bg3_osiris_rete_db*)bg3_arena_calloc(&save->alloc, save->num_dbs,
                                                    sizeof(bg3_osiris_rete_db));
  for (uint32_t i = 0; i < save->num_dbs; ++i) {
    bg3_osiris_rete_db* d = save->dbs + i;
    osiris_save_get_u32(save, &d->db_id);
    osiris_save_get_u8(save, &d->num_schema_columns);
    d->schema_columns = (uint16_t*)bg3_arena_calloc(&save->alloc, d->num_schema_columns,
                                                    sizeof(uint16_t));
    for (uint8_t j = 0; j < d->num_schema_columns; ++j) {
      osiris_save_get_u16(save, d->schema_columns + j);
    }
    osiris_save_get_u32(save, &d->num_rows);
    if (d->num_rows) {
      d->rows = (bg3_osiris_row*)bg3_arena_calloc(&save->alloc, d->num_rows,
                                                  sizeof(bg3_osiris_row));
      for (uint32_t j = 0; j < d->num_rows; ++j) {
        bg3_osiris_row* r = d->rows + j;
        uint8_t num_columns;
        osiris_save_get_u8(save, &num_columns);
        if (num_columns != d->num_schema_columns) {
          osiris_save_debug(save);
        }
        r->columns = (bg3_osiris_variant*)bg3_arena_calloc(&save->alloc, num_columns,
                                                           sizeof(bg3_osiris_variant));
        for (uint8_t k = 0; k < num_columns; ++k) {
          osiris_save_get_value(save, &tmp, r->columns + k);
        }
      }
    }
  }
  bg3_cursor_read(&save->c, &save->num_goals, 4);
  save->goals = (bg3_osiris_goal*)bg3_arena_calloc(&save->alloc, save->num_goals,
                                                   sizeof(bg3_osiris_goal));
  for (uint32_t i = 0; i < save->num_goals; ++i) {
    bg3_osiris_goal* g = save->goals + i;
    osiris_save_get_u32(save, &g->goal_id);
    osiris_save_get_string(save, &tmp);
    g->name = bg3_arena_strdup(&save->alloc, tmp.data);
    osiris_save_get_u8(save, (uint8_t*)&g->combiner);
    uint32_t num_parents;
    osiris_save_get_u32(save, &num_parents);
    // there can be only one. why the format allows multiple is a complete
    // mystery to me, perhaps it's a feature that was previously used or
    // intended to be used in the future, but as it is, no goals with
    // multiple parents exist in BG3
    switch (num_parents) {
      case 0:
        break;
      case 1:
        osiris_save_get_u32(save, &g->parent);
        break;
      default:
        osiris_save_debug(save);
    }
    osiris_save_get_u32(save, &g->num_children);
    if (g->num_children) {
      g->children =
          (uint32_t*)bg3_arena_calloc(&save->alloc, g->num_children, sizeof(uint32_t));
      for (uint32_t j = 0; j < g->num_children; ++j) {
        osiris_save_get_u32(save, g->children + j);
      }
    }
    osiris_save_get_u8(save, (uint8_t*)&g->state);
    osiris_save_get_action_list(save, &tmp, &g->num_init_actions, &g->init_actions);
    osiris_save_get_action_list(save, &tmp, &g->num_exit_actions, &g->exit_actions);
  }
  osiris_save_get_action_list(save, &tmp, &save->num_global_actions,
                              &save->global_actions);
  if (save->c.ptr != save->c.end) {
    osiris_save_debug(save);
  }
  bg3_buffer_destroy(&tmp);
  return bg3_success;
}

static inline void osiris_save_put_u8(bg3_osiris_save* save, uint8_t val) {
  bg3_buffer_push(&save->out, &val, sizeof(uint8_t));
}

static inline void osiris_save_put_u16(bg3_osiris_save* save, uint16_t val) {
  bg3_buffer_push(&save->out, &val, sizeof(uint16_t));
}

static inline void osiris_save_put_u32(bg3_osiris_save* save, uint32_t val) {
  bg3_buffer_push(&save->out, &val, sizeof(uint32_t));
}

static inline void osiris_save_put_u64(bg3_osiris_save* save, uint64_t val) {
  bg3_buffer_push(&save->out, &val, sizeof(uint64_t));
}

static inline void osiris_save_put_string(bg3_osiris_save* save, char const* str) {
  if (str) {
    while (*str) {
      bg3_buffer_putchar(&save->out, ((uint8_t)*str) ^ save->string_mask);
      str++;
    }
  }
  bg3_buffer_putchar(&save->out, save->string_mask);
}

static void osiris_save_put_value(bg3_osiris_save* save, bg3_osiris_variant* value) {
  osiris_save_put_u8(save, value->type == bg3_osiris_prim_type_enum ? 'e' : '0');
  osiris_save_put_u16(save, value->index);
  switch (value->type) {
    case bg3_osiris_prim_type_undef:
      break;
    case bg3_osiris_prim_type_integer:
      osiris_save_put_u32(save, (uint32_t)value->integer);
      break;
    case bg3_osiris_prim_type_integer64:
      osiris_save_put_u64(save, (uint64_t)value->integer64);
      break;
    case bg3_osiris_prim_type_real:
      // punned through union
      osiris_save_put_u32(save, (uint32_t)value->integer);
      break;
    case bg3_osiris_prim_type_enum:
      osiris_save_put_string(save, value->string);
      break;
    case bg3_osiris_prim_type_string:
    case bg3_osiris_prim_type_guidstring:
      osiris_save_put_u8(save, value->string ? 1 : 0);
      if (value->string) {
        osiris_save_put_string(save, value->string);
      }
      break;
  }
}

static void osiris_save_put_binding(bg3_osiris_save* save, bg3_osiris_binding* b) {
  osiris_save_put_u8(save, b->is_variable);
  osiris_save_put_value(save, &b->value);
  osiris_save_put_u8(save, b->is_grounded);
  osiris_save_put_u8(save, b->unused0);
  osiris_save_put_u8(save, b->is_variable_again);
  if (b->is_variable) {
    osiris_save_put_u8(save, b->index);
    osiris_save_put_u8(save, b->is_dead);
    osiris_save_put_u8(save, b->is_live);
  }
}

static void osiris_save_put_action_list(bg3_osiris_save* save,
                                        uint32_t num_actions,
                                        bg3_osiris_action* actions) {
  osiris_save_put_u32(save, num_actions);
  for (uint32_t i = 0; i < num_actions; ++i) {
    bg3_osiris_action* a = actions + i;
    osiris_save_put_string(save, a->function);
    if (a->function && *a->function) {
      osiris_save_put_u8(save, a->num_arguments > 0);
      if (a->num_arguments) {
        osiris_save_put_u8(save, a->num_arguments);
        for (uint8_t j = 0; j < a->num_arguments; ++j) {
          osiris_save_put_binding(save, a->arguments + j);
        }
      }
      osiris_save_put_u8(save, a->retract);
    }
    osiris_save_put_u32(save, a->completed_goal_id);
  }
}

static void osiris_save_put_rete_node_edge(bg3_osiris_save* save,
                                           bg3_osiris_rete_node_edge* edge) {
  osiris_save_put_u32(save, edge->node_id);
  osiris_save_put_u32(save, edge->direction);
  osiris_save_put_u32(save, edge->goal_id);
}

static void osiris_save_put_operator_common(bg3_osiris_save* save,
                                            bg3_osiris_rete_node_edge* child,
                                            bg3_osiris_rete_node_parent* parent) {
  osiris_save_put_rete_node_edge(save, child);
  osiris_save_put_u32(save, parent->node_id);
  osiris_save_put_u32(save, parent->adaptor);
  osiris_save_put_u32(save, parent->db_node);
  osiris_save_put_rete_node_edge(save, &parent->db_edge);
  osiris_save_put_u8(save, parent->db_distance);
}

bg3_status bg3_osiris_save_write_binary(bg3_osiris_save* save, char const* path) {
  FILE* fp = fopen(path, "wb");
  if (!fp) {
    return bg3_error_failed;
  }
  save->out.size = 0;
  bg3_buffer_putchar(&save->out, 0);
  save->string_mask = 0;
  osiris_save_put_string(save, save->version);
  osiris_save_put_u8(save, save->version_major);
  osiris_save_put_u8(save, save->version_minor);
  osiris_save_put_u8(save, 0);  // always little endian
  osiris_save_put_u8(save, save->unk0);
  bg3_buffer_push(&save->out, save->story_version, 0x80);
  osiris_save_put_u32(save, save->debug_flags);
  save->string_mask = LIBBG3_OSIRIS_STRING_MASK;
  osiris_save_put_u32(save, save->num_type_infos);
  for (uint32_t i = 0; i < save->num_type_infos; ++i) {
    bg3_osiris_type_info* ti = save->type_infos + i;
    osiris_save_put_string(save, ti->name);
    osiris_save_put_u8(save, ti->index);
    osiris_save_put_u8(save, ti->alias_index);
  }
  osiris_save_put_u32(save, save->num_enums);
  for (uint32_t i = 0; i < save->num_enums; ++i) {
    bg3_osiris_enum_info* e = save->enums + i;
    osiris_save_put_u16(save, e->index);
    osiris_save_put_u32(save, e->num_entries);
    for (uint32_t j = 0; j < e->num_entries; ++j) {
      bg3_osiris_enum_entry* et = e->entries + j;
      osiris_save_put_string(save, et->name);
      osiris_save_put_u64(save, et->value);
    }
  }
  assert(save->num_div_objects == 0);
  osiris_save_put_u32(save, save->num_div_objects);
  osiris_save_put_u32(save, save->num_functions);
  for (uint32_t i = 0; i < save->num_functions; ++i) {
    bg3_osiris_function_info* fn = save->functions + i;
    osiris_save_put_u32(save, fn->line);
    osiris_save_put_u32(save, fn->num_conds);
    osiris_save_put_u32(save, fn->num_actions);
    osiris_save_put_u32(save, fn->rete_node);
    osiris_save_put_u8(save, fn->type);
    osiris_save_put_u32(save, fn->sys_opcode);
    osiris_save_put_u32(save, fn->unused0);
    osiris_save_put_u32(save, fn->div_opcode);
    osiris_save_put_u32(save, fn->is_external);
    osiris_save_put_string(save, fn->name);
    osiris_save_put_u32(save, fn->num_params >= 8 ? 2 : 1);
    if (fn->num_params >= 8) {
      osiris_save_put_u16(save, fn->out_mask);
    } else {
      osiris_save_put_u8(save, fn->out_mask);
    }
    osiris_save_put_u8(save, fn->num_params);
    for (uint32_t j = 0; j < fn->num_params; ++j) {
      osiris_save_put_u16(save, fn->params[j]);
    }
  }
  osiris_save_put_u32(save, save->num_rete_nodes);
  for (uint32_t i = 0; i < save->num_rete_nodes; ++i) {
    bg3_osiris_rete_node* n = save->rete_nodes + i;
    osiris_save_put_u8(save, n->type);
    osiris_save_put_u32(save, n->node_id);
    osiris_save_put_u32(save, n->db);
    osiris_save_put_string(save, n->name);
    if (n->name && *n->name) {
      osiris_save_put_u8(save, n->arity);
    }
    switch (n->type) {
      case bg3_osiris_rete_node_db:
      case bg3_osiris_rete_node_event: {
        osiris_save_put_u32(save, n->trigger.num_children);
        for (uint32_t j = 0; j < n->trigger.num_children; ++j) {
          osiris_save_put_rete_node_edge(save, n->trigger.children + j);
        }
        break;
      }
      case bg3_osiris_rete_node_div_query:
      case bg3_osiris_rete_node_sys_query:
      case bg3_osiris_rete_node_query: {
        break;
      }
      case bg3_osiris_rete_node_join_and:
      case bg3_osiris_rete_node_join_and_not: {
        osiris_save_put_rete_node_edge(save, &n->join.child);
        osiris_save_put_u32(save, n->join.left_parent.node_id);
        osiris_save_put_u32(save, n->join.right_parent.node_id);
        osiris_save_put_u32(save, n->join.left_parent.adaptor);
        osiris_save_put_u32(save, n->join.right_parent.adaptor);
        osiris_save_put_u32(save, n->join.left_parent.db_node);
        osiris_save_put_rete_node_edge(save, &n->join.left_parent.db_edge);
        osiris_save_put_u8(save, n->join.left_parent.db_distance);
        osiris_save_put_u32(save, n->join.right_parent.db_node);
        osiris_save_put_rete_node_edge(save, &n->join.right_parent.db_edge);
        osiris_save_put_u8(save, n->join.right_parent.db_distance);
        break;
      }
      case bg3_osiris_rete_node_compare: {
        osiris_save_put_operator_common(save, &n->compare.child, &n->compare.parent);
        osiris_save_put_u8(save, n->compare.left_var);
        osiris_save_put_u8(save, n->compare.right_var);
        osiris_save_put_value(save, &n->compare.left_value);
        osiris_save_put_value(save, &n->compare.right_value);
        osiris_save_put_u32(save, n->compare.opcode);
        break;
      }
      case bg3_osiris_rete_node_terminal: {
        osiris_save_put_operator_common(save, &n->terminal.child, &n->terminal.parent);
        osiris_save_put_action_list(save, n->terminal.num_actions, n->terminal.actions);
        osiris_save_put_u8(save, n->terminal.num_vars);
        for (uint8_t j = 0; j < n->terminal.num_vars; ++j) {
          osiris_save_put_binding(save, n->terminal.vars + j);
        }
        osiris_save_put_u32(save, n->terminal.line);
        osiris_save_put_u8(save, n->terminal.is_query);
        break;
      }
      default:
        bg3_panic("invalid node type");
    }
  }
  osiris_save_put_u32(save, save->num_rete_adaptors);
  for (uint32_t i = 0; i < save->num_rete_adaptors; ++i) {
    bg3_osiris_rete_adaptor* a = save->rete_adaptors + i;
    osiris_save_put_u32(save, a->adaptor_id);
    osiris_save_put_u8(save, a->num_values);
    for (uint8_t j = 0; j < a->num_values; ++j) {
      osiris_save_put_u8(save, a->values[j].index);
      osiris_save_put_value(save, &a->values[j].value);
    }
    osiris_save_put_u8(save, a->num_vars);
    bg3_buffer_push(&save->out, a->vars, a->num_vars);
    osiris_save_put_u8(save, a->num_pairs);
    bg3_buffer_push(&save->out, a->pairs, sizeof(uint8_t) * 2 * a->num_pairs);
  }
  osiris_save_put_u32(save, save->num_dbs);
  for (uint32_t i = 0; i < save->num_dbs; ++i) {
    bg3_osiris_rete_db* d = save->dbs + i;
    osiris_save_put_u32(save, d->db_id);
    osiris_save_put_u8(save, d->num_schema_columns);
    for (uint8_t j = 0; j < d->num_schema_columns; ++j) {
      osiris_save_put_u16(save, d->schema_columns[j]);
    }
    osiris_save_put_u32(save, d->num_rows);
    for (uint32_t j = 0; j < d->num_rows; ++j) {
      osiris_save_put_u8(save, d->num_schema_columns);
      for (uint8_t k = 0; k < d->num_schema_columns; ++k) {
        osiris_save_put_value(save, d->rows[j].columns + k);
      }
    }
  }
  osiris_save_put_u32(save, save->num_goals);
  for (uint32_t i = 0; i < save->num_goals; ++i) {
    bg3_osiris_goal* g = save->goals + i;
    osiris_save_put_u32(save, g->goal_id);
    osiris_save_put_string(save, g->name);
    osiris_save_put_u8(save, g->combiner);
    osiris_save_put_u32(save, g->parent ? 1 : 0);
    if (g->parent) {
      osiris_save_put_u32(save, g->parent);
    }
    osiris_save_put_u32(save, g->num_children);
    for (uint32_t j = 0; j < g->num_children; ++j) {
      osiris_save_put_u32(save, g->children[j]);
    }
    osiris_save_put_u8(save, g->state);
    osiris_save_put_action_list(save, g->num_init_actions, g->init_actions);
    osiris_save_put_action_list(save, g->num_exit_actions, g->exit_actions);
  }
  osiris_save_put_action_list(save, save->num_global_actions, save->global_actions);
  fwrite(save->out.data, 1, save->out.size, fp);
  fclose(fp);
  bg3_buffer_destroy(&save->out);
  bg3_buffer_init(&save->out);
  return bg3_success;
}

typedef struct osiris_node_binding_entry {
  int refcount;
  char* name;
  bool is_constant;
  bg3_osiris_variant constant;
} osiris_node_binding_entry;

typedef struct osiris_node_bindings {
  size_t arity;
  osiris_node_binding_entry** entries;
} osiris_node_bindings;

typedef struct osiris_node_bindings_table {
  bg3_osiris_save* save;
  bg3_hash nodes;
  int next_id;
} osiris_node_bindings_table;

static int get_adaptor_last_index(bg3_osiris_save* save, uint32_t adaptor_id) {
  bg3_osiris_rete_adaptor* a = save->rete_adaptors + (adaptor_id - 1);
  int max_index = -1;
  for (uint8_t i = 0; i < a->num_pairs; ++i) {
    max_index = LIBBG3_MAX(max_index, a->pairs[i].left);
  }
  return max_index;
}

static int get_node_arity(bg3_osiris_save* save, bg3_osiris_rete_node* node) {
  switch (node->type) {
    case bg3_osiris_rete_node_db:
    case bg3_osiris_rete_node_event:
    case bg3_osiris_rete_node_div_query:
    case bg3_osiris_rete_node_sys_query:
    case bg3_osiris_rete_node_query:
      assert(node->name);
      return node->arity;
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not:
      return LIBBG3_MAX(get_adaptor_last_index(save, node->join.left_parent.adaptor),
                        get_adaptor_last_index(save, node->join.right_parent.adaptor)) +
             1;
    case bg3_osiris_rete_node_compare:
      return get_adaptor_last_index(save, node->compare.parent.adaptor) + 1;
    case bg3_osiris_rete_node_terminal:
      return get_adaptor_last_index(save, node->terminal.parent.adaptor) + 1;
    default:
      bg3_panic("invalid node type");
  }
}

static bg3_osiris_rete_node* get_left_parent_node(bg3_osiris_save* save,
                                                  bg3_osiris_rete_node* node) {
  switch (node->type) {
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not:
      return save->rete_nodes + (node->join.left_parent.node_id - 1);
    case bg3_osiris_rete_node_terminal:
      return save->rete_nodes + (node->terminal.parent.node_id - 1);
    case bg3_osiris_rete_node_compare:
      return save->rete_nodes + (node->compare.parent.node_id - 1);
    default:
      return 0;
  }
}

static bg3_osiris_rete_node* get_right_parent_node(bg3_osiris_save* save,
                                                   bg3_osiris_rete_node* node) {
  switch (node->type) {
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not:
      return save->rete_nodes + (node->join.right_parent.node_id - 1);
    default:
      return 0;
  }
}

static bg3_osiris_rete_adaptor* get_left_adaptor(bg3_osiris_save* save,
                                                 bg3_osiris_rete_node* node) {
  switch (node->type) {
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not:
      return save->rete_adaptors + (node->join.left_parent.adaptor - 1);
    case bg3_osiris_rete_node_terminal:
      return save->rete_adaptors + (node->terminal.parent.adaptor - 1);
    case bg3_osiris_rete_node_compare:
      return save->rete_adaptors + (node->compare.parent.adaptor - 1);
    default:
      return 0;
  }
}

static bg3_osiris_rete_adaptor* get_right_adaptor(bg3_osiris_save* save,
                                                  bg3_osiris_rete_node* node) {
  switch (node->type) {
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not:
      return save->rete_adaptors + (node->join.right_parent.adaptor - 1);
    default:
      return 0;
  }
}

static bg3_osiris_rete_node* get_root_node(bg3_osiris_save* save,
                                           bg3_osiris_rete_node* node) {
  bg3_osiris_rete_node* parent = get_left_parent_node(save, node);
  if (parent) {
    return get_root_node(save, parent);
  }
  return node;
}

static int32_t get_owner_in_chain(bg3_osiris_save* save,
                                  bg3_osiris_rete_node* node,
                                  int32_t* node_owners) {
  int32_t cur_owner = node_owners[node->node_id - 1];
  if (cur_owner >= 0) {
    return cur_owner;
  }
  switch (node->type) {
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not:
      return get_owner_in_chain(
          save, save->rete_nodes + (node->join.left_parent.node_id - 1), node_owners);
    case bg3_osiris_rete_node_terminal:
      return get_owner_in_chain(
          save, save->rete_nodes + (node->terminal.parent.node_id - 1), node_owners);
    case bg3_osiris_rete_node_compare:
      return get_owner_in_chain(
          save, save->rete_nodes + (node->compare.parent.node_id - 1), node_owners);
    default:
      return -1;
  }
}

static void osiris_node_binding_entry_unref(osiris_node_binding_entry* entry) {
  if (!--entry->refcount) {
    free(entry->name);
    free(entry);
  }
}

static void osiris_node_bindings_replace_at(osiris_node_bindings* bindings,
                                            size_t index,
                                            osiris_node_binding_entry* new_entry) {
  if (index >= bindings->arity) {
    bg3_panic("index out of range");
  }
  new_entry->refcount++;
  osiris_node_binding_entry_unref(bindings->entries[index]);
  bindings->entries[index] = new_entry;
}

static osiris_node_bindings* osiris_node_bindings_table_get(
    osiris_node_bindings_table* table,
    bg3_osiris_rete_node* node) {
  if (node->name) {
    // we only track bindings for non-entry nodes, as event/db nodes may
    // occur multiple times in a given rule.
    return 0;
  }
  bg3_hash_entry* e = bg3_hash_get_entry(&table->nodes, node);
  if (e) {
    return (osiris_node_bindings*)e->value;
  }
  osiris_node_bindings* new_bindings =
      (osiris_node_bindings*)calloc(1, sizeof(osiris_node_bindings));
  new_bindings->arity = get_node_arity(table->save, node);
  new_bindings->entries = (osiris_node_binding_entry**)malloc(
      sizeof(osiris_node_binding_entry*) * new_bindings->arity);
  for (size_t i = 0; i < new_bindings->arity; ++i) {
    char buf[128];
    osiris_node_binding_entry* entry =
        (osiris_node_binding_entry*)calloc(1, sizeof(osiris_node_binding_entry));
    entry->refcount = 1;
    snprintf(buf, sizeof(buf), "Var%d", table->next_id++);
    entry->name = strdup(buf);
    new_bindings->entries[i] = entry;
  }
  bg3_hash_set(&table->nodes, node, new_bindings);
  return new_bindings;
}

static void osiris_node_bindings_destroy_op(void* value, void* user_data) {
  osiris_node_bindings* bindings = (osiris_node_bindings*)value;
  for (size_t i = 0; i < bindings->arity; ++i) {
    osiris_node_binding_entry_unref(bindings->entries[i]);
  }
  free(bindings->entries);
  free(bindings);
}

static bg3_hash_ops node_binding_hash_ops;

void osiris_node_bindings_table_init(osiris_node_bindings_table* table,
                                     bg3_osiris_save* save) {
  node_binding_hash_ops = (bg3_hash_ops){
      .hash_fn = bg3_default_hash_ops.hash_fn,
      .equal_fn = bg3_default_hash_ops.equal_fn,
      .copy_key_fn = bg3_default_hash_ops.copy_key_fn,
      .free_key_fn = bg3_default_hash_ops.free_key_fn,
      .copy_value_fn = bg3_default_hash_ops.copy_value_fn,
      .free_value_fn = osiris_node_bindings_destroy_op,
  };
  memset(table, 0, sizeof(osiris_node_bindings_table));
  bg3_hash_init(&table->nodes, &node_binding_hash_ops, 0);
  table->save = save;
}

void osiris_node_bindings_table_destroy(osiris_node_bindings_table* table) {
  bg3_hash_destroy(&table->nodes);
}

void osiris_node_bindings_table_propagate(osiris_node_bindings_table* table,
                                          bg3_osiris_rete_node* node);

static void propagate_from_to(osiris_node_bindings_table* table,
                              bg3_osiris_rete_node* from,
                              bg3_osiris_rete_node* to,
                              bg3_osiris_rete_adaptor* adaptor) {
  if (to->name) {
    return;
  }
  osiris_node_bindings* bindings = osiris_node_bindings_table_get(table, from);
  osiris_node_bindings* parent_bindings = osiris_node_bindings_table_get(table, to);
  for (uint8_t i = 0; i < adaptor->num_pairs; ++i) {
    size_t index = adaptor->vars[adaptor->pairs[i].right];
    if (index >= bindings->arity) {
      bg3_panic("index out of range");
    }
    if (index != adaptor->pairs[i].left) {
      bg3_panic("assumptions violated");
    }
    osiris_node_bindings_replace_at(parent_bindings, adaptor->pairs[i].left,
                                    bindings->entries[index]);
  }
  osiris_node_bindings_table_propagate(table, to);
}

void osiris_node_bindings_table_propagate(osiris_node_bindings_table* table,
                                          bg3_osiris_rete_node* node) {
  switch (node->type) {
    case bg3_osiris_rete_node_db:
    case bg3_osiris_rete_node_event:
    case bg3_osiris_rete_node_div_query:
    case bg3_osiris_rete_node_sys_query:
    case bg3_osiris_rete_node_query:
      return;
    case bg3_osiris_rete_node_compare:
    case bg3_osiris_rete_node_terminal: {
      bg3_osiris_rete_adaptor* a = get_left_adaptor(table->save, node);
      bg3_osiris_rete_node* parent = get_left_parent_node(table->save, node);
      propagate_from_to(table, node, parent, a);
      break;
    }
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not: {
      bg3_osiris_rete_adaptor* left_a = get_left_adaptor(table->save, node);
      bg3_osiris_rete_adaptor* right_a = get_right_adaptor(table->save, node);
      bg3_osiris_rete_node* left_parent = get_left_parent_node(table->save, node);
      bg3_osiris_rete_node* right_parent = get_right_parent_node(table->save, node);
      propagate_from_to(table, node, left_parent, left_a);
      propagate_from_to(table, node, right_parent, right_a);
      break;
    }
    default:
      bg3_panic("invalid node type");
  }
}

static char const* osiris_goal_state_name(bg3_osiris_goal_state state) {
  static const char* names[] = {
      "active",   "invalid1", "sleeping",   "invalid3",
      "invalid4", "invalid5", "finalising", "exited",
  };
  return state < LIBBG3_COUNT_OF(names) ? names[state] : "unknown";
}

static void osiris_save_put_sexp_value(bg3_osiris_save* save, bg3_osiris_variant* value) {
  if (value->type == bg3_osiris_prim_type_undef) {
    bg3_ibuf_printf(&save->text_out, "undef");
    return;
  }
  bool needs_cast = value->index != value->type ||
                    value->type == bg3_osiris_prim_type_guidstring ||
                    value->type == bg3_osiris_prim_type_integer64;
  if (needs_cast) {
    bg3_ibuf_printf(&save->text_out, "(%s ", save->type_infos[value->index - 1].name);
  }
  switch (value->type) {
    case bg3_osiris_prim_type_integer:
      bg3_ibuf_printf(&save->text_out, "%d", value->integer);
      break;
    case bg3_osiris_prim_type_integer64:
      bg3_ibuf_printf(&save->text_out, "%" PRIi64, value->integer64);
      break;
    case bg3_osiris_prim_type_real:
      bg3_ibuf_printf(&save->text_out, "%f", value->real);
      break;
    case bg3_osiris_prim_type_string:
    case bg3_osiris_prim_type_guidstring:
      bg3_ibuf_printf(&save->text_out, "\"%s\"", value->string);
      break;
    case bg3_osiris_prim_type_enum:
      bg3_ibuf_printf(&save->text_out, "%s", value->string);
      break;
    default:
      bg3_panic("invalid prim type");
  }
  if (needs_cast) {
    bg3_ibuf_printf(&save->text_out, ")");
  }
}

static void osiris_save_put_sexp_binding(bg3_osiris_save* save,
                                         bg3_osiris_binding* binding) {
  if (bg3_ibuf_get_next_col(&save->text_out) > 70 &&
      bg3_ibuf_get_indent(&save->text_out) < 70) {
    bg3_ibuf_fresh_line(&save->text_out);
  }
  if (!binding->is_variable) {
    osiris_save_put_sexp_value(save, &binding->value);
  } else {
    bg3_ibuf_printf(&save->text_out, "Var%d", binding->index);
  }
}

static void osiris_save_put_sexp_action_list(bg3_osiris_save* save,
                                             uint32_t num_actions,
                                             bg3_osiris_action* actions) {
  for (uint32_t i = 0; i < num_actions; ++i) {
    bg3_osiris_action* a = actions + i;
    bg3_ibuf_fresh_line(&save->text_out);
    if (a->function) {
      bg3_ibuf_printf(&save->text_out, "(%s%s", a->retract ? "not " : "", a->function);
      bg3_ibuf_push_align(&save->text_out);
      bg3_ibuf_push(&save->text_out, 1);
      for (uint8_t j = 0; j < a->num_arguments; ++j) {
        bg3_ibuf_printf(&save->text_out, " ");
        osiris_save_put_sexp_binding(save, a->arguments + j);
      }
      bg3_ibuf_pop(&save->text_out);
      bg3_ibuf_pop(&save->text_out);
      bg3_ibuf_printf(&save->text_out, ")");
    } else {
      bg3_ibuf_printf(&save->text_out, "(GoalCompleted)");
    }
  }
}

static void osiris_save_collect_goal_nodes(bg3_osiris_save* save,
                                           bg3_buffer* node_lists) {
  int32_t* node_owners = (int32_t*)malloc(sizeof(int32_t) * save->num_rete_nodes);
  for (uint32_t i = 0; i < save->num_rete_nodes; ++i) {
    node_owners[i] = -1;
  }
  for (uint32_t i = 0; i < save->num_rete_nodes; ++i) {
    bg3_osiris_rete_node* n = save->rete_nodes + i;
    if (n->type == bg3_osiris_rete_node_event || n->type == bg3_osiris_rete_node_db) {
      for (uint32_t j = 0; j < n->trigger.num_children; ++j) {
        bg3_osiris_rete_node_edge* c = n->trigger.children + j;
        if (node_owners[c->node_id - 1] != -1 &&
            node_owners[c->node_id - 1] != c->goal_id - 1) {
          bg3_panic("node %d is owned by multiple goals", c->node_id);
        }
        node_owners[c->node_id - 1] = c->goal_id - 1;
      }
    }
  }
  for (uint32_t i = 0; i < save->num_rete_nodes; ++i) {
    bg3_osiris_rete_node* n = save->rete_nodes + i;
    if (n->type != bg3_osiris_rete_node_terminal) {
      continue;
    }
    int32_t controlling_goal = get_owner_in_chain(save, n, node_owners);
    if (controlling_goal < 0) {
      // TODO: these are "always enabled" rules. we need to find the most
      // recent prior rule and emit this rule in a special form after that
      // rule's definition.
      bg3_error("unable to find a controlling goal for node %d\n", i + 1);
      continue;
    }
    bg3_buffer_push(node_lists + controlling_goal, &i, sizeof(uint32_t));
  }
  free(node_owners);
}

void osiris_save_put_sexp_condition_list(bg3_osiris_save* save,
                                         bg3_osiris_rete_node* node,
                                         bg3_osiris_rete_adaptor* child_adaptor,
                                         osiris_node_bindings* child_bindings,
                                         bool is_not,
                                         osiris_node_bindings_table* table) {
  bg3_osiris_rete_node* left_parent = get_left_parent_node(save, node);
  bg3_osiris_rete_adaptor* left_adaptor = get_left_adaptor(save, node);
  bg3_osiris_rete_node* right_parent = get_right_parent_node(save, node);
  bg3_osiris_rete_adaptor* right_adaptor = get_right_adaptor(save, node);
  osiris_node_bindings* bindings = osiris_node_bindings_table_get(table, node);
  if (left_parent) {
    osiris_save_put_sexp_condition_list(save, left_parent, left_adaptor, bindings, false,
                                        table);
  }
  if (right_parent) {
    bg3_ibuf_fresh_line(&save->text_out);
    osiris_save_put_sexp_condition_list(save, right_parent, right_adaptor, bindings,
                                        node->type == bg3_osiris_rete_node_join_and_not,
                                        table);
  }
  if (node->name) {
    if (left_parent) {
      bg3_ibuf_fresh_line(&save->text_out);
    }
    bg3_ibuf_printf(&save->text_out, "(%s%s", is_not ? "not " : "", node->name);
    for (size_t i = 0; i < node->arity; ++i) {
      if (child_adaptor->vars[i] == 255) {
        bool found = false;
        for (uint8_t j = 0; j < child_adaptor->num_values; ++j) {
          if (child_adaptor->values[j].index == i) {
            bg3_ibuf_printf(&save->text_out, " ");
            osiris_save_put_sexp_value(save, &child_adaptor->values[j].value);
            found = true;
            break;
          }
        }
        if (!found) {
          bg3_ibuf_printf(&save->text_out, " _");
        }
      } else {
        bg3_ibuf_printf(&save->text_out, " %s",
                        child_bindings->entries[child_adaptor->vars[i]]->name);
      }
    }
    bg3_ibuf_printf(&save->text_out, ")");
  } else if (node->type == bg3_osiris_rete_node_compare) {
    if (left_parent) {
      bg3_ibuf_fresh_line(&save->text_out);
    }
    static const char* opcode_names[] = {
        "<", "<=", ">", ">=", "=", "!=",
    };
    bg3_ibuf_printf(&save->text_out, "(%s", opcode_names[node->compare.opcode]);
    bg3_ibuf_printf(&save->text_out, " ");
    if (node->compare.left_var == 255) {
      osiris_save_put_sexp_value(save, &node->compare.left_value);
    } else {
      if (node->compare.left_var >= bindings->arity) {
        bg3_panic("index out of range");
      }
      bg3_ibuf_printf(&save->text_out, "%s",
                      bindings->entries[node->compare.left_var]->name);
    }
    bg3_ibuf_printf(&save->text_out, " ");
    if (node->compare.right_var == 255) {
      osiris_save_put_sexp_value(save, &node->compare.right_value);
    } else {
      if (node->compare.right_var >= bindings->arity) {
        bg3_panic("index out of range");
      }
      bg3_ibuf_printf(&save->text_out, "%s",
                      bindings->entries[node->compare.right_var]->name);
    }
    bg3_ibuf_printf(&save->text_out, ")");
  }
}

bg3_status bg3_osiris_save_write_sexp(bg3_osiris_save* save,
                                      char const* path,
                                      bool verbose) {
  FILE* fp = fopen(path, "wb");
  if (!fp) {
    return bg3_error_failed;
  }
  bg3_buffer* node_lists = (bg3_buffer*)calloc(save->num_goals, sizeof(bg3_buffer));
  osiris_save_collect_goal_nodes(save, node_lists);
  bg3_ibuf_clear(&save->text_out);
  bg3_ibuf_printf(&save->text_out, "(defstory \"%s\" \"%s\" %d %d %d)\n", save->version,
                  save->story_version, save->version_major, save->version_minor,
                  save->debug_flags);
  for (uint32_t i = 0; i < save->num_type_infos; ++i) {
    bg3_osiris_type_info* ti = save->type_infos + i;
    bg3_ibuf_fresh_line(&save->text_out);
    if (ti->alias_index) {
      bg3_ibuf_printf(&save->text_out, "(deftype %s %s)", ti->name,
                      save->type_infos[ti->alias_index - 1].name);
    }
  }
  for (uint32_t i = 0; i < save->num_enums; ++i) {
    bg3_osiris_enum_info* ei = save->enums + i;
    bg3_ibuf_fresh_line(&save->text_out);
    bg3_ibuf_printf(&save->text_out, "(defenum %s", save->type_infos[ei->index - 1].name);
    bg3_ibuf_push(&save->text_out, 2);
    for (uint32_t j = 0; j < ei->num_entries; ++j) {
      bg3_ibuf_fresh_line(&save->text_out);
      bg3_ibuf_printf(&save->text_out, "(%s %" PRIi64 ")", ei->entries[j].name,
                      ei->entries[j].value);
    }
    bg3_ibuf_printf(&save->text_out, ")");
    bg3_ibuf_pop(&save->text_out);
  }
  for (uint32_t i = 0; i < save->num_functions; ++i) {
    static const char* fn_type_names[] = {
        "invalid", "event",    "divquery", "divcall", "db",
        "proc",    "sysquery", "syscall",  "query",
    };
    bg3_osiris_function_info* fi = save->functions + i;
    bg3_ibuf_fresh_line(&save->text_out);
    bg3_ibuf_printf(&save->text_out, "(def%s %s", fn_type_names[fi->type], fi->name);
    if (fi->is_external) {
      bg3_ibuf_printf(&save->text_out, " %d", fi->div_opcode);
    }
    if (!fi->is_external && fi->sys_opcode) {
      bg3_ibuf_printf(&save->text_out, " %d", fi->sys_opcode);
    }
    bg3_ibuf_push(&save->text_out, 2);
    for (uint8_t j = 0; j < fi->num_params; ++j) {
      bg3_osiris_type_info* ti = save->type_infos + (fi->params[j] - 1);
      if (fi->out_mask & LIBBG3_OSIRIS_OUT_PARAM_MASK(j)) {
        bg3_ibuf_printf(&save->text_out, " (out %s)", ti->name);
      } else {
        bg3_ibuf_printf(&save->text_out, " %s", ti->name);
      }
    }
    bg3_ibuf_pop(&save->text_out);
    bg3_ibuf_printf(&save->text_out, ")");
  }
  for (uint32_t i = 0; i < save->num_goals; ++i) {
    static const char* combiner_names[] = {"or", "and"};
    bg3_osiris_goal* g = save->goals + i;
    bg3_ibuf_fresh_line(&save->text_out);
    // TODO: Allow quoted syntax for goal names to avoid this. There is a single goal in
    // BG3 which has a name that contains a space.
    char* escaped_goal_name = strdup(g->name);
    for (char* c = escaped_goal_name; *c; ++c) {
      if (*c == ' ') {
        *c = '_';
      }
    }
    bg3_ibuf_printf(&save->text_out, "(defgoal (%s %s %s)", escaped_goal_name,
                    osiris_goal_state_name(g->state), combiner_names[g->combiner]);
    free(escaped_goal_name);
    bg3_ibuf_push(&save->text_out, 2);
    if (g->parent) {
      bg3_ibuf_fresh_line(&save->text_out);
      bg3_ibuf_printf(&save->text_out, "(parent %s)", save->goals[g->parent - 1].name);
    }
    if (g->num_init_actions) {
      bg3_ibuf_fresh_line(&save->text_out);
      bg3_ibuf_printf(&save->text_out, "(init");
      bg3_ibuf_push(&save->text_out, 2);
      osiris_save_put_sexp_action_list(save, g->num_init_actions, g->init_actions);
      bg3_ibuf_printf(&save->text_out, ")");
      bg3_ibuf_pop(&save->text_out);
    }
    if (g->num_exit_actions) {
      bg3_ibuf_fresh_line(&save->text_out);
      bg3_ibuf_printf(&save->text_out, "(exit");
      bg3_ibuf_push(&save->text_out, 2);
      osiris_save_put_sexp_action_list(save, g->num_exit_actions, g->exit_actions);
      bg3_ibuf_printf(&save->text_out, ")");
      bg3_ibuf_pop(&save->text_out);
    }
    bg3_buffer* owned_nodes_buf = node_lists + i;
    size_t num_owned_nodes = owned_nodes_buf->size / sizeof(uint32_t);
    uint32_t* owned_nodes = (uint32_t*)owned_nodes_buf->data;
    for (size_t i = 0; i < num_owned_nodes; ++i) {
      bg3_osiris_rete_node* node = save->rete_nodes + owned_nodes[i];
      osiris_node_bindings_table table;
      osiris_node_bindings_table_init(&table, save);
      osiris_node_bindings_table_propagate(&table, node);
      bg3_ibuf_fresh_line(&save->text_out);
      bg3_ibuf_printf(&save->text_out, "(rule (");
      bg3_ibuf_push_align(&save->text_out);
      osiris_save_put_sexp_condition_list(save, node, 0, 0, false, &table);
      bg3_ibuf_printf(&save->text_out, ")");
      bg3_ibuf_pop(&save->text_out);
      bg3_ibuf_push(&save->text_out, 2);
      bg3_ibuf_fresh_line(&save->text_out);
      osiris_save_put_sexp_action_list(save, node->terminal.num_actions,
                                       node->terminal.actions);
      bg3_ibuf_printf(&save->text_out, ")");
      bg3_ibuf_pop(&save->text_out);
      osiris_node_bindings_table_destroy(&table);
    }
    bg3_ibuf_printf(&save->text_out, ")");
    bg3_ibuf_pop(&save->text_out);
  }
  bg3_ibuf_fresh_line(&save->text_out);
  fwrite(save->text_out.output.data, 1, save->text_out.output.size, fp);
  fclose(fp);
  return bg3_success;
}

typedef enum symtype {
  symtype_function,
  symtype_type,
  symtype_goal,
  symtype_compare,
  symtype_reserved,
  symtype_variable,
} symtype;

typedef enum reserved_symbol {
  symbol_goal_completed,
} reserved_symbol;

static bg3_status enter_global(bg3_osiris_save_builder* builder,
                               char const* name,
                               void* symval) {
  bg3_hash_entry* entry = bg3_hash_get_entry(&builder->global_symbols, (void*)name);
  if (entry) {
    return bg3_error_failed;
  }
  bg3_hash_set(&builder->global_symbols, (void*)name, symval);
  return bg3_success;
}

static bg3_status lookup_global(bg3_osiris_save_builder* builder,
                                char* name,
                                void** symval) {
  bg3_hash_entry* entry = bg3_hash_get_entry(&builder->global_symbols, name);
  if (entry) {
    *symval = entry->value;
    return bg3_success;
  }
  *symval = 0;
  return bg3_error_failed;
}

static bg3_status enter_local(bg3_osiris_save_builder* builder,
                              char* name,
                              void* symval) {
  bg3_hash_entry* entry = bg3_hash_get_entry(&builder->local_symbols, name);
  if (entry) {
    return bg3_error_failed;
  }
  bg3_hash_set(&builder->local_symbols, name, symval);
  return bg3_success;
}

static bg3_status lookup_local(bg3_osiris_save_builder* builder,
                               char* name,
                               void** symval) {
  bg3_hash_entry* entry = bg3_hash_get_entry(&builder->local_symbols, name);
  if (entry) {
    *symval = entry->value;
    return bg3_success;
  }
  *symval = 0;
  return bg3_error_failed;
}

static bg3_status enter_function(bg3_osiris_save_builder* builder,
                                 char* name,
                                 bg3_osiris_function_info* fn) {
  size_t new_index = builder->save.num_functions + 1;
  if (enter_global(builder, name,
                   LIBBG3_MAKE_SYMBOL_VALUE(symtype_function, new_index))) {
    return bg3_error_failed;
  }
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, functions, *fn);
  return bg3_success;
}

static bg3_osiris_function_info* lookup_function(bg3_osiris_save_builder* builder,
                                                 char* name) {
  void* symval;
  if (lookup_global(builder, name, &symval) ||
      LIBBG3_SYMBOL_TYPE_OF(symval) != symtype_function) {
    return 0;
  }
  return builder->save.functions + (LIBBG3_SYMBOL_INDEX_OF(symval) - 1);
}

static bg3_status enter_type_info(bg3_osiris_save_builder* builder,
                                  char const* name,
                                  bg3_osiris_type_info* ti) {
  size_t new_index = builder->save.num_type_infos + 1;
  if (enter_global(builder, name, LIBBG3_MAKE_SYMBOL_VALUE(symtype_type, new_index))) {
    return bg3_error_failed;
  }
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, type_infos, *ti);
  return bg3_success;
}

static bg3_osiris_type_info* lookup_type_info(bg3_osiris_save_builder* builder,
                                              char* name) {
  void* symval;
  if (lookup_global(builder, name, &symval) ||
      LIBBG3_SYMBOL_TYPE_OF(symval) != symtype_type) {
    return 0;
  }
  return builder->save.type_infos + (LIBBG3_SYMBOL_INDEX_OF(symval) - 1);
}

static bg3_status enter_goal(bg3_osiris_save_builder* builder,
                             char* name,
                             bg3_osiris_goal* goal) {
  size_t new_index = builder->save.num_goals + 1;
  assert(goal->goal_id == new_index);
  if (enter_global(builder, name, LIBBG3_MAKE_SYMBOL_VALUE(symtype_goal, new_index))) {
    return bg3_error_failed;
  }
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, goals, *goal);
  return bg3_success;
}

static bg3_osiris_goal* lookup_goal(bg3_osiris_save_builder* builder, char* name) {
  void* symval;
  if (lookup_global(builder, name, &symval) ||
      LIBBG3_SYMBOL_TYPE_OF(symval) != symtype_goal) {
    return 0;
  }
  return builder->save.goals + (LIBBG3_SYMBOL_INDEX_OF(symval) - 1);
}

static bg3_status enter_variable(bg3_osiris_save_builder* builder,
                                 char* name,
                                 uint32_t var_index) {
  return enter_local(builder, name,
                     LIBBG3_MAKE_SYMBOL_VALUE(symtype_variable, var_index));
}

void bg3_osiris_save_builder_init(bg3_osiris_save_builder* builder) {
  memset(builder, 0, sizeof(bg3_osiris_save_builder));
  bg3_osiris_save_init(&builder->save);
  bg3_hash_init(&builder->global_symbols, &bg3_symtab_hash_ops, &builder->save.alloc);
  bg3_hash_init(&builder->local_symbols, &bg3_symtab_hash_ops, &builder->save.alloc);
  bg3_osiris_type_info builtin_integer = {.name = "INTEGER", .index = 1};
  bg3_osiris_type_info builtin_integer64 = {.name = "INTEGER64", .index = 2};
  bg3_osiris_type_info builtin_real = {.name = "REAL", .index = 3};
  bg3_osiris_type_info builtin_string = {.name = "STRING", .index = 4};
  bg3_osiris_type_info builtin_guidstring = {.name = "GUIDSTRING", .index = 5};
  enter_global(builder, "INTEGER", LIBBG3_MAKE_SYMBOL_VALUE(symtype_type, 1));
  enter_global(builder, "INTEGER64", LIBBG3_MAKE_SYMBOL_VALUE(symtype_type, 2));
  enter_global(builder, "REAL", LIBBG3_MAKE_SYMBOL_VALUE(symtype_type, 3));
  enter_global(builder, "STRING", LIBBG3_MAKE_SYMBOL_VALUE(symtype_type, 4));
  enter_global(builder, "GUIDSTRING", LIBBG3_MAKE_SYMBOL_VALUE(symtype_type, 5));
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, type_infos, builtin_integer);
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, type_infos, builtin_integer64);
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, type_infos, builtin_real);
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, type_infos, builtin_string);
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, type_infos, builtin_guidstring);
  enter_global(builder, "=",
               LIBBG3_MAKE_SYMBOL_VALUE(symtype_compare, bg3_osiris_compare_equal));
  enter_global(builder, "!=",
               LIBBG3_MAKE_SYMBOL_VALUE(symtype_compare, bg3_osiris_compare_not_equal));
  enter_global(builder, "<",
               LIBBG3_MAKE_SYMBOL_VALUE(symtype_compare, bg3_osiris_compare_less));
  enter_global(builder, "<=",
               LIBBG3_MAKE_SYMBOL_VALUE(symtype_compare, bg3_osiris_compare_less_equal));
  enter_global(builder, ">",
               LIBBG3_MAKE_SYMBOL_VALUE(symtype_compare, bg3_osiris_compare_greater));
  enter_global(
      builder,
      ">=", LIBBG3_MAKE_SYMBOL_VALUE(symtype_compare, bg3_osiris_compare_greater_equal));
  enter_global(builder, "GoalCompleted/0",
               LIBBG3_MAKE_SYMBOL_VALUE(symtype_reserved, symbol_goal_completed));
}

void bg3_osiris_save_builder_destroy(bg3_osiris_save_builder* builder) {
  bg3_osiris_save_destroy(&builder->save);
  bg3_hash_destroy(&builder->global_symbols);
  bg3_hash_destroy(&builder->local_symbols);
  bg3_buffer_destroy(&builder->current_toplevel.text);
  bg3_buffer_destroy(&builder->current_item.text);
}

static bg3_status parse_defun(bg3_osiris_save_builder* builder,
                              bg3_sexp_lexer* l,
                              bg3_osiris_function_type type) {
  SLURP(symbol);
  MATCH(symbol);
  bg3_osiris_function_info fn = {.type = type};
  bg3_sexp_token_copy(&builder->current_item, &l->next);
  fn.name = bg3_arena_strdup(&builder->save.alloc, l->next.text.data);
  fn.line = l->next.line;
  SLURP(symbol);
  if (type == bg3_osiris_function_div_query || type == bg3_osiris_function_div_call ||
      type == bg3_osiris_function_event) {
    // div opcode
    MATCH(integer);
    fn.sys_opcode = type == bg3_osiris_function_div_call    ? 1
                    : type == bg3_osiris_function_div_query ? 2
                                                            : 3;
    fn.div_opcode = l->next.int_val;
    fn.is_external = 1;
    SLURP(integer);
  } else if (type == bg3_osiris_function_sys_query ||
             type == bg3_osiris_function_sys_call) {
    // sys opcode
    MATCH(integer);
    fn.sys_opcode = l->next.int_val;
    SLURP(integer);
  }
  while (l->next.type != bg3_sexp_token_type_rparen) {
    bg3_osiris_type_info* ti;
    // out param
    if (l->next.type == bg3_sexp_token_type_lparen) {
      fn.out_mask |= LIBBG3_OSIRIS_OUT_PARAM_MASK(fn.num_params);
      SLURP(lparen);
      MATCH(symbol);
      if (strcmp(l->next.text.data, "out")) {
        fprintf(stderr, "expected symbol 'out', got '%s' at line %d'\n",
                l->next.text.data, l->next.line);
        return bg3_error_failed;
      }
      SLURP(symbol);
      MATCH(symbol);
      if (!(ti = lookup_type_info(builder, l->next.text.data))) {
        fprintf(stderr, "unknown parameter type '%s' at line %d\n", l->next.text.data,
                l->next.line);
        return bg3_error_failed;
      }
      SLURP(symbol);
      SLURP(rparen);
    } else {
      MATCH(symbol);
      if (!(ti = lookup_type_info(builder, l->next.text.data))) {
        fprintf(stderr, "unknown parameter type '%s' at line %d\n", l->next.text.data,
                l->next.line);
        return bg3_error_failed;
      }
      SLURP(symbol);
    }
    LIBBG3_ARRAY_PUSH(&builder->save.alloc, &fn, params, ti->index);
    if (fn.num_params > 31) {
      fprintf(stderr, "too many function parameters at line %d\n", l->next.line);
      return bg3_error_failed;
    }
  }
  bg3_buffer_printf(&builder->current_item.text, "/%d", fn.num_params);
  if (enter_function(builder, builder->current_item.text.data, &fn)) {
    fprintf(stderr, "error at line %d: %s already defined\n", fn.line,
            builder->current_item.text.data);
    return bg3_error_failed;
  }
  SLURP(rparen);
  return bg3_success;
}

static bg3_status parse_value(bg3_osiris_save_builder* builder,
                              bg3_sexp_lexer* l,
                              bg3_osiris_variant* value) {
  if (l->next.type == bg3_sexp_token_type_string) {
    value->type = bg3_osiris_prim_type_string;
    value->string = bg3_arena_strdup(&builder->save.alloc, l->next.text.data);
    SLURP(string);
  } else if (l->next.type == bg3_sexp_token_type_decimal) {
    value->type = bg3_osiris_prim_type_real;
    value->real = l->next.float_val;
    SLURP(decimal);
  } else if (l->next.type == bg3_sexp_token_type_integer) {
    value->type = bg3_osiris_prim_type_integer64;
    value->integer64 = l->next.int_val;
    SLURP(integer);
  } else {
    fprintf(stderr, "expected value at line %d\n", l->next.line);
    return bg3_error_failed;
  }
  return bg3_success;
}

static bg3_status parse_argument(bg3_osiris_save_builder* builder,
                                 bg3_sexp_lexer* l,
                                 bg3_osiris_binding* arg,
                                 bool allow_fresh_vars) {
  bg3_status status = bg3_success;
  if (l->next.type == bg3_sexp_token_type_symbol) {
    // variables
    if (l->next.text.size == 1 && *l->next.text.data == '_' && allow_fresh_vars) {
      // don't-care vars are output as a grounded undef constant. these can
      // only occur in a constext where a fresh variable binding is allowed
      // because they are effectively fresh variables that are always
      // discarded, but the compiled format has a special syntax for them (-1
      // output without a corresponding constant in the adaptor)
      //
      // the way we currently handle these is very different from what Larian's
      // compiler does and results in the variable being completely eliminated
      // from the final output instead of recorded as an unused variable in the
      // rule node. this seems to work fine and keeps the adaptor generation
      // very simple.
      arg->is_grounded = 1;
      SLURP(symbol);
      return bg3_success;
    }
    void* localsym;
    if ((status = lookup_local(builder, l->next.text.data, &localsym))) {
      if (allow_fresh_vars) {
        if (builder->next_var == LIBBG3_OSIRIS_MAX_LOCALS) {
          fprintf(stderr, "too many local vars at line %d\n", l->next.line);
          return bg3_error_failed;
        }
        status = enter_variable(builder, l->next.text.data, builder->next_var);
        localsym = LIBBG3_MAKE_SYMBOL_VALUE(symtype_variable, builder->next_var);
        assert(!status);
        bg3_osiris_binding* new_var = builder->current_vars + builder->next_var;
        new_var->is_variable = 1;
        new_var->is_variable_again = 1;
        new_var->is_live = 1;
        new_var->index = builder->next_var;
        builder->next_var++;
      } else {
        fprintf(stderr, "undefined local '%s' at line %d\n", l->next.text.data,
                l->next.line);
        return status;
      }
    }
    SLURP(symbol);
    *arg = builder->current_vars[LIBBG3_SYMBOL_INDEX_OF(localsym)];
    return bg3_success;
  } else if (l->next.type == bg3_sexp_token_type_lparen) {
    // cast or enum
    arg->is_grounded = 1;
    arg->is_live = 1;
    SLURP(lparen);
    MATCH(symbol);
    bg3_osiris_type_info* type_info = lookup_type_info(builder, l->next.text.data);
    if (!type_info) {
      fprintf(stderr, "undefined type '%s' at line %d\n", l->next.text.data,
              l->next.line);
      return bg3_error_failed;
    }
    arg->value.index = type_info->index;
    SLURP(symbol);
    if (l->next.type == bg3_sexp_token_type_symbol) {
      // enum case
      if (!type_info->enum_index) {
        fprintf(stderr,
                "expected literal but got an enum value; type '%s' is "
                "not an enum type at line %d\n",
                type_info->name, l->next.line);
        return bg3_error_failed;
      }
      bg3_osiris_enum_info* enum_info = builder->save.enums + (type_info->enum_index - 1);
      bool found = false;
      char* enum_val = 0;
      for (uint32_t i = 0; i < enum_info->num_entries; ++i) {
        if (!strcmp(enum_info->entries[i].name, l->next.text.data)) {
          enum_val = enum_info->entries[i].name;
          found = true;
          break;
        }
      }
      if (!found) {
        fprintf(stderr,
                "value '%s' is not a valid member of enum '%s' at line "
                "%d\n",
                l->next.text.data, type_info->name, l->next.line);
        return bg3_error_failed;
      }
      arg->value.type = bg3_osiris_prim_type_enum;
      arg->value.string = enum_val;
      SLURP(symbol);
    } else {
      // cast literal
      status = parse_value(builder, l, &arg->value);
    }
    if (!status) {
      SLURP(rparen);
    }
  } else if (l->next.type == bg3_sexp_token_type_string ||
             l->next.type == bg3_sexp_token_type_decimal ||
             l->next.type == bg3_sexp_token_type_integer) {
    // bare literal
    arg->is_grounded = 1;
    arg->is_live = 1;
    status = parse_value(builder, l, &arg->value);
    // treat bare literals as 32bit. we don't truncate in parse_value so the
    // cast case can use the upper bits
    if (arg->value.type == bg3_osiris_prim_type_integer64) {
      arg->value.type = bg3_osiris_prim_type_integer;
      arg->value.integer = (int32_t)arg->value.integer64;
    }
    arg->value.index = arg->value.type;
  } else {
    fprintf(stderr,
            "invalid argument at line %d. expected type cast, variable or "
            "literal.",
            l->next.line);
    return bg3_error_failed;
  }
  // Make sure the prim type matches the declared type and do implicit
  // literal coercions for alias types.
  assert(arg->value.index != 0);
  bg3_osiris_type_info* resolved = builder->save.type_infos + (arg->value.index - 1);
  while (resolved->alias_index && !resolved->enum_index) {
    resolved = builder->save.type_infos + (resolved->alias_index - 1);
  }
  // We don't have separate literal syntax for 32/64 integers and GUID
  // strings right now, so implicitly coerce casted literals as needed.
  if (arg->value.type == bg3_osiris_prim_type_string &&
      resolved->index == bg3_osiris_prim_type_guidstring) {
    arg->value.type = bg3_osiris_prim_type_guidstring;
  }
  if (arg->value.type == bg3_osiris_prim_type_integer64 &&
      resolved->index == bg3_osiris_prim_type_integer) {
    arg->value.type = bg3_osiris_prim_type_integer;
  }
  if ((arg->value.type == bg3_osiris_prim_type_enum && !resolved->enum_index) ||
      (arg->value.type != bg3_osiris_prim_type_enum &&
       arg->value.type != resolved->index)) {
    // TODO: write a better error message for this. This case can happen if
    // you do e.g. (GUIDSTRING 0) or similar.
    fprintf(stderr, "literal value does not match type at line %d.\n", l->next.line);
    return bg3_error_failed;
  }
  return status;
}

static char const* get_type_name(bg3_osiris_save_builder* builder, uint16_t index) {
  if (!index) {
    return "undef";
  }
  if (index <= builder->save.num_type_infos) {
    return builder->save.type_infos[index - 1].name;
  }
  return "???";
}

static bg3_status infer_and_check_types(bg3_osiris_save_builder* builder,
                                        bg3_osiris_function_info* predicate,
                                        uint32_t num_bindings,
                                        bg3_osiris_binding* bindings,
                                        uint32_t* binding_lines) {
  for (uint32_t i = 0; i < num_bindings; ++i) {
    bg3_osiris_binding* b = bindings + i;
    if (b->is_variable) {
      // reload variables to propagate changes forward
      *b = builder->current_vars[b->index];
    }
    bg3_osiris_type_info* ti = builder->save.type_infos + (predicate->params[i] - 1);
    // If the types are compatible, we're done here. We consider types
    // compatible if either:
    // 1. They are identical
    // 2. One is in the alias chain of the other
    // TODO: test this adequately. we want e.g. GUIDSTRING->ITEMROOT->ROOT
    // conversions to happen but not e.g. CHARACTER->ROOT. In general, I
    // really don't like this, but I don't see anywhere in the save format
    // that type conversions are actually treated explicitly...
    bg3_osiris_type_info* resolved_binding =
        b->value.index ? builder->save.type_infos + (b->value.index - 1) : 0;
    bool found_match = false;
    bg3_osiris_type_info* resolved = ti;
    while (resolved->alias_index) {
      resolved = builder->save.type_infos + (resolved->alias_index - 1);
      if (resolved->index == b->value.index) {
        found_match = true;
      }
    }
    while (resolved_binding && resolved_binding->alias_index) {
      resolved_binding = builder->save.type_infos + (resolved_binding->alias_index - 1);
      if (resolved_binding->index == ti->index) {
        found_match = true;
      }
    }
    if (b->value.index == ti->index || found_match) {
      continue;
    }
    // At this point, either we have a constant of the wrong type, a
    // variable whose usage doesn't match its previously inferred type, a
    // don't-care variable or a variable whose type hasn't been inferred
    // yet. The first 2 cases are an error here.
    if (b->value.index) {
      fprintf(stderr,
              "type mismatch in arg %d to predicate '%s' at line "
              "%d\n ... expected type '%s', actual type '%s'\n",
              i + 1, builder->current_item.text.data, binding_lines[i], ti->name,
              get_type_name(builder, b->value.index));
      return bg3_error_failed;
    }
    // A variable or don't-care we haven't seen yet, assign its type.
    b->value.index = ti->index;
    if (b->is_variable) {
      b->value.type = (bg3_osiris_prim_type)(ti->enum_index ? bg3_osiris_prim_type_enum
                                                            : resolved->index);
      // write back changes to variables to propagate forward
      builder->current_vars[b->index] = *b;
    }
  }
  return bg3_success;
}

typedef struct action_list {
  uint32_t num_actions;
  uint32_t cap_actions;
  bg3_osiris_action* actions;
} action_list;

static bg3_status parse_action_list(bg3_osiris_save_builder* builder,
                                    bg3_sexp_lexer* l,
                                    action_list* alist) {
  bg3_status status = bg3_success;
  while (!status && l->next.type != bg3_sexp_token_type_rparen) {
    bg3_osiris_action action = {};
    uint32_t binding_lines[LIBBG3_OSIRIS_MAX_LOCALS];
    void* symval;
    SLURP(lparen);
    MATCH(symbol);
    if (!strcmp(l->next.text.data, "not")) {
      action.retract = true;
      SLURP(symbol);
      MATCH(symbol);
    }
    bg3_sexp_token_copy(&builder->current_item, &l->next);
    SLURP(symbol);
    while (!status && l->next.type != bg3_sexp_token_type_rparen) {
      bg3_osiris_binding binding = {};
      if (action.num_arguments == LIBBG3_OSIRIS_MAX_LOCALS) {
        fprintf(stderr, "too many arguments at line %d\n", l->next.line);
        return bg3_error_failed;
      }
      binding_lines[action.num_arguments] = l->next.line;
      status = parse_argument(builder, l, &binding, false);
      if (!status) {
        LIBBG3_ARRAY_PUSH(&builder->save.alloc, &action, arguments, binding);
      }
    }
    if (status) {
      return status;
    }
    bg3_buffer_printf(&builder->current_item.text, "/%d", action.num_arguments);
    if ((status = lookup_global(builder, builder->current_item.text.data, &symval))) {
      fprintf(stderr, "undefined symbol '%s' at line %d\n",
              builder->current_item.text.data, builder->current_item.line);
      return status;
    }
    if (LIBBG3_SYMBOL_TYPE_OF(symval) == symtype_reserved &&
        LIBBG3_SYMBOL_INDEX_OF(symval) == symbol_goal_completed) {
      if (action.retract) {
        fprintf(stderr, "'not' modifier is invalid on GoalCompleted at line %d\n",
                l->next.line);
        return bg3_error_failed;
      }
      action.completed_goal_id = builder->current_goal_id;
    } else if (LIBBG3_SYMBOL_TYPE_OF(symval) != symtype_function) {
      fprintf(stderr, "'%s' does not name a predicate at line %d\n",
              builder->current_item.text.data, builder->current_item.line);
      return bg3_error_failed;
    } else {
      bg3_osiris_function_info* fn =
          builder->save.functions + (LIBBG3_SYMBOL_INDEX_OF(symval) - 1);
      if ((status = infer_and_check_types(builder, fn, action.num_arguments,
                                          action.arguments, binding_lines))) {
        return bg3_error_failed;
      }
      action.function = fn->name;
      fn->num_actions++;
    }
    LIBBG3_ARRAY_PUSH(&builder->save.alloc, alist, actions, action);
    SLURP(rparen);
  }
  SLURP(rparen);
  return status;
}

typedef enum condition_type {
  condition_empty,
  condition_trigger,
  condition_join,
  condition_compare,
  condition_terminal,
} condition_type;

typedef struct condition {
  condition_type type;
  uint32_t line;
  uint32_t num_bindings;
  bg3_osiris_binding bindings[LIBBG3_OSIRIS_MAX_LOCALS];
  uint32_t binding_lines[LIBBG3_OSIRIS_MAX_LOCALS];
  bool debug_copied_down[LIBBG3_OSIRIS_MAX_LOCALS];
  bool negated;
  bg3_osiris_compare_op compare_op;
  bg3_osiris_function_info* predicate;
  uint32_t node_id;
  bool root_is_query;
} condition;

static bg3_status parse_condition(bg3_osiris_save_builder* builder,
                                  bg3_sexp_lexer* l,
                                  condition* cond) {
  bg3_status status = bg3_success;
  cond->line = l->next.line;
  SLURP(lparen);
  MATCH(symbol);
  void* symval;
  if (!lookup_global(builder, l->next.text.data, &symval) &&
      LIBBG3_SYMBOL_TYPE_OF(symval) == symtype_compare) {
    cond->type = condition_compare;
    cond->compare_op = (bg3_osiris_compare_op)LIBBG3_SYMBOL_INDEX_OF(symval);
  } else {
    if (!strcmp(l->next.text.data, "not")) {
      SLURP(symbol);
      MATCH(symbol);
      cond->negated = true;
    }
    cond->type = condition_trigger;
    bg3_sexp_token_copy(&builder->current_item, &l->next);
  }
  SLURP(symbol);
  while (!status && l->next.type != bg3_sexp_token_type_rparen) {
    if (cond->num_bindings == LIBBG3_OSIRIS_MAX_LOCALS) {
      fprintf(stderr, "too many arguments to condition at line %d\n", l->next.line);
      return bg3_error_failed;
    }
    cond->binding_lines[cond->num_bindings] = l->next.line;
    status = parse_argument(builder, l, cond->bindings + cond->num_bindings,
                            cond->type != condition_compare);
    cond->num_bindings++;
  }
  if (cond->type == condition_compare && cond->num_bindings != 2) {
    fprintf(stderr, "comparisons must have 2 arguments at line %d\n", l->next.line);
    return bg3_error_failed;
  }
  if (status) {
    return status;
  }
  if (cond->type == condition_trigger) {
    bg3_buffer_printf(&builder->current_item.text, "/%d", cond->num_bindings);
    cond->predicate = lookup_function(builder, builder->current_item.text.data);
    if (!cond->predicate) {
      fprintf(stderr, "undefined predicate '%s' at line %d\n",
              builder->current_item.text.data, builder->current_item.line);
      return bg3_error_failed;
    }
    if ((status = infer_and_check_types(builder, cond->predicate, cond->num_bindings,
                                        cond->bindings, cond->binding_lines))) {
      return status;
    }
  }
  SLURP(rparen);
  return status;
}

static bool is_valid_trigger(bg3_osiris_function_info* fn) {
  return fn->type == bg3_osiris_function_event || fn->type == bg3_osiris_function_db ||
         fn->type == bg3_osiris_function_proc || fn->type == bg3_osiris_function_query;
}

static bg3_status ensure_entry_node(bg3_osiris_save_builder* builder,
                                    condition* cond,
                                    bool is_left_root) {
  bg3_osiris_rete_node node = {};
  node.name = cond->predicate->name;
  node.node_id = builder->save.num_rete_nodes + 1;
  node.arity = cond->predicate->num_params;
  switch (cond->predicate->type) {
    case bg3_osiris_function_event:
      node.type = bg3_osiris_rete_node_event;
      break;
    case bg3_osiris_function_div_query:
      if (is_left_root) {
        fprintf(stderr,
                "DIV queries may not occur as the first condition of a rule at "
                "line %d\n",
                cond->line);
        return bg3_error_failed;
      }
      node.type = bg3_osiris_rete_node_div_query;
      break;
    case bg3_osiris_function_div_call:
      fprintf(stderr,
              "DIV calls may only occur in the action list of a rule at line %d\n",
              cond->line);
      return bg3_error_failed;
    case bg3_osiris_function_db:
      node.type = bg3_osiris_rete_node_db;
      break;
    case bg3_osiris_function_proc:
      if (!is_left_root) {
        fprintf(stderr,
                "proc may only occur as the first condition of a rule at line %d\n",
                cond->line);
        return bg3_error_failed;
      }
      node.type = bg3_osiris_rete_node_event;
      break;
    case bg3_osiris_function_sys_query:
      if (is_left_root) {
        fprintf(stderr,
                "Osiris internal queries may not occur as the first condition of "
                "a rule "
                "at line %d\n",
                cond->line);
        return bg3_error_failed;
      }
      node.type = bg3_osiris_rete_node_sys_query;
      break;
    case bg3_osiris_function_sys_call:
      fprintf(stderr,
              "Osiris internal calls may only occur in the action list of a rule "
              "at line "
              "%d\n",
              cond->line);
      return bg3_error_failed;
    case bg3_osiris_function_query:
      if (is_left_root) {
        node.type = bg3_osiris_rete_node_event;
        cond->root_is_query = true;
      } else {
        node.type = bg3_osiris_rete_node_query;
      }
      break;
    default:
      bg3_panic("invalid function type %d", cond->predicate->type);
  }
  // we check this after validating to ensure that invalid usage is caught.
  if (!cond->predicate->rete_node) {
    if (node.type == bg3_osiris_rete_node_db) {
      bg3_osiris_rete_db db = {};
      node.db = builder->save.num_dbs + 1;
      db.db_id = node.db;
      db.num_schema_columns = cond->predicate->num_params;
      size_t sz = db.num_schema_columns * sizeof(uint16_t);
      db.schema_columns = (uint16_t*)bg3_arena_alloc(&builder->save.alloc, sz);
      memcpy(db.schema_columns, cond->predicate->params, sz);
      LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, dbs, db);
    }
    LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, rete_nodes, node);
    cond->predicate->rete_node = node.node_id;
  }
  cond->node_id = cond->predicate->rete_node;
  cond->predicate->num_conds++;
  return bg3_success;
}

static uint32_t create_adaptor(bg3_osiris_save_builder* builder,
                               condition* parent,
                               condition* output) {
  bg3_osiris_rete_adaptor adaptor = {
      .adaptor_id = builder->save.num_rete_adaptors + 1,
      .num_vars = (uint8_t)parent->num_bindings,
      .vars = (uint8_t*)bg3_arena_alloc(&builder->save.alloc, parent->num_bindings),
  };
  for (uint32_t i = 0; i < parent->num_bindings; ++i) {
    bg3_osiris_binding* b = parent->bindings + i;
    if (!b->is_variable) {
      adaptor.vars[i] = 255;
      if (b->value.type != bg3_osiris_prim_type_undef) {
        adaptor.num_values++;
      }
    } else {
      adaptor.vars[i] = b->index;
      adaptor.num_pairs++;
      output->num_bindings = LIBBG3_MAX(b->index + 1, output->num_bindings);
      assert(output->num_bindings <= LIBBG3_OSIRIS_MAX_LOCALS);
      output->bindings[b->index] = *b;
      output->debug_copied_down[b->index] = true;
    }
  }
  adaptor.values = (bg3_osiris_rete_adaptor_value*)bg3_arena_calloc(
      &builder->save.alloc, adaptor.num_values, sizeof(bg3_osiris_rete_adaptor_value));
  adaptor.pairs = (bg3_osiris_rete_adaptor_pair*)bg3_arena_calloc(
      &builder->save.alloc, adaptor.num_pairs, sizeof(bg3_osiris_rete_adaptor_pair));
  uint32_t next_value = 0;
  uint32_t next_pair = 0;
  for (uint32_t i = 0; i < parent->num_bindings; ++i) {
    bg3_osiris_binding* b = parent->bindings + i;
    if (!b->is_variable) {
      if (b->value.type != bg3_osiris_prim_type_undef) {
        adaptor.values[next_value].index = i;
        adaptor.values[next_value].value = b->value;
        next_value++;
      }
    } else {
      adaptor.pairs[next_pair].left = b->index;
      adaptor.pairs[next_pair].right = i;
      next_pair++;
    }
  }
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, rete_adaptors, adaptor);
  return adaptor.adaptor_id;
}

static void link_parent(bg3_osiris_save_builder* builder,
                        condition* cond,
                        bg3_osiris_rete_node* node,
                        bg3_osiris_edge_direction dir) {
  bg3_osiris_rete_node_edge edge = {
      .node_id = node->node_id,
      .direction = dir,
      .goal_id = builder->current_goal_id,
  };
  assert(cond->node_id);
  bg3_osiris_rete_node* parent = builder->save.rete_nodes + (cond->node_id - 1);
  switch (parent->type) {
    case bg3_osiris_rete_node_db:
    case bg3_osiris_rete_node_event:
    case bg3_osiris_rete_node_div_query:
    case bg3_osiris_rete_node_sys_query:
    case bg3_osiris_rete_node_query:
      LIBBG3_ARRAY_PUSH(&builder->save.alloc, &parent->trigger, children, edge);
      break;
    case bg3_osiris_rete_node_join_and:
    case bg3_osiris_rete_node_join_and_not:
      parent->join.child = edge;
      break;
    case bg3_osiris_rete_node_compare:
      parent->compare.child = edge;
      break;
    default:
      bg3_panic("cannot add a child to node type %d", parent->type);
  }
}

static void create_temp_db(bg3_osiris_save_builder* builder,
                           condition* cond,
                           bg3_osiris_rete_node* node) {
  bg3_osiris_rete_db db = {};
  node->db = builder->save.num_dbs + 1;
  db.db_id = node->db;
  db.num_schema_columns = cond->num_bindings;
  size_t sz = db.num_schema_columns * sizeof(uint16_t);
  db.schema_columns = (uint16_t*)bg3_arena_alloc(&builder->save.alloc, sz);
  for (uint32_t i = 0; i < cond->num_bindings; ++i) {
    assert(cond->bindings[i].value.index != 0);
    db.schema_columns[i] = cond->bindings[i].value.index;
  }
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, dbs, db);
}

// This is less efficient than forward calculating because we're doing a
// lot of duplicate work for long chains (O(n^2) with respect to path length),
// but the advantage is that it's very easy to calculate on an existing save
// file and therefore verify our result is the exact same as Larian's.
static int8_t calc_db_distance(bg3_osiris_save* save,
                               bg3_osiris_rete_node* node,
                               bg3_osiris_rete_node_edge* edge,
                               uint32_t* db_node) {
  if (!node) {
    *edge = (bg3_osiris_rete_node_edge){};
    *db_node = 0;
    return -1;
  }
  if (node->db) {
    *db_node = node->node_id;
    return 0;
  }
  bg3_osiris_rete_node_edge left_edge, right_edge;
  uint32_t left_db, right_db;
  bg3_osiris_rete_node* lp = get_left_parent_node(save, node);
  bg3_osiris_rete_node* rp = get_right_parent_node(save, node);
  int8_t lp_dist = calc_db_distance(save, lp, &left_edge, &left_db);
  int8_t rp_dist = calc_db_distance(save, rp, &right_edge, &right_db);
  if (lp_dist > -1) {
    lp_dist++;
  }
  if (rp_dist > -1) {
    rp_dist++;
    if (rp_dist < lp_dist) {
      if (rp_dist == 1) {
        edge->node_id = node->node_id;
        edge->direction = bg3_osiris_edge_direction_right;
      } else {
        *edge = right_edge;
      }
      *db_node = right_db;
      return rp_dist;
    }
  }
  if (lp_dist == 1) {
    edge->node_id = node->node_id;
    edge->direction = node->type == bg3_osiris_rete_node_join_and ||
                              node->type == bg3_osiris_rete_node_join_and_not
                          ? bg3_osiris_edge_direction_left
                          : bg3_osiris_edge_direction_none;
  } else {
    *edge = left_edge;
  }
  *db_node = left_db;
  return lp_dist;
}

static void calc_db_edges(bg3_osiris_save_builder* builder,
                          bg3_osiris_rete_node* node,
                          uint32_t* left_db,
                          bg3_osiris_rete_node_edge* left_edge,
                          int8_t* left_distance,
                          uint32_t* right_db,
                          bg3_osiris_rete_node_edge* right_edge,
                          int8_t* right_distance) {
  bg3_osiris_save* save = &builder->save;
  uint32_t dummy_db;
  bg3_osiris_rete_node_edge dummy_edge;
  int8_t dummy_distance;
  if (!right_db) {
    right_db = &dummy_db;
  }
  if (!right_edge) {
    right_edge = &dummy_edge;
  }
  if (!right_distance) {
    right_distance = &dummy_distance;
  }
  *left_db = *right_db = 0;
  if (node->db) {
    *left_distance = *right_distance = 0;
    *left_edge = *right_edge = (bg3_osiris_rete_node_edge){};
    return;
  }
  bool is_binary = node->type == bg3_osiris_rete_node_join_and ||
                   node->type == bg3_osiris_rete_node_join_and_not;
  *left_edge =
      (bg3_osiris_rete_node_edge){.node_id = node->node_id,
                                  .direction = is_binary ? bg3_osiris_edge_direction_left
                                                         : bg3_osiris_edge_direction_none,
                                  .goal_id = builder->current_goal_id};
  *right_edge = (bg3_osiris_rete_node_edge){.node_id = node->node_id,
                                            .direction = bg3_osiris_edge_direction_right,
                                            .goal_id = builder->current_goal_id};
  *left_distance =
      calc_db_distance(save, get_left_parent_node(save, node), left_edge, left_db);
  *right_distance =
      calc_db_distance(save, get_right_parent_node(save, node), right_edge, right_db);
  if (*left_distance > -1) {
    (*left_distance)++;
  } else {
    *left_distance = 0;
  }
  if (*right_distance > -1) {
    (*right_distance)++;
  }
}

static bg3_status create_terminal_node(bg3_osiris_save_builder* builder,
                                       bg3_sexp_lexer* l,
                                       condition* last) {
  assert(last->node_id);
  condition terminal_cond = {
      .type = condition_terminal,
      .line = (uint32_t)l->next.line,
      .node_id = builder->save.num_rete_nodes + 1,
      .root_is_query = last->root_is_query,
  };
  bg3_osiris_rete_node node = {
      .type = bg3_osiris_rete_node_terminal,
      .node_id = terminal_cond.node_id,
      .terminal.parent.node_id = last->node_id,
      .terminal.parent.adaptor = create_adaptor(builder, last, &terminal_cond),
      .terminal.line = (uint32_t)l->next.line,
      .terminal.is_query = last->root_is_query,
  };
  link_parent(builder, last, &node, bg3_osiris_edge_direction_none);
  node.terminal.num_vars = builder->next_var;
  size_t sz = sizeof(bg3_osiris_binding) * builder->next_var;
  node.terminal.vars = (bg3_osiris_binding*)bg3_arena_alloc(&builder->save.alloc, sz);
  memcpy(node.terminal.vars, builder->current_vars, sz);
  memcpy(terminal_cond.bindings, builder->current_vars, sz);
  bg3_osiris_rete_node* parent = builder->save.rete_nodes + (last->node_id - 1);
  if (parent->db && terminal_cond.num_bindings) {
    create_temp_db(builder, &terminal_cond, &node);
  }
  calc_db_edges(builder, &node, &node.terminal.parent.db_node,
                &node.terminal.parent.db_edge, &node.terminal.parent.db_distance, 0, 0,
                0);
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, rete_nodes, node);
  *last = terminal_cond;
  return bg3_success;
}

static bg3_status create_compare_node(bg3_osiris_save_builder* builder,
                                      bg3_sexp_lexer* l,
                                      condition* prev,
                                      condition* comp) {
  // This is a bit weird. We're turning a condition node into a condition node
  // that conforms to the shape of the left parent and more or less ignoring
  // the bindings in the original except for the purposes of assigning the node
  // properties.
  condition compare_cond = {
      .type = condition_compare,
      .line = comp->line,
      .compare_op = comp->compare_op,
      .node_id = builder->save.num_rete_nodes + 1,
      .root_is_query = prev->root_is_query,
  };
  assert(comp->num_bindings == 2);
  bg3_osiris_rete_node node = {
      .type = bg3_osiris_rete_node_compare,
      .node_id = compare_cond.node_id,
      .compare.parent.node_id = prev->node_id,
      .compare.parent.adaptor = create_adaptor(builder, prev, &compare_cond),
      .compare.opcode = comp->compare_op,
      .compare.left_var =
          (uint8_t)(comp->bindings[0].is_variable ? comp->bindings[0].index : 255),
      .compare.right_var =
          (uint8_t)(comp->bindings[1].is_variable ? comp->bindings[1].index : 255),
      .compare.left_value = comp->bindings[0].is_variable ? (bg3_osiris_variant){}
                                                          : comp->bindings[0].value,
      .compare.right_value = comp->bindings[1].is_variable ? (bg3_osiris_variant){}
                                                           : comp->bindings[1].value,
  };
  link_parent(builder, prev, &node, bg3_osiris_edge_direction_none);
  bg3_osiris_rete_node* parent = builder->save.rete_nodes + (prev->node_id - 1);
  if (parent->db && compare_cond.num_bindings) {
    create_temp_db(builder, &compare_cond, &node);
  }
  calc_db_edges(builder, &node, &node.compare.parent.db_node,
                &node.compare.parent.db_edge, &node.compare.parent.db_distance, 0, 0, 0);
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, rete_nodes, node);
  *prev = compare_cond;
  return bg3_success;
}

static bg3_status create_join_node(bg3_osiris_save_builder* builder,
                                   bg3_sexp_lexer* l,
                                   condition* left,
                                   condition* right) {
  bg3_status status = bg3_success;
  assert(right->type == condition_trigger);
  if ((status = ensure_entry_node(builder, right, false))) {
    return status;
  }
  assert(left->node_id && right->node_id);
  condition join_cond = {
      .type = condition_join,
      .line = right->line,
      .node_id = builder->save.num_rete_nodes + 1,
      .negated = right->negated,
      .root_is_query = left->root_is_query,
  };
  bg3_osiris_rete_node node = {
      .type = right->negated ? bg3_osiris_rete_node_join_and_not
                             : bg3_osiris_rete_node_join_and,
      .node_id = join_cond.node_id,
      .join.left_parent.node_id = left->node_id,
      .join.left_parent.adaptor = create_adaptor(builder, left, &join_cond),
      .join.right_parent.node_id = right->node_id,
      .join.right_parent.adaptor = create_adaptor(builder, right, &join_cond),
  };
  link_parent(builder, left, &node, bg3_osiris_edge_direction_left);
  link_parent(builder, right, &node, bg3_osiris_edge_direction_right);
  bg3_osiris_rete_node* left_parent = builder->save.rete_nodes + (left->node_id - 1);
  bg3_osiris_rete_node* right_parent = builder->save.rete_nodes + (right->node_id - 1);
  if (left_parent->db && right_parent->db && join_cond.num_bindings) {
    create_temp_db(builder, &join_cond, &node);
  }
  calc_db_edges(builder, &node, &node.join.left_parent.db_node,
                &node.join.left_parent.db_edge, &node.join.left_parent.db_distance,
                &node.join.right_parent.db_node, &node.join.right_parent.db_edge,
                &node.join.right_parent.db_distance);
  LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, rete_nodes, node);
  *left = join_cond;
  return bg3_success;
}

static bg3_status consume_outputs(bg3_osiris_save_builder* builder,
                                  bg3_sexp_lexer* l,
                                  condition* prev,
                                  condition* next) {
  bg3_status status = bg3_success;
  if (prev->type == condition_empty) {
    if (!next) {
      fprintf(stderr, "rule has no conditions at line %d\n", l->next.line);
      return bg3_error_failed;
    }
    if (next->type != condition_trigger || !is_valid_trigger(next->predicate)) {
      fprintf(stderr,
              "first condition of a rule must be an event, db, proc or query "
              "at line %d\n",
              next->line);
      return bg3_error_failed;
    }
    if ((status = ensure_entry_node(builder, next, prev->type == condition_empty))) {
      return status;
    }
    *prev = *next;
  } else if (!next) {
    return create_terminal_node(builder, l, prev);
  } else if (next->type == condition_compare) {
    return create_compare_node(builder, l, prev, next);
  } else if (next->type == condition_trigger) {
    return create_join_node(builder, l, prev, next);
  } else {
    bg3_panic("unhandled condition type");
  }
  return status;
}

static bg3_status parse_rule(bg3_osiris_save_builder* builder, bg3_sexp_lexer* l) {
  action_list body = {};
  bg3_status status = bg3_success;
  bg3_hash_clear(&builder->local_symbols);
  memset(builder->current_vars, 0, sizeof(builder->current_vars));
  builder->next_var = 0;
  SLURP(lparen);
  condition prev = {};
  while (!status && l->next.type != bg3_sexp_token_type_rparen) {
    condition next = {};
    if ((status = parse_condition(builder, l, &next))) {
      return status;
    }
    if ((status = consume_outputs(builder, l, &prev, &next))) {
      return status;
    }
  }
  if ((status = consume_outputs(builder, l, &prev, 0))) {
    return status;
  }
  assert(prev.type == condition_terminal);
  SLURP(rparen);
  if ((status = parse_action_list(builder, l, &body))) {
    return status;
  }
  bg3_osiris_rete_node* terminal_node = builder->save.rete_nodes + (prev.node_id - 1);
  terminal_node->terminal.num_actions = body.num_actions;
  terminal_node->terminal.actions = body.actions;
  return bg3_success;
}

static bg3_status parse_goal(bg3_osiris_save_builder* builder, bg3_sexp_lexer* l) {
  bg3_osiris_goal goal = {};
  action_list init_actions = {};
  action_list exit_actions = {};
  bg3_status status = bg3_success;
  SLURP(symbol);
  SLURP(lparen);
  MATCH(symbol);
  bg3_sexp_token_copy(&builder->current_toplevel, &l->next);
  goal.name = bg3_arena_strdup(&builder->save.alloc, l->next.text.data);
  goal.goal_id = builder->current_goal_id = builder->save.num_goals + 1;
  goal.line = l->next.line;
  SLURP(symbol);
  MATCH(symbol);
  if (!strcmp(l->next.text.data, "active")) {
    goal.state = bg3_osiris_goal_state_active;
  } else if (!strcmp(l->next.text.data, "sleeping")) {
    goal.state = bg3_osiris_goal_state_sleeping;
  } else if (!strcmp(l->next.text.data, "exited")) {
    goal.state = (bg3_osiris_goal_state)(bg3_osiris_goal_state_sleeping |
                                         bg3_osiris_goal_state_finalised |
                                         bg3_osiris_goal_state_completed);
  } else {
    fprintf(stderr, "invalid goal state '%s' at line %d\n", l->next.text.data,
            l->next.line);
    return bg3_error_failed;
  }
  SLURP(symbol);
  MATCH(symbol);
  if (!strcmp(l->next.text.data, "or")) {
    goal.combiner = bg3_osiris_goal_combiner_or;
  } else if (!strcmp(l->next.text.data, "and")) {
    goal.combiner = bg3_osiris_goal_combiner_and;
  } else {
    fprintf(stderr, "invalid subgoal combination '%s' at line %d\n", l->next.text.data,
            l->next.line);
    return bg3_error_failed;
  }
  SLURP(symbol);
  SLURP(rparen);
  while (!status && l->next.type != bg3_sexp_token_type_rparen) {
    SLURP(lparen);
    MATCH(symbol);
    if (!strcmp(l->next.text.data, "init")) {
      SLURP(symbol);
      status = parse_action_list(builder, l, &init_actions);
    } else if (!strcmp(l->next.text.data, "exit")) {
      SLURP(symbol);
      status = parse_action_list(builder, l, &exit_actions);
    } else if (!strcmp(l->next.text.data, "rule")) {
      SLURP(symbol);
      status = parse_rule(builder, l);
    } else if (!strcmp(l->next.text.data, "parent")) {
      if (goal.unresolved_parent) {
        fprintf(stderr, "goal has multiple parent specifications at line %d\n",
                l->next.line);
        return bg3_error_failed;
      }
      SLURP(symbol);
      MATCH(symbol);
      goal.unresolved_parent = bg3_arena_strdup(&builder->save.alloc, l->next.text.data);
      SLURP(symbol);
      SLURP(rparen);
    } else {
      fprintf(stderr, "unexpected goal form %s at line %d\n", l->next.text.data,
              l->next.line);
      status = bg3_error_failed;
    }
  }
  if (!status) {
    SLURP(rparen);
  }
  goal.num_init_actions = init_actions.num_actions;
  goal.init_actions = init_actions.actions;
  goal.num_exit_actions = exit_actions.num_actions;
  goal.exit_actions = exit_actions.actions;
  if (enter_goal(builder, goal.name, &goal)) {
    fprintf(stderr, "redefinition of goal '%s' at line %d\n", goal.name, goal.line);
    return bg3_error_failed;
  }
  return status;
}

static bg3_status parse_toplevel(bg3_osiris_save_builder* builder, bg3_sexp_lexer* l) {
  SLURP(lparen);
  MATCH(symbol);
  bg3_status status = bg3_success;
  if (!strcmp(l->next.text.data, "defgoal")) {
    status = parse_goal(builder, l);
  } else if (!strcmp(l->next.text.data, "defdb")) {
    status = parse_defun(builder, l, bg3_osiris_function_db);
  } else if (!strcmp(l->next.text.data, "defproc")) {
    status = parse_defun(builder, l, bg3_osiris_function_proc);
  } else if (!strcmp(l->next.text.data, "defquery")) {
    status = parse_defun(builder, l, bg3_osiris_function_query);
  } else if (!strcmp(l->next.text.data, "defevent")) {
    status = parse_defun(builder, l, bg3_osiris_function_event);
  } else if (!strcmp(l->next.text.data, "defdivcall")) {
    status = parse_defun(builder, l, bg3_osiris_function_div_call);
  } else if (!strcmp(l->next.text.data, "defdivquery")) {
    status = parse_defun(builder, l, bg3_osiris_function_div_query);
  } else if (!strcmp(l->next.text.data, "defsyscall")) {
    status = parse_defun(builder, l, bg3_osiris_function_sys_call);
  } else if (!strcmp(l->next.text.data, "defsysquery")) {
    status = parse_defun(builder, l, bg3_osiris_function_sys_query);
  } else if (!strcmp(l->next.text.data, "deftype")) {
    bg3_osiris_type_info type_info = {};
    bg3_osiris_type_info* alias_type;
    SLURP(symbol);
    MATCH(symbol);
    type_info.name = bg3_arena_strdup(&builder->save.alloc, l->next.text.data);
    int line = l->next.line;
    SLURP(symbol);
    MATCH(symbol);
    if (!(alias_type = lookup_type_info(builder, l->next.text.data))) {
      fprintf(stderr, "unknown type '%s' at line %d\n", l->next.text.data, l->next.line);
      return bg3_error_failed;
    }
    type_info.index = builder->save.num_type_infos + 1;
    type_info.alias_index = alias_type->index;
    if (enter_type_info(builder, type_info.name, &type_info)) {
      fprintf(stderr, "type '%s' redeclared at line %d\n",
              builder->current_item.text.data, line);
      return bg3_error_failed;
    }
    SLURP(symbol);
    SLURP(rparen);
  } else if (!strcmp(l->next.text.data, "defenum")) {
    bg3_osiris_type_info* type_info;
    bg3_osiris_enum_info enum_info = {};
    SLURP(symbol);
    MATCH(symbol);
    if (!(type_info = lookup_type_info(builder, l->next.text.data))) {
      fprintf(stderr, "undefined type '%s' at line %d\n", l->next.text.data,
              l->next.line);
      return bg3_error_failed;
    }
    if (type_info->enum_index) {
      fprintf(stderr, "duplicate enum definition for '%s' at line %d\n",
              l->next.text.data, l->next.line);
      return bg3_error_failed;
    }
    enum_info.index = type_info->index;
    type_info->enum_index = builder->save.num_enums + 1;
    SLURP(symbol);
    while (l->next.type != bg3_sexp_token_type_rparen) {
      bg3_osiris_enum_entry entry = {};
      SLURP(lparen);
      MATCH(symbol);
      entry.name = bg3_arena_strdup(&builder->save.alloc, l->next.text.data);
      SLURP(symbol);
      MATCH(integer);
      entry.value = l->next.int_val;
      SLURP(integer);
      SLURP(rparen);
      LIBBG3_ARRAY_PUSH(&builder->save.alloc, &enum_info, entries, entry);
    }
    LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, enums, enum_info);
    SLURP(rparen);
  } else if (!strcmp(l->next.text.data, "defstory")) {
    SLURP(symbol);
    MATCH(string);
    builder->save.version = bg3_arena_strdup(&builder->save.alloc, l->next.text.data);
    SLURP(string);
    MATCH(string);
    snprintf(builder->save.story_version, sizeof(builder->save.story_version), "%s",
             l->next.text.data);
    SLURP(string);
    MATCH(integer);
    builder->save.version_major = l->next.int_val;
    SLURP(integer);
    MATCH(integer);
    builder->save.version_minor = l->next.int_val;
    SLURP(integer);
    MATCH(integer);
    builder->save.debug_flags = l->next.int_val;
    SLURP(integer);
    SLURP(rparen);
  } else {
    fprintf(stderr, "unexpected toplevel form %s near line %d\n", l->next.text.data,
            l->line);
    return bg3_error_failed;
  }
  return status;
}

bg3_status bg3_osiris_save_builder_parse(bg3_osiris_save_builder* builder,
                                         char* data,
                                         size_t data_len) {
  bg3_status status = bg3_success;
  bg3_sexp_lexer l;
  bg3_sexp_lexer_init(&l, data, data_len);
  bg3_sexp_lexer_advance(&l);
  while (l.next.type != bg3_sexp_token_type_eof) {
    status = parse_toplevel(builder, &l);
    if (status) {
      break;
    }
  }
  bg3_sexp_lexer_destroy(&l);
  return status;
}

bg3_status bg3_osiris_save_builder_finish(bg3_osiris_save_builder* builder) {
  // create dbs and nodes for any unreferenced db predicates
  for (uint32_t i = 0; i < builder->save.num_functions; ++i) {
    bg3_osiris_function_info* fi = builder->save.functions + i;
    if (fi->type == bg3_osiris_function_db && !fi->rete_node) {
      bg3_osiris_rete_node node = {
          .type = bg3_osiris_rete_node_db,
          .name = fi->name,
          .node_id = builder->save.num_rete_nodes + 1,
          .arity = fi->num_params,
      };
      bg3_osiris_rete_db db = {};
      node.db = builder->save.num_dbs + 1;
      db.db_id = node.db;
      db.num_schema_columns = fi->num_params;
      size_t sz = db.num_schema_columns * sizeof(uint16_t);
      db.schema_columns = (uint16_t*)bg3_arena_alloc(&builder->save.alloc, sz);
      memcpy(db.schema_columns, fi->params, sz);
      LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, dbs, db);
      LIBBG3_ARRAY_PUSH(&builder->save.alloc, &builder->save, rete_nodes, node);
      fi->rete_node = node.node_id;
    }
  }
  // resolve parent goal references
  for (uint32_t i = 0; i < builder->save.num_goals; ++i) {
    bg3_osiris_goal* g = builder->save.goals + i;
    if (g->unresolved_parent) {
      bg3_osiris_goal* parent = lookup_goal(builder, g->unresolved_parent);
      if (!parent) {
        fprintf(stderr, "undefined parent goal '%s' for goal '%s' declared on line %d\n",
                g->unresolved_parent, g->name, g->line);
        return bg3_error_failed;
      }
      g->parent = parent->goal_id;
      LIBBG3_ARRAY_PUSH(&builder->save.alloc, parent, children, g->goal_id);
      g->unresolved_parent = 0;
    }
  }
  return bg3_success;
}
#endif  // LIBBG3_IMPLEMENTATION
#endif  // LIBBG3_H
