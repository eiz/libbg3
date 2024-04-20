#define LIBBG3_IMPLEMENTATION
#include "../libbg3.h"

typedef struct index_search_thread {
  bg3_arena tmp;
  bg3_index_reader* reader;
  char const* needle;
  size_t num_entries;
  size_t cap_entries;
  bg3_index_entry** entries;
} index_search_thread;

int do_find_worker(bg3_parallel_for_thread* tcb) {
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

bg3_status do_find(int argc, char const** argv) {
  if (argc < 3) {
    fprintf(stderr, "syntax: %s <index file> <search string>\n", argv[0]);
    return bg3_error_failed;
  }
  bg3_mapped_file mapped;
  if (bg3_mapped_file_init_ro(&mapped, argv[1])) {
    perror("mapped_file_init_ro");
    return bg3_error_libc;
  }
  bg3_index_reader reader;
  if (bg3_index_reader_init(&reader, mapped.data, mapped.data_len)) {
    fprintf(stderr, "woopsie\n");
    return bg3_error_failed;
  }
  int nthreads = bg3_parallel_for_ncpu();
  index_search_thread* threads =
      (index_search_thread*)alloca(nthreads * sizeof(index_search_thread));
  memset(threads, 0, sizeof(index_search_thread) * nthreads);
  char* term = strdup(argv[2]);
  for (char* p = term; *p; ++p) {
    *p = tolower(*p);
  }
  for (int i = 0; i < nthreads; ++i) {
    bg3_arena_init(&threads[i].tmp, 1024 * 1024, 1024);
    threads[i].needle = term;
    threads[i].reader = &reader;
  }
  bg3_parallel_for(do_find_worker, threads);
  size_t num_entries = 0;
  for (int i = 0; i < nthreads; ++i) {
    for (size_t j = 0; j < threads[i].num_entries; ++j) {
      bg3_index_entry* entry = threads[i].entries[j];
      for (uint32_t k = 0; k < entry->match_len; ++k) {
        bg3_index_match_entry* match = reader.matches + k + entry->match_index;
        printf("%s\n", reader.files[match->file_idx].name);
      }
    }
    num_entries += threads[i].num_entries;
  }
  printf("%zd matches\n", num_entries);
  for (int i = 0; i < nthreads; ++i) {
    bg3_arena_destroy(&threads[i].tmp);
  }
  free(term);
  bg3_index_reader_destroy(&reader);
  bg3_mapped_file_destroy(&mapped);
  return bg3_success;
}
