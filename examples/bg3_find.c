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

int main(int argc, char const** argv) {
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
  bg3_index_search_results results;
  bg3_index_reader_query(&reader, &results, argv[2]);
  for (size_t i = 0; i < results.num_hits; ++i) {
    bg3_index_search_hit* hit = results.hits + i;
    printf("%08X %s\n", hit->value, hit->file->name);
  }
  printf("%zd matches\n", results.num_hits);
  bg3_index_search_results_destroy(&results);
  bg3_index_reader_destroy(&reader);
  bg3_mapped_file_destroy(&mapped);
  return bg3_success;
}
