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

// TODO: this is a totally shitty first pass version. don't care.
// stuff it ought to do:
//  - compression
//  - split archives
//  - parallelization
//  - directory scan instead of manifest txt
//  - be an api
int main(int argc, char const** argv) {
  if (argc < 3) {
    fprintf(stderr, "syntax: %s <list-file> <pak-file>\n", argv[0]);
    return -1;
  }
  FILE* listfp = fopen(argv[1], "r");
  if (!listfp) {
    perror("fopen");
    return -1;
  }
  FILE* pakfp = fopen(argv[2], "wb");
  if (!pakfp) {
    perror("fopen");
    fclose(listfp);
    return -1;
  }
  bg3_buffer manifest_buf;
  bg3_buffer_init(&manifest_buf);
  bg3_lspk_header file_header;
  bg3_lspk_manifest_header manifest_header;
  manifest_header.num_files = 0;
  manifest_header.compressed_size = 0;
  memset(&file_header, 0, sizeof(bg3_lspk_header));
  file_header.magic = LIBBG3_LSPK_MAGIC;
  file_header.version = LIBBG3_LSPK_VERSION;
  file_header.num_parts = 1;
  file_header.priority = 127;
  fwrite(&file_header, sizeof(bg3_lspk_header), 1, pakfp);
  char line[1024];
  uint64_t file_offset = sizeof(bg3_lspk_header);
  while (fgets(line, 1024, listfp)) {
    size_t line_len = strlen(line);
    if (line_len > 0) {
      line[line_len - 1] = '\0';
    }
    bg3_lspk_manifest_entry entry;
    snprintf(entry.name, sizeof(entry.name), "%s", line);
    bg3_mapped_file input_file;
    if (bg3_mapped_file_init_ro(&input_file, entry.name) < 0) {
      fprintf(stderr, "failed to open %s\n", entry.name);
      continue;
    }
    entry.offset_lo = file_offset & 0xFFFFFFFF;
    entry.offset_hi = file_offset >> 32;
    entry.part_num = 0;
    entry.compression = 0;
    entry.compressed_size = input_file.data_len;
    entry.uncompressed_size = 0;
    bg3_buffer_push(&manifest_buf, &entry, sizeof(entry));
    fwrite(input_file.data, input_file.data_len, 1, pakfp);
    manifest_header.num_files++;
    bg3_mapped_file_destroy(&input_file);
    file_offset += input_file.data_len;
  }
  size_t compress_buf_size = LZ4_compressBound(manifest_buf.size);
  char* compress_buf = (char*)malloc(compress_buf_size);
  manifest_header.compressed_size = LZ4_compress_default(
      manifest_buf.data, compress_buf, manifest_buf.size, compress_buf_size);
  file_header.manifest_offset = file_offset;
  file_header.manifest_size = manifest_header.compressed_size + sizeof(manifest_header);
  fwrite(&manifest_header, sizeof(manifest_header), 1, pakfp);
  fwrite(compress_buf, manifest_header.compressed_size, 1, pakfp);
  bg3_buffer_destroy(&manifest_buf);
  fseek(pakfp, 0, SEEK_SET);
  fwrite(&file_header, sizeof(file_header), 1, pakfp);
  fclose(pakfp);
  fclose(listfp);
  return bg3_success;
}
