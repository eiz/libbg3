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

bg3_status do_osiris_decompile(int argc, char const** argv) {
  if (argc < 3) {
    fprintf(stderr, "syntax: %s <story.div.osi path> <.lss path>\n", argv[0]);
    return bg3_error_failed;
  }
  bg3_status status = bg3_success;
  bg3_mapped_file file;
  if ((status = bg3_mapped_file_init_ro(&file, argv[1]))) {
    perror("open");
    return status;
  }
  bg3_osiris_save save;
  bg3_osiris_save_init_binary(&save, file.data, file.data_len);
  if ((status = bg3_osiris_save_write_sexp(&save, argv[2], false))) {
    fprintf(stderr, "error writing decompile output\n");
    return status;
  }
  return status;
}

bg3_status do_osiris_compile(int argc, char const** argv) {
  if (argc < 3) {
    fprintf(stderr, "syntax: %s <.lss path> <story.div.osi path>\n", argv[0]);
    return bg3_error_failed;
  }
  bg3_status status = bg3_success;
  bg3_mapped_file file;
  if ((status = bg3_mapped_file_init_ro(&file, argv[1]))) {
    perror("mapped_file_init_ro");
    return status;
  }
  bg3_osiris_save_builder builder;
  bg3_osiris_save_builder_init(&builder);
  status = bg3_osiris_save_builder_parse(&builder, file.data, file.data_len);
  if (status) {
    fprintf(stderr, "parse failed for %s\n", argv[1]);
    return status;
  }
  status = bg3_osiris_save_builder_finish(&builder);
  if (status) {
    fprintf(stderr, "error building osiris save\n");
    return status;
  }
  status = bg3_osiris_save_write_binary(&builder.save, argv[2]);
  if (status) {
    fprintf(stderr, "error writing osiris save\n");
    return status;
  }
  bg3_osiris_save_builder_destroy(&builder);
  return status;
}

int main(int argc, char const** argv) {
  if (argc < 2) {
    fprintf(stderr, "syntax: %s <command> [args...]\n", argv[0]);
    fprintf(stderr, "commands: compile, decompile\n");
    return 1;
  }
  bg3_status status = bg3_success;
  if (!strcmp(argv[1], "decompile")) {
    status = do_osiris_decompile(argc - 1, argv + 1);
  } else if (!strcmp(argv[1], "compile")) {
    status = do_osiris_compile(argc - 1, argv + 1);
  } else {
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
  }
  return status != bg3_success;
}