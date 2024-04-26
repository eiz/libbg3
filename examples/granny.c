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
  bg3_granny_obj_root* root = bg3_granny_reader_get_root(&reader);
  printf("File schema:\n");
  print_granny_type(root_type, 0);
  printf("From file: %s\n", root->from_file_name);
  printf("Extended data: %p\n", root->extended_data.obj);
  if (root->art_tool_info) {
    printf("Art tool: %s\n", root->art_tool_info->from_art_tool_name);
  }
  printf("Textures: %d\n", root->num_textures);
  printf("Materials: %d\n", root->num_materials);
  printf("Skeletons: %d\n", root->num_skeletons);
  printf("Vertex datas: %d\n", root->num_vertex_datas);
  printf("Tri topologies: %d\n", root->num_tri_topologies);
  printf("Meshes: %d\n", root->num_meshes);
  printf("Models: %d\n", root->num_models);
  printf("Track groups: %d\n", root->num_track_groups);
  printf("Animations: %d\n", root->num_animations);
  for (int i = 0; i < root->num_meshes; ++i) {
    char nbuf[1024];
    snprintf(nbuf, 1024, "tmp/%s.obj", root->meshes[i]->name);
    FILE* fp = fopen(nbuf, "wb");
    if (!fp) {
      perror("fopen");
      continue;
    }
    printf("mesh %s\n", root->meshes[i]->name);
    printf("  ext %p\n", root->meshes[i]->extended_data.obj);
    if (root->meshes[i]->extended_data.obj) {
      bg3_granny_obj_ls_mesh* ls_mesh =
          (bg3_granny_obj_ls_mesh*)root->meshes[i]->extended_data.obj;
      bg3_granny_obj_ls_user_mesh_properties* props = ls_mesh->user_mesh_properties;
      printf("    version %d\n", ls_mesh->lsm_version);
      printf("    lod %d\n", props->lod);
      printf("    num_format_descs %d\n", props->num_format_descs);
      printf("    lod_distance %f\n", props->lod_distance);
      printf("    is_impostor %d\n", props->is_impostor);
      printf("    ext %p\n", props->extended_data.obj);
      print_granny_type(root->meshes[i]->extended_data.type, 2);
    }
    bg3_granny_obj_vertex_data* vdata = root->meshes[i]->primary_vertex_data;
    bg3_granny_obj_tri_topology* topo = root->meshes[i]->primary_topology;
    printf("  vertices %p %d\n", vdata->vertices.items, vdata->vertices.num_items);
    printf("  indices %p %d indices16 %p %d\n", topo->indices, topo->num_indices,
           topo->indices16, topo->num_indices16);
    bg3_granny_obj_ls_vertex* vertices = (bg3_granny_obj_ls_vertex*)vdata->vertices.items;
    for (int32_t j = 0; j < vdata->vertices.num_items; ++j) {
      bg3_granny_obj_ls_vertex v = vertices[j];
      fprintf(fp, "v %f %f %f\n", v.position[0], v.position[1], v.position[2]);
    }
    for (int32_t j = 0; j < topo->num_indices16; j += 3) {
      fprintf(fp, "f %d %d %d\n", topo->indices16[j] + 1, topo->indices16[j + 1] + 1,
              topo->indices16[j + 2] + 1);
    }
    for (int32_t j = 0; j < topo->num_indices; j += 3) {
      fprintf(fp, "f %d %d %d\n", topo->indices[j] + 1, topo->indices[j + 1] + 1,
              topo->indices[j + 2] + 1);
    }
    fclose(fp);
#if 0
        for (int32_t j = 0; j < vdata->vertices.num_items; ++j) {
            granny_obj_ls_vertex v = vertices[j];
            vec4 qt = {v.qtangent[0] / 32767.0, v.qtangent[1] / 32767.0,
                       v.qtangent[2] / 32767.0, v.qtangent[3] / 32767.0};
            mat4x4 rot;
            mat4x4_from_quat(rot, qt);
            vec3 norm = {rot[0][0], rot[0][1], rot[0][2]};
            printf("pos (%f,%f,%f) norm (%f,%f,%f) mag %f uv (%f,%f)\n",
                   v.position[0], v.position[1], v.position[2], rot[0][0],
                   rot[0][1], rot[0][2], vec3_len(norm),
                   (double)v.texture_coordinates0[0],
                   (double)v.texture_coordinates0[1]);
        }
#endif
    print_granny_type(vdata->vertices.type, 4);
  }
  bg3_granny_reader_destroy(&reader);
  return bg3_error_failed;
}
