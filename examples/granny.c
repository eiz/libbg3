#define LIBBG3_IMPLEMENTATION
#include "../libbg3.h"

// TODO: scan for these.
static const size_t offset_granny_decompress_data = 0x516a30;
static const size_t offset_granny_begin_file_decompression = 0x516a38;
static const size_t offset_granny_decompress_incremental = 0x516a3c;
static const size_t offset_granny_end_file_decompression = 0x516a40;

#define LIBBG3_GRANNY_OP(name) \
  .name = (bg3_fn_granny_##name*)((char*)info.dli_fbase + offset_granny_##name)

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

bg3_status do_granny(int argc, char const** argv) {
  void* handle = dlopen("/Users/eiz/l/bg3/MacOS/Baldur's Gate 3", RTLD_LAZY | RTLD_LOCAL);
  if (!handle) {
    printf("couldn't find bg3\n");
    return bg3_error_failed;
  }
  void* ptr = dlsym(handle, "_ZN2ls9SingletonINS_11FileManagerEE5m_ptrE");
  Dl_info info;
  if (!ptr || !dladdr(ptr, &info)) {
    printf("couldn't find an export (use _dyld_* fns instead lol)\n");
    return bg3_error_failed;
  }
  bg3_granny_compressor_ops compress_ops = {
      LIBBG3_GRANNY_OP(decompress_data),
      LIBBG3_GRANNY_OP(begin_file_decompression),
      LIBBG3_GRANNY_OP(decompress_incremental),
      LIBBG3_GRANNY_OP(end_file_decompression),
  };
  if (argc < 2) {
    fprintf(stderr, "syntax: %s <.gr2 path>\n", argv[0]);
    return bg3_error_failed;
  }
  bg3_mapped_file mapped;
  bg3_granny_reader reader;
  if (bg3_mapped_file_init_ro(&mapped, argv[1])) {
    fprintf(stderr, "failed to open file\n");
    return bg3_error_failed;
  }
  if (bg3_granny_reader_init(&reader, mapped.data, mapped.data_len, &compress_ops)) {
    fprintf(stderr, "failed to load granny file\n");
    return bg3_error_failed;
  }
  printf("root type %08X:%08X\n", reader.header.root_type.section,
         reader.header.root_type.offset);
  printf("root obj %08X:%08X\n", reader.header.root_obj.section,
         reader.header.root_obj.offset);
  for (int i = 0; i < reader.header.num_sections; ++i) {
    printf("section %d\n", i);
    printf("  num_fixups %d num_mixed_marshals %d\n",
           reader.section_headers[i].num_fixups,
           reader.section_headers[i].num_mixed_marshals);
    printf("  fixups_offset %08X\n", reader.section_headers[i].fixups_offset);
  }
  bg3_cursor c;
  bg3_granny_section_ptr root_type = reader.header.root_type;
  bg3_granny_section* section = &reader.sections[root_type.section];
  bg3_cursor_init(&c, section->data, section->data_len);
  bg3_cursor_seek(&c, root_type.offset);
  print_granny_type((bg3_granny_type_info*)c.ptr, 0);
  bg3_granny_obj_root* root =
      (bg3_granny_obj_root*)(reader.sections[reader.header.root_obj.section].data +
                             reader.header.root_obj.offset);
  printf("From file: %s\n", root->from_file_name);
  printf("Extended data: %p\n", root->extended_data.obj);
  if (root->art_tool_info) {
    printf("Art tool: %s\n", root->art_tool_info->from_art_tool_name);
  }
  printf(
      "num_textures %d num_materials %d num_skeletons %d num_vertex_datas "
      "%d\n",
      root->num_textures, root->num_materials, root->num_skeletons,
      root->num_vertex_datas);
  printf(
      "num_tri_topologies %d num_meshes %d num_models %d num_track_groups "
      "%d\n",
      root->num_tri_topologies, root->num_meshes, root->num_models,
      root->num_track_groups);
  printf("num_animations %d\n", root->num_animations);
  for (int i = 0; i < root->num_skeletons; ++i) {
    printf("skeleton %s with %d bones\n", root->skeletons[i]->name,
           root->skeletons[i]->num_bones);
    printf("  ext %p\n", root->skeletons[i]->extended_data.obj);
    for (int j = 0; j < root->skeletons[i]->num_bones; ++j) {
      bg3_granny_obj_bone* bone = &root->skeletons[i]->bones[j];
      printf("  bone %s\n", bone->name);
      printf("    ext %p\n", bone->extended_data.obj);
    }
  }
  for (int i = 0; i < root->num_meshes; ++i) {
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
    char nbuf[1024];
    snprintf(nbuf, 1024, "tmp/%s.obj", root->meshes[i]->name);
    FILE* fp = fopen(nbuf, "wb");
    if (!fp) {
      abort();
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
  return bg3_error_failed;
}
