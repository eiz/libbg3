// adapted from https://github.com/powzix/ooz
// the copyright status of this code is unclear but one of the files in
// the repo came with this license:
// === Kraken Decompressor for Windows ===
// Copyright (C) 2016, Powzix
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Several things have been changed from the original implementation to accomodate the
// Granny bitstream format.
//
// - Generally reorganized how dst pointer is used to match Granny bitstream and support
// chunked decoding. there was some weird code for handling the last 4 bytes which
// definitely are not how the Granny implementation does it.
// - The initialization bits at the beginning of a quantum are loaded in some weird
// middle-endian format in Granny.
// - Some minimal bounds checking for debugging purposes (still not safe to use with
// untrusted input)
// - Replaced copy functions with a simpler and slower version that doesn't do out of
// bounds memory access.
//
// This code still has some UB problems even on clean input (mainly unaligned loads). I
// intend to replace it with a clean implementation under MIT license so that it can be
// included in the library and not just an example.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct BitknitLiteral {
  uint16_t lookup[512 + 4];
  uint16_t a[300 + 1];
  uint16_t freq[300];
  uint32_t adapt_interval;
} BitknitLiteral;

typedef struct BitknitDistanceLsb {
  uint16_t lookup[64 + 4];
  uint16_t a[40 + 1];
  uint16_t freq[40];
  uint32_t adapt_interval;
} BitknitDistanceLsb;

typedef struct BitknitDistanceBits {
  uint16_t lookup[64 + 4];
  uint16_t a[21 + 1];
  uint16_t freq[21];
  uint32_t adapt_interval;
} BitknitDistanceBits;

typedef struct BitknitState {
  uint32_t recent_dist[8];
  uint32_t last_match_dist;
  uint32_t recent_dist_mask;
  uint32_t bits, bits2;

  BitknitLiteral literals[4];
  BitknitDistanceLsb distance_lsb[4];
  BitknitDistanceBits distance_bits;
} BitknitState;

void BitknitLiteral_Init(BitknitLiteral* model) {
  size_t i;
  uint16_t *p, *p_end;

  for (i = 0; i < 264; i++)
    model->a[i] = (0x8000 - 300 + 264) * i / 264;
  for (; i <= 300; i++)
    model->a[i] = (0x8000 - 300) + i;

  model->adapt_interval = 1024;
  for (i = 0; i < 300; i++)
    model->freq[i] = 1;

  for (i = 0, p = model->lookup; i < 300; i++) {
    p_end = &model->lookup[(model->a[i + 1] - 1) >> 6];
    do {
      p[0] = p[1] = p[2] = p[3] = i;
      p += 4;
    } while (p <= p_end);
    p = p_end + 1;
  }
}

void BitknitDistanceLsb_Init(BitknitDistanceLsb* model) {
  size_t i;
  uint16_t *p, *p_end;

  for (i = 0; i <= 40; i++)
    model->a[i] = 0x8000 * i / 40;

  model->adapt_interval = 1024;
  for (i = 0; i < 40; i++)
    model->freq[i] = 1;

  for (i = 0, p = model->lookup; i < 40; i++) {
    p_end = &model->lookup[(model->a[i + 1] - 1) >> 9];
    do {
      p[0] = p[1] = p[2] = p[3] = i;
      p += 4;
    } while (p <= p_end);
    p = p_end + 1;
  }
}

void BitknitDistanceBits_Init(BitknitDistanceBits* model) {
  size_t i;
  uint16_t *p, *p_end;

  for (i = 0; i <= 21; i++)
    model->a[i] = 0x8000 * i / 21;

  model->adapt_interval = 1024;
  for (i = 0; i < 21; i++)
    model->freq[i] = 1;

  for (i = 0, p = model->lookup; i < 21; i++) {
    p_end = &model->lookup[(model->a[i + 1] - 1) >> 9];
    do {
      p[0] = p[1] = p[2] = p[3] = i;
      p += 4;
    } while (p <= p_end);
    p = p_end + 1;
  }
}

void BitknitState_Init(BitknitState* bk) {
  size_t i;

  bk->last_match_dist = 1;
  for (i = 0; i < 8; i++)
    bk->recent_dist[i] = 1;

  bk->recent_dist_mask = (7 << (7 * 3)) | (6 << (6 * 3)) | (5 << (5 * 3)) |
                         (4 << (4 * 3)) | (3 << (3 * 3)) | (2 << (2 * 3)) |
                         (1 << (1 * 3)) | (0 << (0 * 3));

  for (i = 0; i < 4; i++)
    BitknitLiteral_Init(&bk->literals[i]);

  for (i = 0; i < 4; i++)
    BitknitDistanceLsb_Init(&bk->distance_lsb[i]);

  BitknitDistanceBits_Init(&bk->distance_bits);
}

void BitknitLiteral_Adaptive(BitknitLiteral* model, uint32_t sym) {
  size_t i;
  uint32_t sum;
  uint16_t *p, *p_end;

  model->adapt_interval = 1024;
  model->freq[sym] += 725;

  sum = 0;
  for (i = 0; i < 300; i++) {
    sum += model->freq[i];
    model->freq[i] = 1;
    model->a[i + 1] = model->a[i + 1] + ((sum - model->a[i + 1]) >> 1);
  }

  for (i = 0, p = model->lookup; i < 300; i++) {
    p_end = &model->lookup[(model->a[i + 1] - 1) >> 6];
    do {
      p[0] = p[1] = p[2] = p[3] = i;
      p += 4;
    } while (p <= p_end);
    p = p_end + 1;
  }
}

uint32_t BitknitLiteral_Lookup(BitknitLiteral* model, uint32_t* bits) {
  uint32_t prev_bits = *bits;
  uint32_t masked = *bits & 0x7FFF;
  size_t sym = model->lookup[masked >> 6];
  sym += masked > model->a[sym + 1];
  while (masked >= model->a[sym + 1])
    sym += 1;
  *bits = masked + (*bits >> 15) * (model->a[sym + 1] - model->a[sym]) - model->a[sym];
  model->freq[sym] += 31;
  if (--model->adapt_interval == 0)
    BitknitLiteral_Adaptive(model, sym);
  return sym;
}

void BitknitDistanceLsb_Adaptive(BitknitDistanceLsb* model, uint32_t sym) {
  size_t i;
  uint32_t sum;
  uint16_t *p, *p_end;

  model->adapt_interval = 1024;
  model->freq[sym] += 985;

  sum = 0;
  for (i = 0; i < 40; i++) {
    sum += model->freq[i];
    model->freq[i] = 1;
    model->a[i + 1] = model->a[i + 1] + ((sum - model->a[i + 1]) >> 1);
  }

  for (i = 0, p = model->lookup; i < 40; i++) {
    p_end = &model->lookup[(model->a[i + 1] - 1) >> 9];
    do {
      p[0] = p[1] = p[2] = p[3] = i;
      p += 4;
    } while (p <= p_end);
    p = p_end + 1;
  }
}

uint32_t BitknitDistanceLsb_Lookup(BitknitDistanceLsb* model, uint32_t* bits) {
  uint32_t masked = *bits & 0x7FFF;
  size_t sym = model->lookup[masked >> 9];
  sym += masked > model->a[sym + 1];
  while (masked >= model->a[sym + 1])
    sym += 1;
  *bits = masked + (*bits >> 15) * (model->a[sym + 1] - model->a[sym]) - model->a[sym];
  model->freq[sym] += 31;
  if (--model->adapt_interval == 0)
    BitknitDistanceLsb_Adaptive(model, sym);
  return sym;
}

void BitknitDistanceBits_Adaptive(BitknitDistanceBits* model, uint32_t sym) {
  size_t i;
  uint32_t sum;
  uint16_t *p, *p_end;

  model->adapt_interval = 1024;
  model->freq[sym] += 1004;

  sum = 0;
  for (i = 0; i < 21; i++) {
    sum += model->freq[i];
    model->freq[i] = 1;
    model->a[i + 1] = model->a[i + 1] + ((sum - model->a[i + 1]) >> 1);
  }

  for (i = 0, p = model->lookup; i < 21; i++) {
    p_end = &model->lookup[(model->a[i + 1] - 1) >> 9];
    do {
      p[0] = p[1] = p[2] = p[3] = i;
      p += 4;
    } while (p <= p_end);
    p = p_end + 1;
  }
}

uint32_t BitknitDistanceBits_Lookup(BitknitDistanceBits* model, uint32_t* bits) {
  uint32_t masked = *bits & 0x7FFF;
  size_t sym = model->lookup[masked >> 9];
  sym += masked > model->a[sym + 1];
  while (masked >= model->a[sym + 1]) {
    sym += 1;
  }
  *bits = masked + (*bits >> 15) * (model->a[sym + 1] - model->a[sym]) - model->a[sym];
  model->freq[sym] += 31;
  if (--model->adapt_interval == 0) {
    BitknitDistanceBits_Adaptive(model, sym);
  }
  return sym;
}

#define RENORMALIZE()                                  \
  {                                                    \
    if (bits < 0x10000) {                              \
      bits = (bits << 16) | *(uint16_t*)src, src += 2; \
    }                                                  \
    bitst = bits;                                      \
    bits = bits2;                                      \
    bits2 = bitst;                                     \
  }

size_t Bitknit_Decode(const uint8_t* src,
                      const uint8_t* src_end,
                      uint8_t** dst_ptr,
                      uint8_t* dst_quantum_end,
                      uint8_t* dst_end,
                      uint8_t* dst_start,
                      BitknitState* bk) {
  const uint8_t* src_in = src;
  uint8_t* dst = *dst_ptr;
  BitknitLiteral* litmodel[4];
  BitknitDistanceLsb* distancelsb[4];
  size_t i;
  intptr_t last_match_negative;
  uint32_t bits, bits2, bitst;
  uint32_t v, a, n;
  uint32_t copy_length;
  uint32_t recent_dist_mask;
  uint32_t match_dist;
  for (i = 0; i < 4; i++) {
    litmodel[i] = &bk->literals[(i - (intptr_t)dst_start) & 3];
  }
  for (i = 0; i < 4; i++) {
    distancelsb[i] = &bk->distance_lsb[(i - (intptr_t)dst_start) & 3];
  }
  recent_dist_mask = bk->recent_dist_mask;
  last_match_negative = -(intptr_t)bk->last_match_dist;
  v = *(uint32_t*)src, src += 4;
  v = (v << 16) | (v >> 16);
  if (v < 0x10000) {
    return 0;
  }
  a = v >> 4;
  n = v & 0xF;
  if (a < 0x10000)
    a = (a << 16) | *(uint16_t*)src, src += 2;
  bits = a >> n;
  if (bits < 0x10000)
    bits = (bits << 16) | *(uint16_t*)src, src += 2;
  a = (a << 16) | *(uint16_t*)src, src += 2;
  bits2 = (1 << (n + 16)) | (a & ((1 << (n + 16)) - 1));
  if (dst == dst_start) {
    *dst++ = bits;
    bits >>= 8;
    RENORMALIZE();
  }
  while (dst < dst_quantum_end) {
    uint32_t sym = BitknitLiteral_Lookup(litmodel[(intptr_t)dst & 3], &bits);
    RENORMALIZE();
    if (sym < 256) {
      *dst = sym + dst[last_match_negative];
      dst++;
      if (dst >= dst_quantum_end) {
        break;
      }
      sym = BitknitLiteral_Lookup(litmodel[(intptr_t)dst & 3], &bits);
      RENORMALIZE();
      if (sym < 256) {
        *dst = sym + dst[last_match_negative];
        dst++;
        continue;
      }
    }
    if (sym >= 288) {
      uint32_t nb = sym - 287;
      sym = (bits & ((1 << nb) - 1)) + (1 << nb) + 286;
      bits >>= nb;
      RENORMALIZE();
    }
    copy_length = sym - 254;
    sym = BitknitDistanceLsb_Lookup(distancelsb[(intptr_t)dst & 3], &bits);
    RENORMALIZE();
    static int traceboi = 0;
    if (sym >= 8) {
      uint32_t nb = BitknitDistanceBits_Lookup(&bk->distance_bits, &bits);
      RENORMALIZE();
      match_dist = bits & ((1 << (nb & 0xF)) - 1);
      bits >>= (nb & 0xF);
      RENORMALIZE();
      if (nb >= 0x10) {
        match_dist = (match_dist << 16) | *(uint16_t*)src, src += 2;
      }
      match_dist = (32 << nb) + (match_dist << 5) + sym - 39;
      bk->recent_dist[(recent_dist_mask >> 21) & 7] =
          bk->recent_dist[(recent_dist_mask >> 18) & 7];
      bk->recent_dist[(recent_dist_mask >> 18) & 7] = match_dist;
    } else {
      size_t idx = (recent_dist_mask >> (3 * sym)) & 7;
      uint32_t mask = ~7U << (3 * sym);
      match_dist = bk->recent_dist[idx];
      recent_dist_mask = (recent_dist_mask & mask) | (idx + 8 * recent_dist_mask) & ~mask;
    }
    uint32_t safe_copy_len = (copy_length + 7) & ~7U;
    assert(match_dist <= dst - dst_start);
    assert(dst_end - dst >= safe_copy_len);
    for (i = 0; i < copy_length; i++) {
      dst[i] = dst[i - match_dist];
    }
    dst += copy_length;
    last_match_negative = -(intptr_t)match_dist;
  }
  assert(bits == 0x10000 && bits2 == 0x10000);
  assert(dst >= dst_quantum_end);
  assert(dst <= dst_end);
  assert(src <= src_end);
  bk->last_match_dist = -last_match_negative;
  bk->recent_dist_mask = recent_dist_mask;
  *dst_ptr = dst;
  return src - src_in;
}
