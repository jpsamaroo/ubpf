/*
 * Copyright 2020 Julian P. Samaroo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include "ubpf_int.h"
#include "ebpf.h"

typedef int (*WALKER)(struct ubpf_vm *vm, struct ebpf_inst inst, void *data, int inst_off, char *visited);

enum ubpf_walk_action
{
    UBPF_WALK_CONTINUE,
    UBPF_WALK_STOP,
    UBPF_WALK_INVALID,
};

int isjmp(struct ebpf_inst inst)
{
    if (((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_JMP) && (inst.opcode != EBPF_OP_CALL)) {
        return true;
    }
    return false;
}

int
ubpf_walk_paths(struct ubpf_vm *vm, WALKER walk_fn, void *data, int inst_off, char *visited)
{
    struct ebpf_inst inst = vm->insts[inst_off];
    int cmd = walk_fn(vm, inst, data, inst_off, visited);
    visited[inst_off] = 1;
    if (cmd != UBPF_WALK_CONTINUE)
        return cmd;
    if (inst.opcode == EBPF_OP_EXIT) {
        return UBPF_WALK_CONTINUE;
    } else if (isjmp(inst)) {
        int next_pc = inst_off+1+inst.offset;
        if (next_pc == inst_off) {
            fprintf(stderr, "Jump to self at offset %d\n", inst_off);
            return UBPF_WALK_INVALID;
        } else if ((next_pc < 0) || (next_pc > vm->num_insts-1)) {
            fprintf(stderr, "Jump out-of-bounds at offset %d to %d\n", inst_off, next_pc);
            return UBPF_WALK_INVALID;
        }
        if (visited[next_pc] == 0) {
            cmd = ubpf_walk_paths(vm, walk_fn, data, next_pc, visited);
            if (cmd == UBPF_WALK_STOP || cmd == UBPF_WALK_INVALID)
                return cmd;
        }
    }
    if (inst_off == vm->num_insts-1) {
        return UBPF_WALK_CONTINUE;
    } else {
        return ubpf_walk_paths(vm, walk_fn, data, inst_off+1, visited);
    }
}

int
ubpf_walk_start(struct ubpf_vm *vm, WALKER walk_fn, void *data)
{
    char visited[vm->num_insts];
    memset((void *)visited, 0, vm->num_insts);
    return ubpf_walk_paths(vm, walk_fn, data, 0, visited);
}

int
_walker_no_dead_insts(struct ubpf_vm *vm, struct ebpf_inst inst, void *data, int inst_off, char *visited)
{
    return UBPF_WALK_CONTINUE;
}

int
ubpf_verify_no_dead_insts(struct ubpf_vm *vm)
{
    char visited[vm->num_insts];
    memset((void *)visited, 0, vm->num_insts);
    int ret = ubpf_walk_paths(vm, _walker_no_dead_insts, NULL, 0, visited);
    if (ret)
        return ret;
    int any_dead = 0;
    for (int i = 0; i < vm->num_insts; i++) {
        if (visited[i] == 0) {
            any_dead = 1;
            fprintf(stderr, "Dead instruction at offset %d\n", i);
        }
    }
    return any_dead;
}

int
_walker_no_loops(struct ubpf_vm *vm, struct ebpf_inst inst, void *data, int inst_off, char *visited)
{
    if (isjmp(inst) && (inst_off+1+inst.offset < inst_off) && visited[inst_off+1+inst.offset]) {
        fprintf(stderr, "Loop detected at offset %d\n", inst_off);
        return UBPF_WALK_STOP;
    }
    return UBPF_WALK_CONTINUE;
}

int
ubpf_verify_no_loops(struct ubpf_vm *vm)
{
    return ubpf_walk_start(vm, _walker_no_loops, NULL);
}

int
ubpf_verify(struct ubpf_vm *vm)
{
    if (ubpf_verify_no_loops(vm))
        return 1;
    if (ubpf_verify_no_dead_insts(vm))
        return 1;
    return 0;
}
