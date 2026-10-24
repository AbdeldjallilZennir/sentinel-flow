// Userspace BPF map manager for SentinelFlow (no libbpf-dev required)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PIN_PATH "/sys/fs/bpf/tc/globals/blocked_ips"

struct block_entry {
    uint64_t blocked_at_ns;
    uint64_t dropped_pkts;
    uint64_t dropped_bytes;
    uint32_t reason_code;
    uint32_t pad;
};

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static uint64_t ptr_to_u64(const void *ptr)
{
    return (uint64_t)(uintptr_t)ptr;
}

static int open_or_create_map(const char *pin_path, int create_if_missing)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64(pin_path);
    int fd = sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    if (fd >= 0 || !create_if_missing)
        return fd;

    memset(&attr, 0, sizeof(attr));
    attr.map_type    = BPF_MAP_TYPE_HASH;
    attr.key_size    = sizeof(uint32_t);
    attr.value_size  = sizeof(struct block_entry);
    attr.max_entries = 65536;
    snprintf(attr.map_name, sizeof(attr.map_name), "blocked_ips");

    fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        perror("BPF_MAP_CREATE");
        return -1;
    }

    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64(pin_path);
    attr.bpf_fd   = (uint32_t)fd;
    if (sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) < 0) {
        perror("BPF_OBJ_PIN");
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    const char *pin_path = getenv("SENTINEL_BPF_MAP");
    if (!pin_path || !pin_path[0])
        pin_path = DEFAULT_PIN_PATH;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <init|add IP [reason]|del IP|list|teardown>\n", argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "init") == 0) {
        int fd = open_or_create_map(pin_path, 1);
        if (fd < 0) return 1;
        close(fd);
        printf("{\"status\":\"ok\",\"map\":\"%s\"}\n", pin_path);
        return 0;
    }

    if (strcmp(cmd, "teardown") == 0) {
        unlink(pin_path);
        printf("{\"status\":\"removed\",\"map\":\"%s\"}\n", pin_path);
        return 0;
    }

    if (strcmp(cmd, "add") == 0 && argc >= 3) {
        uint32_t key = 0;
        if (inet_pton(AF_INET, argv[2], &key) != 1) {
            fprintf(stderr, "Invalid IPv4: %s\n", argv[2]);
            return 1;
        }
        int fd = open_or_create_map(pin_path, 1);
        if (fd < 0) return 1;

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct block_entry val;
        memset(&val, 0, sizeof(val));
        val.blocked_at_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        val.reason_code   = (argc >= 4) ? (uint32_t)strtoul(argv[3], NULL, 10) : 1;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.map_fd = (uint32_t)fd;
        attr.key    = ptr_to_u64(&key);
        attr.value  = ptr_to_u64(&val);
        attr.flags  = BPF_ANY;

        if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
            perror("BPF_MAP_UPDATE_ELEM");
            close(fd);
            return 1;
        }
        close(fd);
        printf("{\"status\":\"added\",\"ip\":\"%s\"}\n", argv[2]);
        return 0;
    }

    if (strcmp(cmd, "del") == 0 && argc >= 3) {
        uint32_t key = 0;
        if (inet_pton(AF_INET, argv[2], &key) != 1) return 1;
        int fd = open_or_create_map(pin_path, 0);
        if (fd < 0) return 1;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.map_fd = (uint32_t)fd;
        attr.key    = ptr_to_u64(&key);
        sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
        close(fd);
        printf("{\"status\":\"deleted\",\"ip\":\"%s\"}\n", argv[2]);
        return 0;
    }

    if (strcmp(cmd, "list") == 0) {
        int fd = open_or_create_map(pin_path, 0);
        if (fd < 0) {
            printf("[]\n");
            return 0;
        }
        uint32_t key = 0, next_key = 0;
        int first = 1;
        union bpf_attr attr;
        printf("[");
        memset(&attr, 0, sizeof(attr));
        attr.map_fd   = (uint32_t)fd;
        attr.key      = 0;
        attr.next_key = ptr_to_u64(&next_key);

        while (sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr)) == 0) {
            struct block_entry val;
            memset(&val, 0, sizeof(val));
            union bpf_attr lk;
            memset(&lk, 0, sizeof(lk));
            lk.map_fd = (uint32_t)fd;
            lk.key    = ptr_to_u64(&next_key);
            lk.value  = ptr_to_u64(&val);
            if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &lk, sizeof(lk)) == 0) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str));
                printf("%s{\"ip\":\"%s\",\"blocked_at_ns\":%llu,\"dropped_pkts\":%llu,\"dropped_bytes\":%llu,\"reason_code\":%u}",
                       first ? "" : ",",
                       ip_str,
                       (unsigned long long)val.blocked_at_ns,
                       (unsigned long long)val.dropped_pkts,
                       (unsigned long long)val.dropped_bytes,
                       val.reason_code);
                first = 0;
            }
            key = next_key;
            attr.key = ptr_to_u64(&key);
        }
        printf("]\n");
        close(fd);
        return 0;
    }

    return 1;
}
