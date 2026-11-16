#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>

#include "bounded_queue.hpp"

struct ProcessStatInfo {
    pid_t ppid{0};
    unsigned long long start_time{0};
};

class LinuxProcessCollector {
public:
    LinuxProcessCollector() = default;
    ~LinuxProcessCollector();

    LinuxProcessCollector(const LinuxProcessCollector&) = delete;
    LinuxProcessCollector& operator=(const LinuxProcessCollector&) = delete;

    void start(BoundedEventQueue& queue, std::atomic<bool>& is_running);

private:
    int sock_fd_{-1};
    uint8_t buffer_[4096]{};
    std::atomic<uint64_t> seq_counter_{0};

    bool init_netlink();
    std::string get_process_image(pid_t pid);
    std::string get_process_cmdline(pid_t pid);
    ProcessStatInfo get_process_stat(pid_t pid);
    std::optional<ProcessEvent> enrich_process_from_procfs(pid_t pid);
    void parse_proc_event(BoundedEventQueue& queue);
};

