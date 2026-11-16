#include "linux_collector.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <fstream>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

bool LinuxProcessCollector::init_netlink() {
    sock_fd_ = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (sock_fd_ < 0) {
        std::perror("Socket failed");
        return false;
    }

    const auto close_socket = [this]() {
        if (sock_fd_ >= 0) {
            close(sock_fd_);
            sock_fd_ = -1;
        }
    };

    int rcvbuf_size = 4 * 1024 * 1024;
    if (setsockopt(sock_fd_, SOL_SOCKET, SO_RCVBUF,
                   &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        close_socket();
        return false;
    }

    int flags = fcntl(sock_fd_, F_GETFL, 0);
    if (flags == -1) {
        close_socket();
        return false;
    }

    flags |= O_NONBLOCK;
    if (fcntl(sock_fd_, F_SETFL, flags) == -1) {
        close_socket();
        return false;
    }

    sockaddr_nl src_addr{};
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = CN_IDX_PROC;

    if (bind(sock_fd_, reinterpret_cast<sockaddr*>(&src_addr),
             sizeof(src_addr)) < 0) {
        std::perror("Bind failed");
        close_socket();
        return false;
    }

    char buf[128]{};
    auto* nl_hdr = reinterpret_cast<nlmsghdr*>(buf);
    auto* cn_hdr = reinterpret_cast<cn_msg*>(NLMSG_DATA(nl_hdr));
    auto* op = reinterpret_cast<enum proc_cn_mcast_op*>(cn_hdr->data);

    *op = PROC_CN_MCAST_LISTEN;

    nl_hdr->nlmsg_len =
        NLMSG_LENGTH(sizeof(cn_msg) + sizeof(enum proc_cn_mcast_op));
    nl_hdr->nlmsg_type = NLMSG_DONE;
    nl_hdr->nlmsg_pid = getpid();

    cn_hdr->id.idx = CN_IDX_PROC;
    cn_hdr->id.val = CN_VAL_PROC;
    cn_hdr->len = sizeof(enum proc_cn_mcast_op);

    if (send(sock_fd_, nl_hdr, nl_hdr->nlmsg_len, 0) < 0) {
        std::perror("Send subscription failed");
        close_socket();
        return false;
    }

    return true;
}

std::string LinuxProcessCollector::get_process_image(pid_t pid) {
    const std::string path = "/proc/" + std::to_string(pid) + "/exe";
    char buf[PATH_MAX];

    const ssize_t len = readlink(path.c_str(), buf, sizeof(buf) - 1);
    if (len <= 0) {
        return {};
    }

    return std::string(buf, static_cast<std::size_t>(len));
}

std::string LinuxProcessCollector::get_process_cmdline(pid_t pid) {
    const std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return {};
    }

    char buffer[PATH_MAX];
    const ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (len <= 0) {
        return {};
    }

    for (ssize_t i = 0; i < len; ++i) {
        if (buffer[i] == '\0') {
            buffer[i] = ' ';
        }
    }

    std::string result(buffer, static_cast<std::size_t>(len));
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }

    return result;
}

ProcessStatInfo LinuxProcessCollector::get_process_stat(pid_t pid) {
    const std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream file(path);

    if (!file.is_open()) {
        return {};
    }

    std::string line;
    std::getline(file, line);

    // Имя процесса в stat заключено в скобки и может содержать пробелы.
    const std::size_t last_bracket = line.rfind(')');
    if (last_bracket == std::string::npos ||
        last_bracket + 2 >= line.length()) {
        return {};
    }

    std::stringstream stream(line.substr(last_bracket + 2));

    std::string state;
    std::string ppid_string;
    stream >> state >> ppid_string;

    // После state и ppid пропускаем поля 5..21.
    std::string dummy;
    for (int field = 5; field <= 21; ++field) {
        if (!(stream >> dummy)) {
            return {};
        }
    }

    unsigned long long start_time = 0;
    if (!(stream >> start_time)) {
        return {};
    }

    try {
        const auto ppid = static_cast<pid_t>(std::stol(ppid_string));
        return {ppid, start_time};
    } catch (...) {
        return {};
    }
}

std::optional<ProcessEvent>
LinuxProcessCollector::enrich_process_from_procfs(pid_t pid) {
    const std::string image = get_process_image(pid);
    if (image.empty()) {
        return std::nullopt;
    }

    std::string cmdline = get_process_cmdline(pid);
    if (cmdline.empty()) {
        cmdline = image;
    }

    const ProcessStatInfo pid_stat = get_process_stat(pid);
    const ProcessStatInfo ppid_stat = get_process_stat(pid_stat.ppid);

    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    ProcessEvent event;
    event.set_sequence_id(++seq_counter_);
    event.set_timestamp_epoch_ms(now_ms);
    event.set_type(PROCESS_EVENT_TYPE_START);

    auto* ids = event.mutable_all_ids();
    ids->set_pid(pid);
    ids->set_ppid(pid_stat.ppid);
    ids->set_process_uid(
        "linux-" + std::to_string(pid) + "-" +
        std::to_string(pid_stat.start_time));

    if (pid_stat.ppid <= 1 || ppid_stat.start_time == 0) {
        // Не создаём фиктивный UID, если родитель неизвестен или уже завершился.
        ids->set_parent_process_uid("");
    } else {
        ids->set_parent_process_uid(
            "linux-" + std::to_string(pid_stat.ppid) + "-" +
            std::to_string(ppid_stat.start_time));
    }

    auto* bin = event.mutable_bin_data();
    bin->set_image_path(image);
    bin->set_command_line(cmdline);

    return event;
}

void LinuxProcessCollector::parse_proc_event(BoundedEventQueue& queue) {
    const ssize_t len = recv(sock_fd_, buffer_, sizeof(buffer_), 0);

    if (len < 0) {
        if (errno == ENOBUFS) {
            openlog("AgentAppExdaer", LOG_PID | LOG_CONS, LOG_USER);
            syslog(LOG_WARNING, "Внимание: переполнение буфера приёма Netlink");
            closelog();
        }
        return;
    }

    if (len == 0) {
        return;
    }

    int remaining = static_cast<int>(len);
    auto* nl_hdr = reinterpret_cast<nlmsghdr*>(buffer_);

    while (NLMSG_OK(nl_hdr, remaining)) {
        if (nl_hdr->nlmsg_len < NLMSG_LENGTH(sizeof(cn_msg))) {
            break;
        }

        auto* cn_hdr = reinterpret_cast<cn_msg*>(NLMSG_DATA(nl_hdr));
        if (cn_hdr->id.idx == CN_IDX_PROC &&
            cn_hdr->id.val == CN_VAL_PROC &&
            cn_hdr->len >= sizeof(proc_event)) {

            auto* proc_ev = reinterpret_cast<proc_event*>(cn_hdr->data);
            if (proc_ev->what == PROC_EVENT_EXEC) {
                const pid_t pid = proc_ev->event_data.exec.process_tgid;
                auto event = enrich_process_from_procfs(pid);

                if (event.has_value()) {
                    queue.push(std::move(*event));
                }
            }
        }

        nl_hdr = NLMSG_NEXT(nl_hdr, remaining);
    }
}

void LinuxProcessCollector::start(
    BoundedEventQueue& queue,
    std::atomic<bool>& is_running) {
    if (!init_netlink()) {
        return;
    }

    pollfd pfd{};
    pfd.fd = sock_fd_;
    pfd.events = POLLIN;

    while (is_running.load()) {
        const int result = poll(&pfd, 1, 200);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (result == 0) {
            continue;
        }

        if (pfd.revents & POLLIN) {
            parse_proc_event(queue);
        } else if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            break;
        }
    }
}

LinuxProcessCollector::~LinuxProcessCollector() {
    if (sock_fd_ >= 0) {
        close(sock_fd_);
        sock_fd_ = -1;
    }
}
