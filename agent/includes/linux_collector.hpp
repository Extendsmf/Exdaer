#pragma once
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <atomic>
#include "bounded_queue.hpp"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <linux/cn_proc.h>
#include <linux/connector.h> 
#include <linux/limits.h>
#include <optional>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <syslog.h>
#include <poll.h>

class LinuxProcessCollector {
    private:
        int sock_fd_{-1};
        uint8_t buffer_[4096];
        std::atomic<uint64_t> seq_counter_{0};
        bool init_netlink() {
            sock_fd_ = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR); // Открываем сокет

            if (sock_fd_ < 0) {
                std::perror("Socket failed");
                return false;
            }

            int rcvbuf_size = 4*1024*1024; // Размер буфера для логов из ядра, пока они не сохранились в очередь

            if (setsockopt(sock_fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) { // Увеличиваем размер до 4 мб
                close(sock_fd_);
                return false;
            }

            int flags = fcntl(sock_fd_, F_GETFL, 0); // Сохраняем текущие флаги сокета в переменную flags
            if (flags == -1) return false;
            flags |= O_NONBLOCK; // Добавляем флаг O_NONBLOCK
            if(fcntl(sock_fd_, F_SETFL, flags) == -1) return false; // Записываем обновленные флаги

            struct sockaddr_nl src_addr;
            std::memset(&src_addr, 0, sizeof(src_addr));
            src_addr.nl_family = AF_NETLINK; // Указываем семейство адресов Netlink
            src_addr.nl_pid = getpid(); // Идентификатор текущего процесса
            src_addr.nl_groups = CN_IDX_PROC;


            if (bind(sock_fd_, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
                std::perror("Bind failed");
                close(sock_fd_);
                return false;
            }

            // 1. Выделяем буфер под заголовок Netlink + заголовок Connector + команду
            char buf[128];
            std::memset(buf, 0, sizeof(buf));

            // 2. Размечаем указатели:
            auto* nl_hdr = reinterpret_cast<struct nlmsghdr*>(buf);
            auto* cn_hdr = reinterpret_cast<struct cn_msg*>(NLMSG_DATA(nl_hdr));

            // 3. Записываем команду PROC_CN_MCAST_LISTEN прямо в data коннектора:
            auto* op = reinterpret_cast<enum proc_cn_mcast_op*>(cn_hdr->data);
            *op = PROC_CN_MCAST_LISTEN;

            // 4. Заполняем размеры:
            nl_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
            nl_hdr->nlmsg_type = NLMSG_DONE;
            nl_hdr->nlmsg_pid = getpid();

            cn_hdr->id.idx = CN_IDX_PROC;
            cn_hdr->id.val = CN_VAL_PROC;
            cn_hdr->len = sizeof(enum proc_cn_mcast_op);

            // 5. Отправляем:
            if (send(sock_fd_, nl_hdr, nl_hdr->nlmsg_len, 0) < 0) {
                std::perror("Send subscription failed");
                close(sock_fd_);
                return false;
            }
            return true;
                    
        }

        std::string get_process_image(pid_t pid) {
            std::string path = "/proc/" + std::to_string(pid) + "/exe";
            char buf[PATH_MAX];

            ssize_t len = readlink(path.c_str(), buf, sizeof(buf) - 1);
            if (len <= 0) {
                return "";  
            } else {
                return std::string(buf, len); // Конструктор создаст строку длиной РОВНО len байт!
            }
        }

        std::string get_process_cmdline(pid_t pid) {
            std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
            int fd = open(path.c_str(), O_RDONLY);
            if (fd < 0) {
                return "";
            }

            char buffer[PATH_MAX];
            ssize_t len = read(fd, buffer, sizeof(buffer) - 1);

            if (len == -1 ) {
                close(fd);
                return "";
            }

            for (auto i = 0; i < len; i++) {
                if (buffer[i] == '\0') buffer[i] = ' ';
            }

            std::string res(buffer, len);

            if (!res.empty() && res.back() == ' ') {
                res.pop_back();
            }
            
            close(fd); // Закрываем файл
            return res;
        }

        pid_t get_process_ppid(pid_t pid) {
            std::string path = "/proc/" + std::to_string(pid) + "/stat";
            std::ifstream file(path);

            if (!file.is_open()) return -1;
            std::string line;
            std::getline(file, line);

            size_t last_bracket = line.rfind(')');
            if (last_bracket == std::string::npos || last_bracket + 2 >= line.length()) {
                return -1;
            }

            std::string remaining_part = line.substr(last_bracket + 2);

            std::stringstream stream(remaining_part);
            std::string state;
            std::string ppid_string;

            stream >> state >> ppid_string;
            
            try {
                return static_cast<pid_t>(std::stol(ppid_string));
            } catch (...) {
                return -1;
            }
        }

        std::optional<ProcessEvent> enrich_process_from_procfs(pid_t pid) {
            std::string image = get_process_image(pid);
            if (image.empty()) return std::nullopt;

            std::string cmdline = get_process_cmdline(pid);
            if (cmdline.empty()) cmdline = image;
            
            pid_t ppid = get_process_ppid(pid);

            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            ProcessEvent event;

            event.set_sequence_id(++seq_counter_); 
            event.set_timestamp_epoch_ms(now_ms);
            event.set_type(PROCESS_EVENT_TYPE_START);
            
            auto* ids = event.mutable_all_ids();
            ids->set_pid(pid);
            ids->set_ppid(ppid);
            ids->set_process_uid("linux-" + std::to_string(pid) + "-" + std::to_string(now_ms));
            ids->set_parent_process_uid("linux-" + std::to_string(ppid) + "-parent");
            
            auto* bin = event.mutable_bin_data();
            bin->set_image_path(image);
            bin->set_command_line(cmdline);

            return event;

        }

        void parse_proc_event(BoundedEventQueue& queue) {
            ssize_t len = recv(sock_fd_, buffer_, sizeof(buffer_), 0); 
            if (len < 0 && errno == ENOBUFS) {
                openlog("AgentAppExdaer", LOG_PID | LOG_CONS, LOG_USER);
                syslog(LOG_WARNING, "Внимание: низкий уровень свободной памяти");
                closelog();
            } else if (len < 0) return;


            ssize_t remaining = len;
            auto* nl_hdr = reinterpret_cast<struct nlmsghdr*>(buffer_); // Привожу тело буфера к типу заголовка Netlink (struct nlmsghdr)

            if (!NLMSG_OK(nl_hdr, len)) {
                return; // Пакет поврежден или обрезан ядром, дальше читать нельзя
            }

            while (NLMSG_OK(nl_hdr, remaining)) {
                auto* cn_hdr = reinterpret_cast<struct cn_msg*>(NLMSG_DATA(nl_hdr)); // Перемещаем указатель с помощью макроса NLMSG_DATA на следующую структуру и приводим к нужному типу
                
                if (!(cn_hdr->id.idx == CN_IDX_PROC && cn_hdr->id.val == CN_VAL_PROC)) {
                    return;
                }

                auto* proc_ev = reinterpret_cast<struct proc_event*> (cn_hdr->data);

                if (proc_ev->what != PROC_EVENT_EXEC) return; // Отбрасываем все, кроме execve
                
                pid_t pid = proc_ev->event_data.exec.process_tgid;
                auto event = enrich_process_from_procfs(pid);

                if (event.has_value()) {
                    queue.push(std::move(*event));
                }
                nl_hdr = NLMSG_NEXT(nl_hdr, remaining);
            }


        }



    public:
        
        ~LinuxProcessCollector() {
            if (sock_fd_ >= 0) {
                close(sock_fd_);
            }
        }

        void start(BoundedEventQueue& queue, std::atomic<bool>& is_running) {
            if (!init_netlink()) return;

            struct pollfd pfd;
            pfd.fd = sock_fd_;
            pfd.events = POLLIN;

            while(is_running.load()) {
                int res = poll(&pfd, 1, 200);
                if (res <= 0) continue;

                parse_proc_event(queue);
            }
            
        }

};