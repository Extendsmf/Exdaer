#include "bounded_queue.hpp"
#include "telemetry.grpc.pb.h"
#include "telemetry.pb.h"
#include <thread>
#include <atomic>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include "linux_collector.hpp"
#include <csignal>

void network_consumer_thread(BoundedEventQueue& queue, std::string server_address, std::atomic<bool>& is_running) {
    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    std::unique_ptr<TelemetryService::Stub> stub = TelemetryService::NewStub(channel);


    std::vector <ProcessEvent> curr_batch;
    uint32_t curr_drops = 0;
    size_t max_batch_size = 100;
    std::chrono::milliseconds timeout(200);
    std::chrono::milliseconds last_tmout(10);

    auto send_batch = [&](std::vector<ProcessEvent>& events, uint32_t drops) {
        if (events.empty() && drops == 0) return;

        TelemetryBatch batch;
        batch.set_host_id("endpoint-linux-01");
        batch.set_schema_version("1.0");
        batch.set_dropped_events_count(drops);

        for (auto& event : events) {
            *batch.add_events() = std::move(event);
        }

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        IngestResponse response;

        grpc::Status status = stub->SendTelemetry(&context, batch, &response);
        if (status.ok()) {
            for (const auto& uid : response.kill_process_uids()) {
                size_t first_dash = uid.find('-');
                size_t second_dash = uid.find('-', first_dash + 1);
                std::string pid_str = uid.substr(first_dash + 1, second_dash - first_dash - 1);
                if (first_dash == std::string::npos || second_dash == std::string::npos || second_dash <= first_dash + 1) {
                    continue; // Невалидный формат, пропускаем без паники
                }
                int pid = 0;

                try {
                    pid = std::stoi(pid_str);
                } catch (...) {
                    continue; // Если не число — безопасно пропускаем
                }

                if (pid <= 1 || pid == getpid()) continue;

                kill(pid, SIGKILL);

                if (kill(pid, SIGKILL) == 0) {
                    std::cout << "[ACTIVE RESPONSE] Successfully terminated malicious process PID: " << pid << "!" << std::endl;
                } else {
                    if (errno == ESRCH) {
                        // Процесс уже успел завершиться сам
                    } else {
                        std::perror("[ACTIVE RESPONSE] Failed to kill process");
                    }
                }

            }
        } else {
            std::cerr << status.error_message() << std::endl;
        }
    };

    // 1. Основной рабочий цикл
    while (is_running) {
        auto [events, drops] = queue.pop_batch(max_batch_size, timeout);
        send_batch(events, drops);
    }

    // 2. Дренирование остатков очереди при выключении
    while (true) {
        auto [events, drops] = queue.pop_batch(max_batch_size, last_tmout);
        if (events.empty() && drops == 0) break;
        send_batch(events, drops);
    }
}


static std::atomic<bool>* g_running = nullptr;

void signal_handler(int) {
    if (g_running) {
        g_running->store(false);
    }
}

int main() {

    std::cout << "Agent started successfully!" << std::endl;
    std::atomic<bool> is_running{true};
    g_running = &is_running;

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    BoundedEventQueue queue(100);
    LinuxProcessCollector collector;

    std::thread network_worker(network_consumer_thread, std::ref(queue), "localhost:50051", std::ref(is_running));
    std::thread collector_worker(&LinuxProcessCollector::start, &collector, std::ref(queue), std::ref(is_running));


    collector_worker.join();
    network_worker.join();


}