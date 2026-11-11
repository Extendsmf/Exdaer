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
            std::cout << response.ack_sequence_id() << std::endl;
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