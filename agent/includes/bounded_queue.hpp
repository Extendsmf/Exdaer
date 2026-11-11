#pragma once
#include "telemetry.pb.h"
#include <mutex>
#include <condition_variable>
#include <deque>
#include <vector>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <utility>


class BoundedEventQueue {
    private:
        mutable std::mutex mutex_;
        size_t max_capacity_;
        uint32_t dropped_events_count_;
        std::condition_variable cv_;
        std::deque <ProcessEvent> queue_;
    
    public:
        explicit BoundedEventQueue(size_t max_capacity = 1000)
            : max_capacity_(max_capacity), 
            dropped_events_count_(0) {}

        void push(ProcessEvent event) {
            std::lock_guard<std::mutex> lock(mutex_); //Захватываем мьютекс
            if (queue_.size() >= max_capacity_) { //Проверка на переполнение очереди
                queue_.pop_front();
                dropped_events_count_++; //Увеличиваем счетчик дропнутых ивентов
            } 

            queue_.push_back(std::move(event)); //Добавляем ивент в очередь
            cv_.notify_one(); //уведомление о том, что ивент пришел

        }

        std::pair <std::vector<ProcessEvent>, uint32_t> pop_batch(size_t max_batch_size, std::chrono::milliseconds timeout) { //метод для отправки ивентов из очереди
            std::unique_lock<std::mutex> lock(mutex_); //Захватываем мьютекс
            cv_.wait_for(lock, timeout, [this] { 
                return !queue_.empty(); 
            });

            uint32_t drops = std::exchange(dropped_events_count_, 0);
            
            std::vector <ProcessEvent> batch;
            
            size_t current_batch_size = std::min(max_batch_size, queue_.size());
            batch.reserve(current_batch_size);

            for(size_t i = 0; i < current_batch_size; i++) {
                batch.push_back(std::move(queue_.front()));
                queue_.pop_front();
            }

            return {batch, drops};
        }


};