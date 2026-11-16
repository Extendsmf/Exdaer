#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <atomic>
#include <string>
#include <windows.h>
#include <winevt.h>
#include "bounded_queue.hpp"

class WindowsProcessCollector {
private:
    EVT_HANDLE subscription_handle_{ NULL };
    std::atomic<uint64_t> seq_counter_{ 0 };
    BoundedEventQueue* queue_{ nullptr };

    std::string wide_to_utf8(const wchar_t* wstr);
    void ParseEvent(EVT_HANDLE hEvent);

    static DWORD WINAPI SubscriptionCallback(
        EVT_SUBSCRIBE_NOTIFY_ACTION action,
        PVOID pContext,
        EVT_HANDLE hEvent
    );

public:
    void start(BoundedEventQueue& queue, std::atomic<bool>& is_running);
    
    ~WindowsProcessCollector();
};