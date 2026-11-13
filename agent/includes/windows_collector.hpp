#pragma once
#pragma comment(lib, "wevtapi.lib")
#include <atomic>
#include "bounded_queue.hpp"
#include <thread>
#include <chrono>
#include <windows.h>
#include <winevt.h>
#include "pugixml.hpp"





class WindowsProcessCollector {
    private:
        EVT_HANDLE subscription_handle_{NULL};
        std::atomic<uint64_t> seq_counter_{0};
        BoundedEventQueue* queue_;

        std::string wide_to_utf8(const wchar_t* wstr) {
            if (!wstr) return "";
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
            std::string str(size_needed - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], size_needed, NULL, NULL);
            return str;
        }

        void ParseEvent(EVT_HANDLE hEvent) {
            DWORD bufferSize = 0;
            DWORD bufferUsed = 0;
            DWORD propertyCount = 0;

            // 1. Узнаем необходимый размер буфера
            if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, NULL, &bufferUsed, &propertyCount)) {
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    bufferSize = bufferUsed;
                    
                    // Выделяем память (bufferSize указан в байтах, делим на размер wchar_t)
                    std::vector<wchar_t> buffer(bufferSize / sizeof(wchar_t));
                    // 2. Получаем сам XML-текст события
                    if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer.data(), &bufferUsed, &propertyCount)) {
                        
                        std::string xml_utf8 =  wide_to_utf8(buffer.data());
                        ProcessEvent event;

                        pugi::xml_document doc;
                        pugi::xml_parse_result result = doc.load_string(xml_utf8.c_str());

                        if (!result) {
                            return; // XML битый
                        }

                        // 1. Прыгаем сразу в блок EventData:
                        pugi::xml_node event_data = doc.child("Event").child("EventData");

                        // 2. В цикле обходим все теги <Data Name="...">:
                        for (pugi::xml_node data : event_data.children("Data")) {
                            std::string name = data.attribute("Name").as_string();
                            std::string value = data.text().as_string();

                            // 3. Раскладываем по полям Protobuf:
                            if (name == "ProcessGuid") {
                                event.mutable_all_ids()->set_process_uid(value);
                            } else if (name == "ParentProcessGuid") {
                                event.mutable_all_ids()->set_parent_process_uid(value);
                            } else if (name == "Image") {
                                event.mutable_bin_data()->set_image_path(value);
                            } else if (name == "CommandLine") {
                                event.mutable_bin_data()->set_command_line(value);
                            } else if (name == "ProcessId") {
                                event.mutable_all_ids()->set_pid(std::stoul(value));
                            }

                            
                        }   
                        event.set_sequence_id(seq_counter_);
                        event.set_type(PROCESS_EVENT_TYPE_START);

                        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()
                        ).count();

                        event.set_timestamp_epoch_ms(now_ms);
                        queue_->push(std::move(event));
                    } else {
                        wprintf(L"Ошибка при рендеринге: %lu\n", GetLastError());
                    }
                } else {
                    wprintf(L"Неожиданная ошибка: %lu\n", GetLastError());
                }
            }
        }



        static DWORD WINAPI SubscriptionCallback(
            EVT_SUBSCRIBE_NOTIFY_ACTION action, 
            PVOID pContext, 
            EVT_HANDLE hEvent
        ) {

            auto* self = static_cast<WindowsProcessCollector*>(pContext);
            switch (action)
            {
            case EvtSubscribeActionError: {
                DWORD errorCode = (DWORD)(ULONG_PTR)hEvent;
                break;
            }
                
            case EvtSubscribeActionDeliver: {
                self->seq_counter_++;
                self->ParseEvent(hEvent);
                break;
            }

            default:
                break;
            }

            return ERROR_SUCCESS;
        }


    public:

        void start(BoundedEventQueue& queue, std::atomic<bool>& is_running) {

            queue_ = &queue;

            subscription_handle_ = EvtSubscribe(
                NULL, 
                NULL, 
                L"Microsoft-Windows-Sysmon/Operational", 
                L"*[System[(EventID=1)]]", 
                NULL, 
                this, 
                SubscriptionCallback, // Передаю функцию сюда
                EvtSubscribeToFutureEvents
            );

            if (subscription_handle_ == NULL) {
                wprintf(L"[WindowsCollector] Failed to subscribe to Sysmon! Error: %lu\n", GetLastError());
                return;
            }
            
            while(is_running.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                
            }
            EvtClose(subscription_handle_);
        }
};