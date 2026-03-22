#pragma once

#include <gtkmm.h>
#include <thread>
#include <functional>
#include <future>

namespace async {

// Run function in background thread, call callback on main thread with result
template<typename T>
void run(std::function<T()> task, std::function<void(T)> callback) {
    std::thread([task, callback]() {
        T result = task();
        // Dispatch callback to main GTK thread
        Glib::signal_idle().connect_once([callback, result]() {
            callback(result);
        });
    }).detach();
}

// Run void function in background, call callback when done
inline void run(std::function<void()> task, std::function<void()> callback) {
    std::thread([task, callback]() {
        task();
        Glib::signal_idle().connect_once(callback);
    }).detach();
}

// Run function in background, no callback needed
inline void fire_and_forget(std::function<void()> task) {
    std::thread(task).detach();
}

} // namespace async
