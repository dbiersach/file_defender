/*
 * File Defender daemon.
 *
 * Reads a stream of file-activity events (from the fanotify collector on stdin,
 * or from a CSV file for offline testing), maintains a rolling behavioral
 * feature window PER PROCESS, scores each window with the trained Isolation
 * Forest model, and alerts when a process looks like ransomware.
 *
 * Defaults are deliberately safe:
 *   - alert-only: it prints alerts and does nothing to your processes.
 *   - --notify enables a desktop notification (via notify-send).
 *   - --stop enables pausing a flagged process with SIGSTOP. This is opt-in,
 *     and even then a process is only ever paused (never killed), so a false
 *     positive can be undone with `kill -CONT <pid>`.
 *
 * Examples:
 *   Offline test with the sample data:
 *     ./file_defender_daemon --events ../testdata/sample_events.csv --model model.json
 *
 *   Live monitoring (collector runs as root, daemon as your user):
 *     sudo ./fanotify_collector /home/student | ./file_defender_daemon --model model.json --notify
 */

#include "anomaly_model.hpp"
#include "feature_window.hpp"
#include "file_event.hpp"

#include <csignal>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> values;
    std::stringstream stream(line);
    std::string item;
    while (std::getline(stream, item, ',')) {
        values.push_back(item);
    }
    return values;
}

bool parse_event(const std::string& line, FileEvent& event) {
    const auto fields = split_csv_line(line);
    if (fields.size() != 8) {
        return false;
    }
    try {
        event.timestamp_seconds = std::stod(fields[0]);
        event.user_name = fields[1];
        event.process_name = fields[2];
        event.process_id = std::stoi(fields[3]);
        event.operation = fields[4];
        event.path = fields[5];
        event.bytes = static_cast<std::uint64_t>(std::stoull(fields[6]));
        event.byte_entropy = std::stod(fields[7]);
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

std::string arg_value(int argc, char** argv, const std::string& name, const std::string& fallback) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (name == argv[i]) {
            return argv[i + 1];
        }
    }
    return fallback;
}

bool has_flag(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; ++i) {
        if (name == argv[i]) {
            return true;
        }
    }
    return false;
}

// Send a desktop notification without invoking a shell (no injection risk).
void send_notification(const std::string& title, const std::string& body) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("notify-send", "notify-send", "--urgency=critical", title.c_str(), body.c_str(),
               static_cast<char*>(nullptr));
        _exit(127);  // exec failed (notify-send not installed)
    } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
    }
}

// Pause a process pending user review. Guarded so we never touch init or self.
void pause_process(int pid) {
    if (pid > 1 && pid != static_cast<int>(getpid())) {
        if (kill(static_cast<pid_t>(pid), SIGSTOP) == 0) {
            std::cerr << "Paused pid " << pid << " with SIGSTOP. Resume with: kill -CONT " << pid
                      << "\n";
        } else {
            std::cerr << "Could not pause pid " << pid << " (insufficient permissions?)\n";
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    const std::string events_path = arg_value(argc, argv, "--events", "-");
    const std::string model_path = arg_value(argc, argv, "--model", "model.json");
    const double window_seconds = std::stod(arg_value(argc, argv, "--window", "10"));
    const bool do_notify = has_flag(argc, argv, "--notify");
    const bool do_stop = has_flag(argc, argv, "--stop");

    AnomalyModel model;
    if (!model.load(model_path)) {
        std::cerr << "Could not load model: " << model_path << "\n";
        std::cerr << "Train one first: python3 python/train_isolation_forest.py ...\n";
        return 1;
    }

    // Use the model's recommended threshold unless the user overrides it.
    const double threshold =
        std::stod(arg_value(argc, argv, "--threshold",
                            std::to_string(model.recommended_threshold())));

    std::cerr << "File Defender daemon started.\n"
              << "  model      : " << model_path << "\n"
              << "  threshold  : " << threshold << "\n"
              << "  window     : " << window_seconds << " s\n"
              << "  mode       : " << (do_stop ? "STOP suspicious processes" : "alert-only")
              << (do_notify ? " + desktop notifications" : "") << "\n";

    // Choose the input stream: a CSV file, or stdin for live collector piping.
    std::ifstream file_input;
    std::istream* input = &std::cin;
    if (events_path != "-") {
        file_input.open(events_path);
        if (!file_input) {
            std::cerr << "Could not open events file: " << events_path << "\n";
            return 1;
        }
        input = &file_input;
    }

    // One rolling feature window per process id, so each process is judged on
    // its own behavior. This is what lets us name (and optionally pause) the
    // specific offending process.
    std::unordered_map<int, FeatureWindow> windows;
    std::unordered_set<int> already_flagged;

    std::string line;
    while (std::getline(*input, line)) {
        if (line.empty() || line.rfind("timestamp_seconds", 0) == 0) {
            continue;  // skip blank lines and the CSV header
        }

        FileEvent event;
        if (!parse_event(line, event)) {
            continue;
        }

        auto [it, inserted] = windows.try_emplace(event.process_id, window_seconds);
        FeatureWindow& window = it->second;
        window.add_event(event);

        const FeatureVector features = window.features();
        const double anomaly_score = model.score(to_vector(features));

        if (anomaly_score >= threshold) {
            std::cout << "ALERT score=" << anomaly_score << " pid=" << event.process_id
                      << " process=" << event.process_name << " user=" << event.user_name
                      << " op=" << event.operation << " path=" << event.path << " "
                      << to_string(features) << "\n";
            std::cout.flush();

            // Act once per process so we do not spam notifications or signals.
            if (already_flagged.insert(event.process_id).second) {
                if (do_notify) {
                    send_notification("File Defender: suspicious activity",
                                      event.process_name + " (pid " +
                                          std::to_string(event.process_id) + ") may be ransomware");
                }
                if (do_stop) {
                    pause_process(event.process_id);
                }
            }
        }
    }

    return 0;
}
