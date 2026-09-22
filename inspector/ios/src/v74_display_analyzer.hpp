#pragma once

#include <string>

struct PvZ2V74DisplayAnalysis {
    bool present = false;
    std::string diagnosis;
    std::string next_plan;
    std::string critical_excerpt;
};

PvZ2V74DisplayAnalysis AnalyzeV74DisplayLog(
    const std::string& log);
