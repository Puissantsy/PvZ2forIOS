#pragma once

#include <string>

struct PvZ2V68RuntimeAnalysis {
    bool present = false;
    std::string diagnosis;
    std::string v69_plan;
    std::string critical_excerpt;
};

PvZ2V68RuntimeAnalysis AnalyzeV68RuntimeLog(
    const std::string& log);
