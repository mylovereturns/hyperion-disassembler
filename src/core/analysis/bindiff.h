#pragma once
#include "analysis_db.h"
#include <vector>
#include <string>

namespace hype {

struct DiffResult {
    va_t        addr_a;
    va_t        addr_b;
    std::string name;
    float       similarity;
    enum Status : u8 { Added, Removed, Modified, Identical };
    Status      status;
};

class BinDiff {
public:
    std::vector<DiffResult> compare(const AnalysisDB& a, const AnalysisDB& b);

private:
    float compute_similarity(const Function& fa, const Function& fb,
                             const AnalysisDB& da, const AnalysisDB& db);
    std::vector<u8> func_bytes(const Function& f, const AnalysisDB& db);
};

}
