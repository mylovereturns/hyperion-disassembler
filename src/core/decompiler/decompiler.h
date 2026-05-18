#pragma once
#include "core/decompiler/lifter.h"
#include "core/decompiler/lifter_arm64.h"
#include "core/decompiler/lifter_arm.h"
#include "core/decompiler/ssa.h"
#include "core/decompiler/dce.h"
#include "core/decompiler/propagate.h"
#include "core/decompiler/type_infer.h"
#include "core/decompiler/cf_struct.h"
#include "core/decompiler/emitter.h"
#include "core/decompiler/pseudo_gen.h"
#include "core/analysis/rtti.h"

namespace hype {

class Decompiler {
public:
    std::vector<PseudoLine> decompile(const Function& func, const AnalysisDB& db,
                                       const RTTIParser* rtti = nullptr);

private:
    Lifter      lifter_;
    LifterARM64 arm64_lifter_;
    LifterARM   arm_lifter_;
    SSABuilder  ssa_;
    DCE         dce_;
    Propagate   prop_;
    TypeInfer   ti_;
    CFStructure cf_;
    Emitter     emitter_;
};

}
