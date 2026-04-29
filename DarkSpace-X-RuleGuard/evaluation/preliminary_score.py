"""
Softplus-based composite for FPR/FNR tradeoff analysis in local evaluation.

FPR and FNR are fractions in [0, 1]. Lower returned score is better.
"""
from __future__ import annotations

import math

FPR_PENALTY_ORIGIN = 0.05
LINEAR_FNR_WEIGHT = 1.0
SOFTPLUS_FPR_WEIGHT = 2.0
FPR_SLOPE = 15.0


def softplus(x: float) -> float:
    return math.log(1.0 + math.exp(x))


def preliminary_score(fpr: float, fnr: float) -> float:
    return SOFTPLUS_FPR_WEIGHT * softplus(FPR_SLOPE * (fpr - FPR_PENALTY_ORIGIN)) + LINEAR_FNR_WEIGHT * fnr
