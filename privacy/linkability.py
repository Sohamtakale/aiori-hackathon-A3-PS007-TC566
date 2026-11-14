"""PT-3 passive linkability model.

A passive adversary WITHOUT keys sees addresses appear and disappear on the
shared segment and tries to link each new address to the device that owned the
previous one, using timing adjacency: a new address is guessed to belong to the
device whose previous address stopped being used closest in time.

We measure the adversary's linkage accuracy against the random baseline
(1 / number of devices active at that moment). Overlapping address validity and
many devices rotating concurrently blur the old->new transition and push
accuracy toward random; sparse, cleanly separated rotations leak linkage. The
number is reported, not promised (PRD section 12, PT-3).
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List


@dataclass
class LinkResult:
    accuracy: float
    random_baseline: float
    advantage: float          # accuracy - baseline (0 = no better than guessing)
    n_links: int


@dataclass
class _Transition:
    t: float                  # time the device's new address appears (old->new rotation)
    device: int


def generate_transitions(num_devices: int, duration: float, interval: float, jitter: float,
                         seed: int) -> List[_Transition]:
    """One transition per device rotation. The first address of each device is
    not a transition (nothing to link it to)."""
    rng = random.Random("pt3/%d" % seed)
    trans: List[_Transition] = []
    for dev in range(num_devices):
        t = rng.uniform(0, interval)
        first = True
        while t < duration:
            if not first:
                trans.append(_Transition(t, dev))
            first = False
            t += max(0.1, interval + rng.uniform(-jitter, jitter))
    trans.sort(key=lambda x: x.t)
    return trans


def adversary_link(trans: List[_Transition], num_devices: int, window: float, overlap: float,
                   seed: int) -> LinkResult:
    """Timing-adjacency attack: to link a device's new address to its previous
    one, the adversary must tell this rotation apart from others nearby. Any
    rotation within +/-(window+overlap) is a confusable candidate; the adversary
    picks uniformly among the devices transitioning in that span, so it is right
    with probability 1/k. Overlapping validity widens the blur; concurrency
    raises k. (Expected accuracy -- deterministic given the schedule.)"""
    span = window + overlap
    times = [x.t for x in trans]
    import bisect
    correct_prob = 0.0
    seen = set()
    active_counts = []
    for i, x in enumerate(trans):
        lo = bisect.bisect_left(times, x.t - span)
        hi = bisect.bisect_right(times, x.t + span)
        devs = {trans[j].device for j in range(lo, hi)}
        k = max(1, len(devs))
        correct_prob += 1.0 / k
        seen.add(x.device)
        active_counts.append(max(1, len(seen)))
    n = len(trans)
    acc = correct_prob / n if n else 0.0
    base = sum(1.0 / a for a in active_counts) / n if n else 0.0
    return LinkResult(acc, base, acc - base, n)


def measure(num_devices: int = 5, duration: float = 600.0, interval: float = 30.0,
            jitter: float = 10.0, overlap: float = 5.0, window: float = 2.0,
            seeds: int = 20) -> LinkResult:
    accs, bases, advs, n = [], [], [], 0
    for seed in range(seeds):
        tr = generate_transitions(num_devices, duration, interval, jitter, seed)
        r = adversary_link(tr, num_devices, window, overlap, seed)
        accs.append(r.accuracy)
        bases.append(r.random_baseline)
        advs.append(r.advantage)
        n += r.n_links
    k = len(accs)
    return LinkResult(sum(accs) / k, sum(bases) / k, sum(advs) / k, n // k)
