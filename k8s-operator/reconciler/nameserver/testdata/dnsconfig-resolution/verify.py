# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

"""Check snapshots from the isolated DNSConfig resolution scenario."""

import json
import sys
from collections import Counter
from pathlib import Path

output = Path(sys.argv[1])


def load(name):
    return json.loads((output / name).read_text())


def condition(obj, kind="DNSResolutionReady"):
    return next(c for c in obj["status"]["conditions"] if c["type"] == kind)


def event_counts(name):
    counts = Counter()
    for event in load(name)["items"]:
        counts[(event["type"], event["reason"])] += event.get("count", 1)
    return counts


def pods(name):
    return sorted(
        (pod["metadata"]["name"], pod["metadata"]["uid"],
         [(c["name"], c["restartCount"]) for c in pod["status"]["containerStatuses"]])
        for pod in load(name)["items"]
    )


states = {
    name: load(name + ".json")
    for name in ("empty", "unavailable", "unavailable-again", "failed",
                 "failed-again", "recovered", "recovered-again")
}
expected = {
    "empty": ("Unknown", "NoProbeRecord"),
    "unavailable": ("Unknown", "NameserverUnavailable"),
    "unavailable-again": ("Unknown", "NameserverUnavailable"),
    "failed": ("False", "DNSForwardingFailed"),
    "failed-again": ("False", "DNSForwardingFailed"),
    "recovered": ("True", "DNSResolutionSucceeded"),
    "recovered-again": ("True", "DNSResolutionSucceeded"),
}
for name, state in states.items():
    current = condition(state)
    assert (current["status"], current["reason"]) == expected[name], (name, current)
    assert current["observedGeneration"] == state["metadata"]["generation"], name
    assert condition(state, "NameserverReady")["status"] == "True", name

for name in ("unavailable", "failed", "recovered"):
    assert states[name]["metadata"]["resourceVersion"] == states[name + "-again"]["metadata"]["resourceVersion"], f"{name}: repeated observation rewrote status"

waiting = [
    c.get("state", {}).get("waiting", {}).get("reason")
    for pod in load("pods-unavailable.json")["items"]
    if pod["metadata"]["labels"].get("app") == "nameserver"
    for c in pod["status"].get("containerStatuses", [])
]
assert any(reason in ("ImagePullBackOff", "ErrImagePull") for reason in waiting), waiting
assert not event_counts("events-unavailable.json"), "Unavailable nameserver emitted a DNSConfig event"
assert event_counts("events-failed.json") == {("Warning", "DNSForwardingFailed"): 1}
assert event_counts("events-recovered.json") == {
    ("Warning", "DNSForwardingFailed"): 1,
    ("Normal", "DNSResolutionRecovered"): 1,
}
assert pods("pods-before.json") == pods("pods-after.json"), "Controller or nameserver restarted during forwarding recovery"

summary = {
    "result": "PASS",
    "empty_condition": condition(states["empty"]),
    "unavailable_condition": condition(states["unavailable-again"]),
    "unavailable_image_states": waiting,
    "unavailable_warnings": 0,
    "failure_condition": condition(states["failed"]),
    "recovery_condition": condition(states["recovered"]),
    "events": {"DNSForwardingFailed": 1, "DNSResolutionRecovered": 1},
    "provisioning_ready_throughout": True,
    "repeated_status_writes": False,
    "pods_restarted_during_forwarding_recovery": False,
    "scope": "Production nameserver controller running continuously inside kind; synthetic A and AAAA records over IPv4 cluster DNS; full operator and tailnet traffic excluded.",
}
(output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
