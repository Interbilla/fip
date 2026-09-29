"""One filesystem probe inside the OpenShell sandbox. Prints one JSON object."""

import errno
import json
import sys
from datetime import datetime, timezone

PROBES = {
    "authorized-read": ("read", "/mission/input/input.txt"),
    "authorized-write": ("write", "/mission/output/result.txt"),
    "unauthorized-input-write": ("write", "/mission/input/unauthorized.txt"),
    "unauthorized-unrelated-read": ("read", "/mission/unrelated/secret.txt"),
    "unauthorized-unrelated-write": ("write", "/mission/unrelated/unauthorized.txt"),
    "critical-input-write": ("write", "/mission/input/should-fail.txt"),
    "critical-unrelated-write": ("write", "/mission/unrelated/should-fail.txt"),
    "substrate-tmp-write": ("write", "/tmp/fip-m4-test.txt"),
    "substrate-etc-read": ("read", "/etc/os-release"),
    "workdir-read": ("read", "/sandbox/only-via-workdir.txt"),
}


def main():
    name = sys.argv[1]
    operation, path = PROBES[name]
    observed = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {
        "probe": name,
        "operation": operation,
        "path": path,
        "observedAt": observed,
        "outcome": None,
        "errno": None,
        "errnoName": None,
        "detail": None,
    }
    try:
        if operation == "read":
            with open(path, "rb") as handle:
                record["detail"] = handle.read(64).decode("utf-8", "replace")
        elif operation == "write":
            with open(path, "wb") as handle:
                handle.write(b"fip-m4\n")
            record["detail"] = "wrote"
        else:
            raise ValueError(operation)
        record["outcome"] = "success"
    except OSError as exc:
        record["outcome"] = "failure"
        record["errno"] = exc.errno
        record["errnoName"] = errno.errorcode.get(exc.errno, str(exc.errno))
        record["detail"] = exc.strerror
    json.dump(record, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
