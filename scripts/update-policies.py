from collections import OrderedDict
from collections.abc import Mapping
from itertools import chain
from typing import Any, Mapping

import oyaml
import requests

extra_syscalls = [
    "_exit",
    "clear_tid_address",
    "futimens",
    "getreuid",
    "inotify1_init",
    "signal",
    "sigpending",
    "sigsuspend",
    "wait",
    "wait3",
]


class OYAMLDumper(oyaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(OYAMLDumper, self).increase_indent(flow, False)


def nmget(
    o: Mapping[str, Any],
    key_path: str,
    def_val: Any = None,
    path_delimiter: str = ".",
    null_as_default: bool = True,
) -> Any:
    """
    A short-hand for retrieving a value from nested mappings
    ("nested-mapping-get"). At each level it checks if the given "path"
    component in the given key exists and return the default value whenever
    fails.
    Example:
    >>> o = {'a':{'b':1}, 'x': None}
    >>> nmget(o, 'a', 0)
    {'b': 1}
    >>> nmget(o, 'a.b', 0)
    1
    >>> nmget(o, 'a/b', 0, '/')
    1
    >>> nmget(o, 'a.c', 0)
    0
    >>> nmget(o, 'x', 0)
    0
    >>> nmget(o, 'x', 0, null_as_default=False)
    None
    """
    pieces = key_path.split(path_delimiter)
    while pieces:
        p = pieces.pop(0)
        if o is None or p not in o:
            return def_val
        o = o[p]
    if o is None and null_as_default:
        return def_val
    return o


def filter_syscalls(processor_arch, syscalls_item):
    if syscalls_item["action"] != "SCMP_ACT_ALLOW":
        return []

    excludes = nmget(syscalls_item, "excludes.arches")
    if excludes and processor_arch in excludes:
        return []

    includes = nmget(syscalls_item, "includes.arches")
    if includes and not processor_arch in includes:
        return []

    # TODO: Add ("includes" | "excludes") . "caps" filtering implementation here.

    return syscalls_item["names"]


docker_seccomp_default_profile = requests.get(
    "https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json"
).json()


# ['amd64', 'arm', 'arm64', 'x32', 'x86', 's390', 's390x', 'riscv64', 'ppc64le']:
for processor_arch in ["amd64", "arm64"]:
    allowed_syscalls = set(
        chain(
            *list(
                filter_syscalls(processor_arch, syscalls_item)
                for syscalls_item in docker_seccomp_default_profile["syscalls"]
            ),
            extra_syscalls,
        )
    )

    yml_filepath = f"./default-policies/default-policy.{processor_arch}.yml"
    default_policy = oyaml.load(open(yml_filepath, "r"), Loader=oyaml.FullLoader)
    if not default_policy:
        default_policy = OrderedDict()
    default_policy["allowed_syscalls"] = sorted(list(allowed_syscalls))

    oyaml.dump(
        default_policy,
        open(yml_filepath, "w"),
        Dumper=OYAMLDumper,
        default_flow_style=False,
    )
