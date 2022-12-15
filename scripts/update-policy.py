import requests
import oyaml
from itertools import chain
from collections.abc import Mapping
from collections import OrderedDict

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
  "wait3"
]


class OYAMLDumper(oyaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(OYAMLDumper, self).increase_indent(flow, False)


def lense(obj, *args):
    if len(args) == 0 and obj is not None:
        return obj

    if not isinstance(obj, Mapping):
        return None

    return lense(obj.get(args[0], None), *args[1:])


def filter_syscalls(processor_arch, syscalls_item):
    if syscalls_item['action'] != 'SCMP_ACT_ALLOW':
        return []

    excludes = lense(syscalls_item, 'excludes', 'arches')
    if excludes and processor_arch in excludes:
        return []

    includes = lense(syscalls_item, 'includes', 'arches')
    if includes and not processor_arch in includes:
        return []

    # TODO: Add ("includes" | "excludes") . "caps" filtering implementation here.

    return syscalls_item['names']


docker_seccomp_profile = requests.get('https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json').json()


# ['amd64', 'arm', 'arm64', 'x32', 'x86', 's390', 's390x', 'riscv64', 'ppc64le']:
for processor_arch in ['amd64', 'arm64']:
    allowed_syscalls = set(
        chain(
            *list(
                filter_syscalls(processor_arch, syscalls_item)
                for syscalls_item in docker_seccomp_profile['syscalls']
            ),
            extra_syscalls
        )
    )

    yml_filepath = f'./default-policies/default-policy.{processor_arch}.yml'
    default_policy = oyaml.load(open(yml_filepath, 'r'), Loader=oyaml.FullLoader)
    if not default_policy:
        default_policy = OrderedDict()
    default_policy['allowed_syscalls'] = sorted(list(allowed_syscalls))

    oyaml.dump(default_policy, open(yml_filepath, 'w'), Dumper=OYAMLDumper, default_flow_style=False)
