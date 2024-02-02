# Copyright 2023 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This module is used to construct the config settings in the BUILD file in this same package.
"""

load("@bazel_skylib//lib:selects.bzl", "selects")
load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("//python:versions.bzl", "MINOR_MAPPING")

def construct_config_settings(name, python_versions, platforms = None):
    """Constructs a set of configs for all Python versions.

    Args:
        name: str, unused; only specified to satisfy buildifier lint checks
            and allow programatic modification of the target.
        python_versions: list of all (x.y.z) Python versions supported by rules_python.
        platforms (list[tuple[os, cpu]], optional): a list of platforms to
            generate settings for.
    """

    # Maps e.g. "3.8" -> ["3.8.1", "3.8.2", etc]
    minor_to_micro_versions = {}

    allowed_flag_values = []
    for micro_version in python_versions:
        minor, _, _ = micro_version.rpartition(".")
        minor_to_micro_versions.setdefault(minor, []).append(micro_version)
        allowed_flag_values.append(micro_version)

    allowed_flag_values.extend(list(minor_to_micro_versions))

    string_flag(
        name = "python_version",
        # TODO: The default here should somehow match the MODULE config. Until
        # then, use the empty string to indicate an unknown version. This
        # also prevents version-unaware targets from inadvertently matching
        # a select condition when they shouldn't.
        build_setting_default = "",
        values = [""] + sorted(allowed_flag_values),
        visibility = ["//visibility:public"],
    )

    oses = []
    cpus = []
    for (os, cpu) in platforms or []:
        if os not in oses:
            oses.append(os)
        if cpu not in cpus:
            cpus.append(cpu)

        _construct_config_settings_for_os_cpu(
            name = "_{}_{}".format(os, cpu),
            minor_to_micro_versions = minor_to_micro_versions,
            os = os,
            cpu = cpu,
        )

    for os in oses:
        _construct_config_settings_for_os_cpu(name = "_{}_any".format(os), minor_to_micro_versions = minor_to_micro_versions, os = os)

    for cpu in cpus:
        _construct_config_settings_for_os_cpu(name = "_any_{}".format(cpu), minor_to_micro_versions = minor_to_micro_versions, cpu = cpu)

def _construct_config_settings_for_os_cpu(*, name, minor_to_micro_versions, os = None, cpu = None):
    """Constructs a set of configs for all Python versions.

    Args:
        name: str, unused; only specified to satisfy buildifier lint checks
            and allow programatic modification of the target.
        minor_to_micro_versions: Maps e.g. "3.8" -> ["3.8.1", "3.8.2", etc]
        os: TODO
        cpu: TODO
    """

    constraint_values = []
    if os:
        constraint_values.append("@platforms//os:{}".format(os))
    if cpu:
        constraint_values.append("@platforms//cpu:{}".format(cpu))

    for minor_version, micro_versions in minor_to_micro_versions.items():
        # This matches the raw flag value, e.g. --//python/config_settings:python_version=3.8
        # It's private because matching the concept of e.g. "3.8" value is done
        # using the `is_python_X.Y` config setting group, which is aware of the
        # minor versions that could match instead.
        equals_minor_version_name = "_python_version_flag_equals_" + minor_version + name
        native.config_setting(
            name = equals_minor_version_name,
            flag_values = {":python_version": minor_version},
            constraint_values = constraint_values,
        )
        matches_minor_version_names = [equals_minor_version_name]

        default_micro_version = MINOR_MAPPING[minor_version]

        for micro_version in micro_versions:
            is_micro_version_name = "is_python_" + micro_version + name
            if default_micro_version != micro_version:
                native.config_setting(
                    name = is_micro_version_name,
                    flag_values = {":python_version": micro_version},
                    constraint_values = constraint_values,
                    visibility = ["//visibility:public"],
                )
                matches_minor_version_names.append(is_micro_version_name)
                continue

            # Ensure that is_python_3.9.8 is matched if python_version is set
            # to 3.9 if MINOR_MAPPING points to 3.9.8
            equals_micro_name = "_python_version_flag_equals_" + micro_version + name
            native.config_setting(
                name = equals_micro_name,
                flag_values = {":python_version": micro_version},
                constraint_values = constraint_values,
            )

            # An alias pointing to an underscore-prefixed config_setting_group
            # is used because config_setting_group creates
            # `is_{minor}_N` targets, which are easily confused with the
            # `is_{minor}.{micro}` (dot) targets.
            selects.config_setting_group(
                name = "_" + is_micro_version_name,
                match_any = [
                    equals_micro_name,
                    equals_minor_version_name,
                ],
            )
            native.alias(
                name = is_micro_version_name,
                actual = "_" + is_micro_version_name,
                visibility = ["//visibility:public"],
            )
            matches_minor_version_names.append(equals_micro_name)

        # This is prefixed with an underscore to prevent confusion due to how
        # config_setting_group is implemented and how our micro-version targets
        # are named. config_setting_group will generate targets like
        # "is_python_3.10_1" (where the `_N` suffix is len(match_any).
        # Meanwhile, the micro-version tarets are named "is_python_3.10.1" --
        # just a single dot vs underscore character difference.
        selects.config_setting_group(
            name = "_is_python_" + minor_version + name,
            match_any = matches_minor_version_names,
        )

        native.alias(
            name = "is_python_" + minor_version + name,
            actual = "_is_python_" + minor_version,
            visibility = ["//visibility:public"],
        )
