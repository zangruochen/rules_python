"""extract_wheels

extract_wheels resolves and fetches artifacts transitively from the Python Package Index (PyPI) based on a
requirements.txt. It generates the required BUILD files to consume these packages as Python libraries.

Under the hood, it depends on the `pip wheel` command to do resolution, download, and compilation into wheels.
"""
import argparse
import glob
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import textwrap
import zipfile
from typing import Dict, Iterable, List, Optional, Set, Tuple

import pkg_resources
import pkginfo

WHEEL_FILE_LABEL = "whl"


def current_umask() -> int:
    """Get the current umask which involves having to set it temporarily."""
    mask = os.umask(0)
    os.umask(mask)
    return mask


def set_extracted_file_to_default_mode_plus_executable(path: str) -> None:
    """
    Make file present at path have execute for user/group/world
    (chmod +x) is no-op on windows per python docs
    """
    os.chmod(path, (0o777 & ~current_umask() | 0o111))


class Wheel:
    """Representation of the compressed .whl file"""

    def __init__(self, path: str):
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    @property
    def name(self) -> str:
        return str(self.metadata.name)

    @property
    def metadata(self) -> pkginfo.Wheel:
        return pkginfo.get_metadata(self.path)

    def dependencies(self, extras_requested: Optional[Set[str]] = None) -> Set[str]:
        dependency_set = set()

        for wheel_req in self.metadata.requires_dist:
            req = pkg_resources.Requirement(wheel_req)  # type: ignore

            if req.marker is None or any(
                    req.marker.evaluate({"extra": extra})
                    for extra in extras_requested or [""]
            ):
                dependency_set.add(req.name)  # type: ignore

        return dependency_set

    def unzip(self, directory: str) -> None:
        with zipfile.ZipFile(self.path, "r") as whl:
            whl.extractall(directory)
            # The following logic is borrowed from Pip:
            # https://github.com/pypa/pip/blob/cc48c07b64f338ac5e347d90f6cb4efc22ed0d0b/src/pip/_internal/utils/unpacking.py#L240
            for info in whl.infolist():
                name = info.filename
                # Do not attempt to modify directories.
                if name.endswith("/") or name.endswith("\\"):
                    continue
                mode = info.external_attr >> 16
                # if mode and regular file and any execute permissions for
                # user/group/world?
                if mode and stat.S_ISREG(mode) and mode & 0o111:
                    name = os.path.join(directory, name)
                    set_extracted_file_to_default_mode_plus_executable(name)


def get_dist_info(wheel_dir: str) -> str:
    """"Returns the relative path to the dist-info directory if it exists.

    Args:
         wheel_dir: The root of the extracted wheel directory.

    Returns:
        Relative path to the dist-info directory if it exists, else, None.
    """
    dist_info_dirs = glob.glob(os.path.join(wheel_dir, "*.dist-info"))
    if not dist_info_dirs:
        raise ValueError(
            "No *.dist-info directory found. %s is not a valid Wheel." % wheel_dir
        )

    if len(dist_info_dirs) > 1:
        raise ValueError(
            "Found more than 1 *.dist-info directory. %s is not a valid Wheel."
            % wheel_dir
        )

    return dist_info_dirs[0]


def get_dot_data_directory(wheel_dir: str) -> Optional[str]:
    """Returns the relative path to the data directory if it exists.

    See: https://www.python.org/dev/peps/pep-0491/#the-data-directory

    Args:
         wheel_dir: The root of the extracted wheel directory.

    Returns:
        Relative path to the data directory if it exists, else, None.
    """

    dot_data_dirs = glob.glob(os.path.join(wheel_dir, "*.data"))
    if not dot_data_dirs:
        return None

    if len(dot_data_dirs) > 1:
        raise ValueError(
            "Found more than 1 *.data directory. %s is not a valid Wheel." % wheel_dir
        )

    return dot_data_dirs[0]


def parse_wheel_meta_file(wheel_dir: str) -> Dict[str, str]:
    """Parses the given WHEEL file into a dictionary.

    Args:
         wheel_dir: The file path of the WHEEL metadata file in dist-info.

    Returns:
        The WHEEL file mapped into a dictionary.
    """
    contents = {}
    with open(wheel_dir, "r") as wheel_file:
        for line in wheel_file:
            cleaned = line.strip()
            if not cleaned:
                continue
            try:
                key, value = cleaned.split(":", maxsplit=1)
                contents[key] = value.strip()
            except ValueError:
                raise RuntimeError(
                    "Encounted invalid line in WHEEL file: '%s'" % cleaned
                )
    return contents


def generate_build_file_contents(
        name: str, dependencies: List[str], whl_file_deps: List[str], pip_data_exclude: List[str],
) -> str:
    """Generate a BUILD file for an unzipped Wheel

    Args:
        name: the target name of the py_library
        dependencies: a list of Bazel labels pointing to dependencies of the library
        whl_file_deps: a list of Bazel labels pointing to wheel file dependencies of this wheel.

    Returns:
        A complete BUILD file as a string

    We allow for empty Python sources as for Wheels containing only compiled C code
    there may be no Python sources whatsoever (e.g. packages written in Cython: like `pymssql`).
    """

    data_exclude = ["*.whl", "**/*.py", "**/* *", "BUILD", "WORKSPACE"] + pip_data_exclude

    return textwrap.dedent(
        """\
        package(default_visibility = ["//visibility:public"])

        load("@rules_python//python:defs.bzl", "py_library")

        filegroup(
            name="{whl_file_label}",
            srcs=glob(["*.whl"]),
            data=[{whl_file_deps}]
        )

        py_library(
            name = "{name}",
            srcs = glob(["**/*.py"], allow_empty = True),
            data = glob(["**/*"], exclude={data_exclude}),
            # This makes this directory a top-level in the python import
            # search path for anything that depends on this.
            imports = ["."],
            deps = [{dependencies}],
        )
        """.format(
            name=name,
            dependencies=",".join(dependencies),
            data_exclude=json.dumps(data_exclude),
            whl_file_label=WHEEL_FILE_LABEL,
            whl_file_deps=",".join(whl_file_deps),
        )
    )


def generate_requirements_file_contents(repo_name: str, targets: Iterable[str]) -> str:
    """Generate a requirements.bzl file for a given pip repository

    The file allows converting the PyPI name to a bazel label. Additionally, it adds a function which can glob all the
    installed dependencies.

    Args:
        repo_name: the name of the pip repository
        targets: a list of Bazel labels pointing to all the generated targets

    Returns:
        A complete requirements.bzl file as a string
    """

    sorted_targets = sorted(targets)
    requirement_labels = ",".join(sorted_targets)
    whl_requirement_labels = ",".join(
        '"{}:whl"'.format(target.strip('"')) for target in sorted_targets
    )
    return textwrap.dedent(
        """\
        all_requirements = [{requirement_labels}]

        all_whl_requirements = [{whl_requirement_labels}]

        def requirement(name):
           name_key = name.replace("-", "_").replace(".", "_").lower()
           return "{repo}//pypi__" + name_key

        def whl_requirement(name):
            return requirement(name) + ":whl"
        """.format(
            repo=repo_name,
            requirement_labels=requirement_labels,
            whl_requirement_labels=whl_requirement_labels,
        )
    )


def sanitise_name(name: str) -> str:
    """Sanitises the name to be compatible with Bazel labels.

    There are certain requirements around Bazel labels that we need to consider. From the Bazel docs:

        Package names must be composed entirely of characters drawn from the set A-Z, a–z, 0–9, '/', '-', '.', and '_',
        and cannot start with a slash.

    Due to restrictions on Bazel labels we also cannot allow hyphens. See
    https://github.com/bazelbuild/bazel/issues/6841

    Further, rules-python automatically adds the repository root to the PYTHONPATH, meaning a package that has the same
    name as a module is picked up. We workaround this by prefixing with `pypi__`. Alternatively we could require
    `--noexperimental_python_import_all_repositories` be set, however this breaks rules_docker.
    See: https://github.com/bazelbuild/bazel/issues/2636
    """

    return "pypi__" + name.replace("-", "_").replace(".", "_").lower()


def setup_namespace_pkg_compatibility(wheel_dir: str) -> None:
    """Converts native namespace packages to pkgutil-style packages

    Namespace packages can be created in one of three ways. They are detailed here:
    https://packaging.python.org/guides/packaging-namespace-packages/#creating-a-namespace-package

    'pkgutil-style namespace packages' (2) and 'pkg_resources-style namespace packages' (3) works in Bazel, but
    'native namespace packages' (1) do not.

    We ensure compatibility with Bazel of method 1 by converting them into method 2.

    Args:
        wheel_dir: the directory of the wheel to convert
    """

    namespace_pkg_dirs = implicit_namespace_packages(
        wheel_dir, ignored_dirnames=["%s/bin" % wheel_dir,],
    )

    for ns_pkg_dir in namespace_pkg_dirs:
        add_pkgutil_style_namespace_pkg_init(ns_pkg_dir)


def extract_wheel(
        wheel_file: str,
        extras: Dict[str, Set[str]],
        pip_data_exclude: List[str],
        enable_implicit_namespace_pkgs: bool,
) -> str:
    """Extracts wheel into given directory and creates py_library and filegroup targets.

    Args:
        wheel_file: the filepath of the .whl
        extras: a list of extras to add as dependencies for the installed wheel
        pip_data_exclude: list of file patterns to exclude from the generated data section of the py_library
        enable_implicit_namespace_pkgs: if true, disables conversion of implicit namespace packages and will unzip as-is

    Returns:
        The Bazel label for the extracted wheel, in the form '//path/to/wheel'.
    """

    whl = Wheel(wheel_file)
    directory = sanitise_name(whl.name)

    os.mkdir(directory)
    # copy the original wheel
    shutil.copy(whl.path, directory)
    whl.unzip(directory)

    # Note: Order of operations matters here
    spread_purelib_into_root(directory)

    if not enable_implicit_namespace_pkgs:
        setup_namespace_pkg_compatibility(directory)

    extras_requested = extras[whl.name] if whl.name in extras else set()
    whl_deps = sorted(whl.dependencies(extras_requested))

    sanitised_dependencies = [
        '"//%s"' % sanitise_name(d) for d in whl_deps
    ]
    sanitised_wheel_file_dependencies = [
        '"//%s:%s"' % (sanitise_name(d), WHEEL_FILE_LABEL) for d in whl_deps
    ]

    with open(os.path.join(directory, "BUILD"), "w") as build_file:
        contents = generate_build_file_contents(
            sanitise_name(whl.name), sanitised_dependencies, sanitised_wheel_file_dependencies, pip_data_exclude
        )
        build_file.write(contents)

    os.remove(whl.path)

    return "//%s" % directory


def implicit_namespace_packages(
        directory: str, ignored_dirnames: Optional[List[str]] = None
) -> Set[str]:
    """Discovers namespace packages implemented using the 'native namespace packages' method.

    AKA 'implicit namespace packages', which has been supported since Python 3.3.
    See: https://packaging.python.org/guides/packaging-namespace-packages/#native-namespace-packages

    Args:
        directory: The root directory to recursively find packages in.
        ignored_dirnames: A list of directories to exclude from the search

    Returns:
        The set of directories found under root to be packages using the native namespace method.
    """
    namespace_pkg_dirs = set()
    for dirpath, dirnames, filenames in os.walk(directory, topdown=True):
        # We are only interested in dirs with no __init__.py file
        if "__init__.py" in filenames:
            dirnames[:] = []  # Remove dirnames from search
            continue

        for ignored_dir in ignored_dirnames or []:
            if ignored_dir in dirnames:
                dirnames.remove(ignored_dir)

        non_empty_directory = dirnames or filenames
        if (
                non_empty_directory
                and
                # The root of the directory should never be an implicit namespace
                dirpath != directory
        ):
            namespace_pkg_dirs.add(dirpath)

    return namespace_pkg_dirs


def add_pkgutil_style_namespace_pkg_init(dir_path: str) -> None:
    """Adds 'pkgutil-style namespace packages' init file to the given directory

    See: https://packaging.python.org/guides/packaging-namespace-packages/#pkgutil-style-namespace-packages

    Args:
        dir_path: The directory to create an __init__.py for.

    Raises:
        ValueError: If the directory already contains an __init__.py file
    """
    ns_pkg_init_filepath = os.path.join(dir_path, "__init__.py")

    if os.path.isfile(ns_pkg_init_filepath):
        raise ValueError("%s already contains an __init__.py file." % dir_path)

    with open(ns_pkg_init_filepath, "w") as ns_pkg_init_f:
        # See https://packaging.python.org/guides/packaging-namespace-packages/#pkgutil-style-namespace-packages
        ns_pkg_init_f.write(
            textwrap.dedent(
                """\
                # __path__ manipulation added by rules_python_external to support namespace pkgs.
                __path__ = __import__('pkgutil').extend_path(__path__, __name__)
                """
            )
        )


def spread_purelib_into_root(wheel_dir: str) -> None:
    """Unpacks purelib directories into the root.

    Args:
         wheel_dir: The root of the extracted wheel directory.
    """
    dist_info = get_dist_info(wheel_dir)
    wheel_metadata_file_path = pathlib.Path(dist_info, "WHEEL")
    wheel_metadata_dict = parse_wheel_meta_file(str(wheel_metadata_file_path))

    if "Root-Is-Purelib" not in wheel_metadata_dict:
        raise ValueError(
            "Invalid WHEEL file '%s'. Expected key 'Root-Is-Purelib'."
            % wheel_metadata_file_path
        )
    root_is_purelib = wheel_metadata_dict["Root-Is-Purelib"]

    if root_is_purelib.lower() == "true":
        # The Python package code is in the root of the Wheel, so no need to 'spread' anything.
        return

    dot_data_dir = get_dot_data_directory(wheel_dir)
    # 'Root-Is-Purelib: false' is no guarantee a .date directory exists with
    # package code in it. eg. the 'markupsafe' package.
    if not dot_data_dir:
        return

    for child in pathlib.Path(dot_data_dir).iterdir():
        # TODO(Jonathon): Should all other potential folders get ignored? eg. 'platlib'
        if str(child).endswith("purelib"):
            spread_purelib(child, wheel_dir)


def spread_purelib(purelib_dir: pathlib.Path, root_dir: str) -> None:
    """Recursively moves all sibling directories of the purelib to the root.

    Args:
        purelib_dir: The directory of the purelib.
        root_dir: The directory to move files into.
    """
    for grandchild in purelib_dir.iterdir():
        # Some purelib Wheels, like Tensorflow 2.0.0, have directories
        # split between the root and the purelib directory. In this case
        # we should leave the purelib 'sibling' alone.
        # See: https://github.com/dillon-giacoppo/rules_python_external/issues/8
        if not pathlib.Path(root_dir, grandchild.name).exists():
            shutil.move(
                src=str(grandchild), dst=root_dir,
            )


def parse_extras(requirements_path: str) -> Dict[str, Set[str]]:
    """Parse over the requirements.txt file to find extras requested.

    Args:
        requirements_path: The filepath for the requirements.txt file to parse.

    Returns:
         A dictionary mapping the requirement name to a set of extras requested.
    """

    extras_requested = {}
    with open(requirements_path, "r") as requirements:
        # Merge all backslash line continuations so we parse each requirement as a single line.
        for line in requirements.read().replace("\\\n", "").split("\n"):
            requirement, extras = parse_requirement_for_extra(line)
            if requirement and extras:
                extras_requested[requirement] = extras

    return extras_requested


def parse_requirement_for_extra(
        requirement: str,
) -> Tuple[Optional[str], Optional[Set[str]]]:
    """Given a requirement string, returns the requirement name and set of extras, if extras specified.
    Else, returns (None, None)
    """
    # https://www.python.org/dev/peps/pep-0508/#grammar
    extras_pattern = re.compile(
        r"^\s*([0-9A-Za-z][0-9A-Za-z_.\-]*)\s*\[\s*([0-9A-Za-z][0-9A-Za-z_.\-]*(?:\s*,\s*[0-9A-Za-z][0-9A-Za-z_.\-]*)*)\s*\]"
    )

    matches = extras_pattern.match(requirement)
    if matches:
        return (
            matches.group(1),
            {extra.strip() for extra in matches.group(2).split(",")},
        )
    return None, None


def configure_reproducible_wheels() -> None:
    """Modifies the environment to make wheel building reproducible.

    Wheels created from sdists are not reproducible by default. We can however workaround this by
    patching in some configuration with environment variables.
    """

    # wheel, by default, enables debug symbols in GCC. This incidentally captures the build path in the .so file
    # We can override this behavior by disabling debug symbols entirely.
    # https://github.com/pypa/pip/issues/6505
    if "CFLAGS" in os.environ:
        os.environ["CFLAGS"] += " -g0"
    else:
        os.environ["CFLAGS"] = "-g0"

    # set SOURCE_DATE_EPOCH to 1980 so that we can use python wheels
    # https://github.com/NixOS/nixpkgs/blob/master/doc/languages-frameworks/python.section.md#python-setuppy-bdist_wheel-cannot-create-whl
    if "SOURCE_DATE_EPOCH" not in os.environ:
        os.environ["SOURCE_DATE_EPOCH"] = "315532800"

    # Python wheel metadata files can be unstable.
    # See https://bitbucket.org/pypa/wheel/pull-requests/74/make-the-output-of-metadata-files/diff
    if "PYTHONHASHSEED" not in os.environ:
        os.environ["PYTHONHASHSEED"] = "0"


def main() -> None:
    """Main program.

    Exits zero on successful program termination, non-zero otherwise.
    """

    configure_reproducible_wheels()

    parser = argparse.ArgumentParser(
        description="Resolve and fetch artifacts transitively from PyPI"
    )
    parser.add_argument(
        "--requirements",
        action="store",
        required=True,
        help="Path to requirements.txt from where to install dependencies",
    )
    parser.add_argument(
        "--repo",
        action="store",
        required=True,
        help="The external repo name to install dependencies. In the format '@{REPO_NAME}'",
    )
    parser.add_argument(
        "--extra_pip_args", action="store", help="Extra arguments to pass down to pip.",
    )
    parser.add_argument(
        "--pip_data_exclude",
        action="store",
        help="Additional data exclusion parameters to add to the pip packages BUILD file.",
    )
    parser.add_argument(
        "--enable_implicit_namespace_pkgs",
        action="store_true",
        help="Disables conversion of implicit namespace packages into pkg-util style packages.",
    )
    args = parser.parse_args()

    pip_args = [sys.executable, "-m", "pip", "--isolated", "wheel", "-r", args.requirements]
    if args.extra_pip_args:
        pip_args += json.loads(args.extra_pip_args)["args"]

    # Assumes any errors are logged by pip so do nothing. This command will fail if pip fails
    subprocess.run(pip_args, check=True)

    extras = parse_extras(args.requirements)

    if args.pip_data_exclude:
        pip_data_exclude = json.loads(args.pip_data_exclude)["exclude"]
    else:
        pip_data_exclude = []

    targets = [
        '"%s%s"'
        % (
            args.repo,
            extract_wheel(
                whl, extras, pip_data_exclude, args.enable_implicit_namespace_pkgs
            ),
        )
        for whl in glob.glob("*.whl")
    ]

    with open("requirements.bzl", "w") as requirement_file:
        requirement_file.write(
            generate_requirements_file_contents(args.repo, targets)
        )
