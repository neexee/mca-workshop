#!/usr/bin/env python3
import argparse
import os
from glob import glob

from modules.sysmon_analyzer import parse_files


def main():
    args = _parse_args()
    files = _unfold_paths(args.paths)
    processes, connections = parse_files(files)
    print(f'Discovered {len(processes)} processes and '
          f'{len(connections)} connections across {len(files)} file(s)')


def _parse_args():
    parser = argparse.ArgumentParser(
        description='Analyze sysmon json-formated logs')
    parser.add_argument(
        "paths",
        help='Paths to separate json logs or directory containing them',
        nargs='+')
    return parser.parse_args()


def _unfold_paths(paths):
    files = []
    for path in paths:
        if os.path.isdir(path):
            files.extend(glob(os.path.join(path, '*.json')))
            continue
        files.append(path)
    return files


if __name__ == '__main__':
    main()
