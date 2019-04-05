#!/usr/bin/env python2
# -*- coding: utf-8 -*-

""" The script will correct the permissions rights of system wide installed Python packages

    The problem arises due to hardening applied on top of Linux. Packages installed AFTER security policy
    has been updated might be affected. The policy changed a default "umask" to a more restrictive settings.

    How umask works, read here: https://en.wikipedia.org/wiki/Umask

    List of the modified files will be saved by default under: /tmp/python_perm.log

"""

import argparse
import logging
import os
import sys


_author__ = "Patryk Kubiak"
__version__ = "1.0.1"
__maintainer__ = "Patryk Kubiak"


# constants
SKIP_DIR_PATHS = ('/home', '/mnt')
DEFAULT_PERM_DIR = 0o755
DEFAULT_PERM_FILE = 0o644
EXPECTED_PERM_OCTAL_DIR = (oct(0755),)
EXPECTED_PERM_OCTAL_FILE = (oct(0755), oct(0644))

# configure simple logger
LOG_FORMAT = '%(levelname)s %(asctime)s - %(message)s'
LOG_FILE = '/tmp/python_perm.log'
LOG_LEVEL = logging.INFO
logging.basicConfig(filename=LOG_FILE, format=LOG_FORMAT,
                    level=LOG_LEVEL, filemode='a')
logger = logging.getLogger()


def parse_args():
    """ Parse arguments from CLI """
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--fix", help="apply fix to Python system packages",
                       action='store_true', default=False)
    group.add_argument("-q", "--query", help="return a number of files with wrong permissions or 0",
                       action='store_true', default=False)
    args = parser.parse_args()

    if args.fix:
        print("All information will be logged to %s" % LOG_FILE)
        fix_python_paths()
        logger.info("=== DONE ===")
    elif args.query:
        print(query_python_paths())
    else:
        parser.print_help()


def main():
    """ Entry point to a main program """
    if os.geteuid() != 0:
        print("You must be root to run this command. Aborting..")
        sys.exit(2)
    else:
        parse_args()


# helper functions
def _create_log_dir(path):
    """ Create folder to store log files """
    if not os.path.exists(os.path.dirname(path)):
        os.mkdir(path)


def _get_perm_octal(path):
    """ Get permissions of the path in octal """
    return oct(os.stat(path).st_mode)[-4:]


def _ensure_valid_permissions(path, expected_perm, default_perm, update=True):
    """ Wrapper function to ensure the correct permissions are set. """
    try:
        current_perm = _get_perm_octal(path)

        if current_perm not in expected_perm:
            try:
                if update:
                    logger.info("Fixing permission for %s. Permissions before %s and after %s" % (
                        path, current_perm, oct(default_perm)))
                    os.chmod(path, default_perm)
                return True
            except Exception as e:
                logger.error(
                    'Failed while trying to change attributes of %s: %s' % (path, str(e)))
    except OSError:
        logger.warn("** Skipping %s from checking (not exist)" % path)


def set_dir_perm(dir):
    """Set directory permissions to a default value provided """
    if (_ensure_valid_permissions(dir, EXPECTED_PERM_OCTAL_DIR, DEFAULT_PERM_DIR)):
        return True


def set_file_perm(file):
    """ Set file permissions to a default value provided """
    if (_ensure_valid_permissions(file, EXPECTED_PERM_OCTAL_FILE, DEFAULT_PERM_FILE)):
        return True


def query_dir_perm(dir):
    """ Return number of directories that require permission fix """
    if (_ensure_valid_permissions(dir, EXPECTED_PERM_OCTAL_DIR, DEFAULT_PERM_DIR, update=False)):
        return True


def query_file_perm(file):
    """ Return number of files that require permission fix """
    if (_ensure_valid_permissions(file, EXPECTED_PERM_OCTAL_FILE, DEFAULT_PERM_FILE, update=False)):
        return True


def query_python_paths():
    """ Return total number of files to apply fix (if any) """
    total = 0

    for item in sys.path:
        if not item.startswith(SKIP_DIR_PATHS):
            for root, dirs, files in os.walk(item):
                for d in dirs:
                    if (query_dir_perm(os.path.join(root, d))):
                        total += 1
                for f in files:
                    if (query_file_perm(os.path.join(root, f))):
                        total += 1
    return total


def fix_python_paths():
    """ Fix dir and files permissions recursively """
    fixed_files, fixed_dirs = 0, 0

    for item in sys.path:
        if not item.startswith(SKIP_DIR_PATHS):
            for root, dirs, files in os.walk(item):
                for d in dirs:
                    if (set_dir_perm(os.path.join(root, d))):
                        fixed_dirs += 1
                for f in files:
                    if (set_file_perm(os.path.join(root, f))):
                        fixed_files += 1

    print("Affected number of directories : %i" % fixed_dirs)
    print("Affected number of files : %i" % fixed_files)
    print("Total number affected: %i " % (fixed_dirs + fixed_files))


if __name__ == "__main__":
    main()
