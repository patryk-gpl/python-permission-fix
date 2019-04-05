# python-permission-fix

Ansible role to fix permissions to all Python packages installed system-wide.

It can be applied to systems where very restrictive policy has been applied, for example `umask`
caused regular user do not have `read` permissions to certain Python files.
