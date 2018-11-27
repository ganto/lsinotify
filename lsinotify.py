#!/usr/bin/python
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# 2018, Reto Gantenbein

from __future__ import print_function

import os
import subprocess
import sys

from operator import itemgetter
from optparse import OptionParser

DEBUG = False


class MountManager():
    mounts = list()

    def __init__(self, pid):
        fs_mounts = subprocess.check_output(
            ["nsenter", "--target", str(pid), "--mount", "--pid", "--",
             "mount"]
        )
        for mount in fs_mounts.split('\n')[:-1]:
            try:
                self.mounts.append(Mount(mountpoint=mount.split()[2], pid=pid))
            except subprocess.CalledProcessError:
                # this will happen when the mount point cannot be read, so far
                # this only happend for a gvfs mount, therefore skip for now
                continue

    def get_mount_by_device_number(self, device_number):
        for mount in self.mounts:
            if mount.device_number == device_number:
                return mount
        return None


class Mount():
    """
    File system mount
    """
    device = None
    device_number = None
    fstype = None
    mountpoint = None
    pid = None

    def __init__(self, mountpoint, pid):
        self.mountpoint = mountpoint
        self.fstype = subprocess.check_output(
            ["nsenter", "--target", str(pid), "--mount", "--pid", "--",
             "findmnt", "--noheadings", "--output", "FSTYPE", "%s" %
             self.mountpoint]
        ).strip()
        self.device = subprocess.check_output(
            ["nsenter", "--target", str(pid), "--mount", "--pid", "--",
             "findmnt", "--noheadings", "--output", "SOURCE", "%s" %
             self.mountpoint]
        ).strip()
        self.device_number = int(subprocess.check_output(
            ["nsenter", "--target", str(pid), "--mount", "--pid", "--",
             "stat", "-c %d", "%s" % mountpoint])
        )
        # store pid-reference for mount
        # TODO: replace with proper namespace handling
        self.pid = pid

        debug("%s" % self)

    def __str__(self):
        return "Mount({'mountpoint': '%s', 'fstype': '%s', 'device_number': %x})" % \
            (self.mountpoint, self.fstype, self.device_number)

    def get_device(self):
        return self.device

    def get_device_number(self):
        return self.device_number

    def get_path(self, inode):
        # debugfs is much faster than find, but only available for ext2/3/4
        if self.fstype in ['ext2', 'ext3', 'ext4']:
            cmd = ["nsenter", "--target", str(self.pid), "--mount", "--pid",
                   "--", "debugfs", self.get_device(), "-R", "ncheck %s" %
                   inode]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            # output will contain something like (in one line):
            #
            #   debugfs 1.44.2 (14-May-2018)\n
            #   Inode\tPathname\n
            #   15\t/lost+found\n
            #
            path_tuple = output.split('\n')[2].split('\t')
            if len(path_tuple) == 2:
                # the path is relative to the mountpoint and starts with '/'
                rel_path = path_tuple[1].lstrip('/')
                path = os.path.join(self.mountpoint, rel_path)
            else:
                # if the inode is the mountpoint itself, the Pathname is empty
                path = self.mountpoint
        else:
            cmd = ["nsenter", "--target", str(self.pid), "--mount", "--pid",
                   "--", "find", "%s" % self.mountpoint, "-xdev", "-inum",
                   "%d" % inode, "-print"]
            path_list = subprocess.check_output(cmd).split('\n')[:-1]
            # if the inode is the mountpoint itself, it can happen, that
            # multiple paths are returned(?!)
            path = path_list[0]

        debug("Mount.get_path() : cmd = '%s'" % " ".join(cmd))
        debug("Mount.get_path() : path = %s" % path)

        return path

    def get_mountpoint(self):
        return self.mountpoint


class FsNotifyHandle():
    '''
    Store information about fsnotify handle. See documentation in section 3.8 at:
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/filesystems/proc.txt?h=linux-3.10.y

    @param info  fdinfo line (e.g. 'inotify wd:4 ino:596 sdev:13 mask:d84 ignored_mask:0 fhandle-bytes:c fhandle-type:1 f_handle:2252865b9605000000000000')
    '''

    def __init__(self, info):
        #    print("DEBUG : %s" % info)
        for item in info.split():
            if item.startswith('inotify'):
                continue
            elif item.startswith('wd'):
                self.watch_descriptor = int(item.split(':')[1], 16)  # hex
            elif item.startswith('ino'):
                self.inode = int(item.split(':')[1], 16)  # hex
            elif item.startswith('sdev'):
                self.source_device = int(item.split(
                    ':')[1].replace('000', ''), 16)  # hex
            elif item.startswith('mask'):
                self.mask = int(item.split(':')[1], 16)  # hex
            elif item.startswith('ignored_mask'):
                self.ignored_mask = int(item.split(':')[1], 16)  # hex
            elif item.startswith('fhandle-bytes'):
                self.fhandle_bytes = int(item.split(':')[1], 16)  # hex
            elif item.startswith('fhandle-type'):
                self.fhandle_type = int(item.split(':')[1], 16)  # hex
            elif item.startswith('f_handle'):
                self.fhandle = int(item.split(':')[1], 16)  # hex

        debug("FsNotifyHandle(%s)" % self)

    def __str__(self):
        return "inotify wd:%x ino:%x sdev:%x " % \
            (self.watch_descriptor, self.inode, self.source_device) + \
            "mask:%x ignored_mask:%x fhandle-bytes:%x fhandle-type:%x " % \
            (self.mask, self.ignored_mask, self.fhandle_bytes,
             self.fhandle_type) + "f_handle:%x" % self.fhandle

    def get_inode(self):
        return self.inode

    def get_path(self, mount):
        return mount.get_path(self.inode)

    def get_source_device(self):
        return self.source_device

    def get_watch_descriptor(self):
        return self.watch_descriptor


class Process():
    """
    Represents an Linux process with the given PID (process id).
    """

    def __init__(self, pid=os.getpid()):
        self.pid = int(pid)

        # this will throw exceptions if process has terminated in the meantime
        with open(os.path.join('/proc',
                               str(self.pid),
                               'cmdline'), 'r') as cmd_fd:
            # cmdline arguments are \0 seperated
            self.cmdline = cmd_fd.readline().replace('\0', ' ').strip()

        self.uid = int(subprocess.check_output(
            ["ps", "--no-headings", "-o", "uid", "-p", "%d" % self.pid]
        ).strip())

        debug("%s" % self)

    def __str__(self):
        return "Process({'cmdline': '%s', 'pid': %d, 'uid': %d})" % \
            (self.cmdline, self.pid, self.uid)

    def get_cmdline(self):
        return self.cmdline

    def get_fsnotify_watches(self):
        watches = list()
        fdinfo = os.path.join('/proc', str(self.pid), 'fdinfo')

        for fd in os.listdir(fdinfo):
            with open(os.path.join(fdinfo, str(fd)), 'r') as fdinfo_fd:
                content = fdinfo_fd.readlines()
            for line in content:
                if "inotify" in line:
                    info = {'fd': fd}
                    info['path'] = os.readlink(os.path.join(
                        '/proc', str(self.pid), 'fd', fd))
                    info['fsnotify'] = FsNotifyHandle(line.strip())
                    watches.append(info)
        return watches

    def get_pid(self):
        return self.pid

    def get_uid(self):
        return self.uid


def debug(msg):
    if DEBUG:
        print("DEBUG : %s" % msg, file=sys.stderr)


def main(argv=None):
    usage = "Usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-a', '--all', action='store_true', default=False,
                      help='examine processes of all users (root only!)')
#    parser.add_option('-c', '--count', action='store_true', default=False,
#                      help='only show total count')
    parser.add_option('-d', '--debug', action='store_true', default=False,
                      help='print debug messages')
#    parser.add_option('-f', '--format', action='store', type='str', metavar='FORMAT',
#                      help="format output (default: 'column')")
#    parser.add_option('-l', '--limit', action='store', type='str', metavar='OPT=VAL',
#                      help='limit output to match given option/value')
    parser.add_option('-n', '--no-headers', action='store_true', default=False,
                      help='do not print column headers')
#    parser.add_option('-o', '--options', action='store', type='str', metavar='STRING',
#                      help='only show given option columns')
    parser.add_option('-p', '--pids', action='store', type='str', metavar='NUM[,NUM]',
                      help='restrict to list of process IDs')
#    parser.add_options('-s', '--sort-by', action='store', type='str', metavar='OPTION',
#                       help='sort output by given column')
    parser.add_option('-u', '--uid', action='store', type='int', metavar='NUM',
                      help='examine processes of given user ID (root only!)')
    (options, args) = parser.parse_args()

    if options.all and options.uid:
        parser.error("cannot use '-a|--all' and '-u|uid' at the same time")

    if options.debug:
        global DEBUG
        DEBUG = True

    if options.no_headers:
        headers = False
    else:
        headers = True

    if options.pids:
        pids = [int(pid) for pid in options.pids.split(',')]
    else:
        pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]

    debug("checking PIDs: %s" % ", ".join(str(pid) for pid in pids))

    # by default use UID of executing user
    uid = int(Process().get_uid())
    if options.all:
        uid = None
    if options.uid:
        uid = options.uid

    print_inotify_watches(get_inotify_watches(pids=pids,
                                              restrict_uid=uid),
                          show_headers=headers)


def get_inotify_watches(pids, restrict_uid=None):
    inotify_watches = {}
    for pid in pids:
        try:
            proc = Process(pid)

        # ignore terminated processes
        except IOError:
            pass

        except OSError as e:
            if e.errno == 13:
                print("error: not allowed to query process with PID %d" %
                      pid, file=sys.stderr)
                sys.exit(1)

        debug("get_inotify_watches(): pid = %d, restrict_uid = %s, uid = %d" %
              (pid, restrict_uid, proc.get_uid()))

        # restrict to given uid
        if (restrict_uid is not None) and (restrict_uid != proc.get_uid()):
            debug("get_inotify_watches(): skipping process (PID %d)" % pid +
                  "due to UID restriction")
            continue

        try:
            watches = proc.get_fsnotify_watches()
        # ignore terminated processes
        except IOError:
            continue

        if len(watches) == 0:
            debug("get_inotify_watches(): no fsnotify watches found for " +
                  "process (PID %d)" % pid)
            continue

        # get mount manager per namespace
        mm = MountManager(proc.pid)
        for watch in watches:
            fsnotify = watch['fsnotify']
            sdev = fsnotify.get_source_device()
            mount = mm.get_mount_by_device_number(sdev)
            if not mount:
                # no idea what's going on here, can't find the corresponding
                # device
                print("WARN : Cannot find sdev = %x" % sdev)
                continue

            wd = fsnotify.get_watch_descriptor()
            path = fsnotify.get_path(mount)
            uid = proc.get_uid()
            key = (wd, sdev, path, uid)

            # create a unique hash to de-duplicate fsnotify entries
            inotify_hash = hash(key)

            if inotify_hash in inotify_watches:
                # append fd/process details if entry already exists
                fd_info = {'pid': proc.get_pid(),
                           'cmdline': proc.get_cmdline(),
                           'fd': watch['fd'],
                           'uid': uid}

                debug("get_inotify_watches(): update inotify watch entry " +
                      "'%s': %s" % (inotify_hash, fd_info))

                inotify_watches[inotify_hash]['procs'].append(fd_info)

            else:
                # create new entry
                watch = {
                    'watch_descriptor': wd,
                    'source_device': sdev,
                    'path': path,
                    'inode': fsnotify.get_inode(),
                    'procs': [{
                        'pid': proc.get_pid(),
                        'cmdline': proc.get_cmdline(),
                        'fd': watch['fd'],
                        'uid': uid,
                    }]
                }

                debug("get_inotify_watches(): create inotify watch entry " +
                      "'%s': %s" % (inotify_hash, watch))

                inotify_watches[inotify_hash] = watch

    return inotify_watches


def get_max_user_watches():
    return int(subprocess.check_output(
        ["cat", "/proc/sys/fs/inotify/max_user_watches"]
    ).strip())


def print_inotify_watches(watches,
                          show_headers=True,
                          sort_by='watch_descriptor',
                          summary=True):

    # sort collected watch entries
    output_list = sorted(watches.values(), key=itemgetter(sort_by))

    if len(output_list) > 0:
        if show_headers:
            print("{:<6} {:<7} {:<10} {:<90} {:<4} {:<6} {:<8} {:<50}".format(
                'WD', 'SDEV', 'INODE', 'PATH', 'FD', 'PID', 'UID', 'CMD'
            ))

        for item in output_list:
            for proc_idx in range(0, len(item['procs'])):
                # TODO: make width depending on item length
                print("{:<6} {:<7} {:<10} {:<90} {:<4} {:<6} {:<8} {:<50}".format(
                    hex(item['watch_descriptor']),
                    hex(item['source_device']),
                    hex(item['inode']),
                    truncate_string(item['path']),
                    item['procs'][proc_idx]['fd'],
                    item['procs'][proc_idx]['pid'],
                    item['procs'][proc_idx]['uid'],
                    truncate_string(item['procs'][proc_idx]['cmdline'], 47)
                ))
    else:
        print("no inotify watches found", file=sys.stderr)

    if summary:
        print("\nNUM_MAX  NUM_TOTAL")
        print("%7d  %9d" % (get_max_user_watches(), len(watches.keys())))


def truncate_string(content, length=87):
    return (content[:length] + '..') if len(content) > 88 else content


if __name__ == "__main__":
    main(sys.argv[1:])


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
