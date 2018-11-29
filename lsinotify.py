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
from optparse import OptionGroup, OptionParser

DEBUG = False


class NamespaceMountTab():
    """
    Collection of file system mounts as seen from a process namespace.
    """
    mounts = list()

    def __init__(self, proc):
        # query mounted file systems in process mount/pid namespace
        mounted_filesystems = subprocess.check_output(
            ["nsenter", "--target", str(proc.get_pid()), "--mount", "--pid",
             "--", "mount"]
        ).split('\n')[:-1]

        # create a NamespaceMount object that can be queried for an inode later
        for line in mounted_filesystems:
            # line will contain something like:
            #   tmpfs on /run type tmpfs (rw,nosuid,nodev,seclabel,mode=755)
            device, _, mountpoint, _, fstype, _ = line.split()
            try:
                self.mounts.append(
                    NamespaceMount(device=device,
                                   mountpoint=mountpoint,
                                   fstype=fstype,
                                   pid=proc.get_pid())
                )
            except subprocess.CalledProcessError:
                # exception thrown when mount point cannot be read, so far
                # this only happend for a gvfs mount... skip for now
                continue

    def get_mount_by_device_number(self, device_number):
        for mount in self.mounts:
            if device_number == mount.get_device_number():
                return mount
        return None


class NamespaceMount():
    """
    File system mount as seen from a process namespace.
    """
    device = None
    device_number = None
    fstype = None
    mountpoint = None
    pid = None

    def __init__(self, device, mountpoint, fstype, pid):
        self.device = device
        self.fstype = fstype
        self.mountpoint = mountpoint
        # store pid-reference for mount
        self.pid = pid

        # query device number of the mounts from within the namespace
        self.device_number = int(subprocess.check_output(
            ["nsenter", "--target", str(pid), "--mount", "--pid", "--",
             "stat", "-c %d", "%s" % mountpoint])
        )

        debug("%s" % self)

    def __str__(self):
        return "NamespaceMount({'device': %s, " % self.device + \
            "'device_number': %x, " % self.device_number + \
            "'mountpoint': '%s', " % self.mountpoint + \
            "'fstype': '%s', " % self.fstype + \
            "'pid': %s})" % self.pid

    def get_device(self):
        return self.device

    def get_device_number(self):
        return self.device_number

    def get_fstype(self):
        return self.fstype

    def get_mountpoint(self):
        return self.mountpoint

    def get_path(self, inode):
        # debugfs is much faster than find, but only available for ext2/3/4
        if self.get_fstype() in ['ext2', 'ext3', 'ext4']:
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

        debug("NamespaceMount.get_path(): cmd = '%s'" % " ".join(cmd))
        debug("NamespaceMount.get_path(): path = %s" % path)

        return path


class FsNotifyHandle():
    """
    Store information about fsnotify handle. See description in section 3.8
    of the kernel proc filesystem documentation at:
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/filesystems/proc.txt?h=linux-3.10.y

    @param info  fdinfo line (e.g. 'inotify wd:4 ino:596 sdev:13 mask:d84 ignored_mask:0 fhandle-bytes:c fhandle-type:1 f_handle:2252865b9605000000000000')
    """
    def __init__(self, info):
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

        proc_details = subprocess.check_output(
            ["ps", "--no-headings", "-o", "state,uid,mntns,pidns",
             "-p", "%s" % self.pid]
        ).split()

        # ignore zombie processes
        if proc_details[0] == 'Z':
            raise IOError("PID %d is a zombie" % self.pid)

        self.uid, self.mount_ns, self.pid_ns = [
            int(result.strip()) for result in proc_details[1:]
        ]

        debug("%s" % self)

    def __str__(self):
        return "Process({'pid': %d, 'uid': %d, " % (self.pid, self.uid) + \
            "'mount_ns': %d, 'pid_ns': %s, " % (self.mount_ns, self.pid_ns) + \
            "'cmdline': '%s'})" % (self.cmdline)

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

    def get_mount_namespace(self):
        return self.mount_ns

    def get_pid(self):
        return self.pid

    def get_pid_namespace(self):
        return self.pid_ns

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
    parser.add_option('-c', '--count', action='store_true', default=False,
                      help='only show total count')
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
    parser.add_option('-p', '--pids', action='store', type='str',
                      metavar='NUM[,NUM]',
                      help='restrict to list of process IDs')
    parser.add_option('-s', '--sort-by', action='store', type='str',
                      metavar='OPTION',
                      help='sort output by given option')
    parser.add_option('-u', '--uid', action='store', type='int', metavar='NUM',
                      help='examine processes of given user ID (root only!)')
    parser.add_option_group(OptionGroup(
        parser,
        "Display options",
        "watch_descriptor    inotify watch descriptor                         "
        "inode               inode of watched file                            "
        "path                path of watched file                             "
        "source_device       source device of watched file                    "
    ))

    (options, args) = parser.parse_args()

    if options.all and options.uid:
        parser.error("cannot use '-a|--all' and '-u|uid' at the same time")

    summary_only = False
    if options.count:
        summary_only = True

    if options.debug:
        global DEBUG
        DEBUG = True

    headers = True
    if options.no_headers:
        headers = False

    if options.pids:
        pids = [int(pid) for pid in options.pids.split(',')]
    else:
        pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]

    sort_by = 'watch_descriptor'
    if options.sort_by:
        sort_by = options.sort_by

    debug("checking PIDs: %s" % ", ".join(str(pid) for pid in pids))

    # by default use UID of executing user
    uid = int(Process().get_uid())
    if options.all:
        uid = None
    if options.uid:
        uid = options.uid

    print_inotify_watches(get_inotify_watches(pids=pids,
                                              restrict_uid=uid),
                          sort_by=sort_by,
                          show_headers=headers,
                          summary_only=summary_only)


def get_inotify_watches(pids, restrict_uid=None):
    namespace_mtabs = {}
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
            debug("get_inotify_watches(): skipping process (PID %d) " % pid +
                  "due to UID restriction")
            continue

        try:
            # query inotify watches of process
            watches = proc.get_fsnotify_watches()
        except IOError:
            # ignore terminated processes
            continue

        if len(watches) == 0:
            debug("get_inotify_watches(): no fsnotify watches found for " +
                  "process (PID %d)" % pid)
            continue

        # get file system mounts per namespace
        ns_mtab_key = (proc.get_mount_namespace(), proc.get_pid_namespace())
        if ns_mtab_key not in namespace_mtabs.keys():
            debug("get_inotify_watches(): create NamespaceMountTab(PID: " +
                  "%d) for ns_mtab_key=%s" % (proc.get_pid(), ns_mtab_key))

            ns_mtab = NamespaceMountTab(proc)
            # cache object in 'namespace_mtabs' to avoid lookup overhead per
            # process mount/pid namespace
            namespace_mtabs[ns_mtab_key] = ns_mtab
        else:
            ns_mtab = namespace_mtabs[ns_mtab_key]

        for watch in watches:
            fsnotify = watch['fsnotify']
            sdev = fsnotify.get_source_device()
            mount = ns_mtab.get_mount_by_device_number(sdev)
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
                          summary_only=False,
                          show_headers=True,
                          sort_by='watch_descriptor'):

    # sort collected watch entries
    output_list = sorted(watches.values(), key=itemgetter(sort_by))

    if len(output_list) > 0:
        if not summary_only:
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

    print("\nNUM_MAX  NUM_TOTAL")
    print("%7d  %9d" % (get_max_user_watches(), len(watches.keys())))


def truncate_string(content, length=87):
    return (content[:length] + '..') \
        if len(content) > (length + 2) else content


if __name__ == "__main__":
    main(sys.argv[1:])


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
