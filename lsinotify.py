#!/usr/bin/python
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
            ["nsenter", "--target", str(pid), "--mount", "--uts", "--ipc", "--net", "--pid", "--", "mount"])
        for mount in fs_mounts.split('\n')[:-1]:
            #            if not mount:
            #                continue
            try:
                self.mounts.append(Mount(mountpoint=mount.split()[2],
                                         fstype=mount.split()[4],
                                         pid=pid))
            except subprocess.CalledProcessError:
                # this will happen when the mount point cannot be read, so far
                # this only happend for a gvfs mount, therefore skip for now
                continue

    def get_mount_by_device_number(self, device_number):
        for mount in self.mounts:
            #            print("get_mount_by_device_number(): mount.device_number = %x/%d <-> device_number = %x/%d" % (mount.device_number, mount.device_number, device_number, device_number))
            if mount.device_number == device_number:
                return mount
        return None


class Mount():
    mountpoint = None
    fstype = None
    device_number = None

    def __init__(self, mountpoint, fstype, pid):
        self.mountpoint = mountpoint
        self.fstype = fstype
        self.device_number = int(subprocess.check_output(["nsenter", "--target", str(
            pid), "--mount", "--uts", "--ipc", "--net", "--pid", "--", "stat", "-c %d", "%s" % mountpoint]))
#        print("%s" % self)

    def get_device_number(self):
        return self.device_number

    def get_mountpoint(self):
        return self.mountpoint

    def __str__(self):
        return "Mount({'mountpoint': '%s', 'fstype': '%s', 'device_number': %x})" % \
            (self.mountpoint, self.fstype, self.device_number)


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

    def __str__(self):
        return "inotify wd:%x ino:%x sdev:%x mask:%x ignored_mask:%x fhandle-bytes:%x fhandle-type:%x f_handle:%x" % \
            (self.watch_descriptor, self.inode, self.source_device, self.mask,
             self.ignored_mask, self.fhandle_bytes, self.fhandle_type, self.fhandle)

    def get_inode(self):
        return self.inode

    def get_path(self, mount):
        #        print("DEBUG : FsNotifyHandle.get_path(mount='%s'): mountpoint = %s") % \
        #              (mount, mount.mountpoint)
        cmd = ["find", "%s" % mount.mountpoint, "-xdev",
               "-inum", "%d" % self.inode, "-print"]
#        print("DEBUG : FsNotifyHandle: cmd = '%s'" % " ".join(cmd))
        path_list = subprocess.check_output(cmd).split('\n')[:-1]
#        print("DEBUG : FsNotifyHandle: path_list = %s" % path_list)
        return path_list[0]

    def get_source_device(self):
        return self.source_device

    def get_watch_descriptor(self):
        return self.watch_descriptor


class Process():

    def __init__(self, pid):
        self.pid = int(pid)
        # this will throw exceptions if process has terminated in the meantime
        with open(os.path.join('/proc', str(self.pid), 'cmdline'), 'r') as cmd_fd:
            self.cmdline = cmd_fd.readline().strip('\n').replace('\0', ' ')
        with open(os.path.join('/proc', str(self.pid), 'uid_map'), 'r') as uid_fd:
            uid_map = uid_fd.readlines()
#        print("DEBUG : pid = %d, uid_map = %s" % (pid, uid_map))
        if len(uid_map) > 0:
            self.real_uid = int(uid_map[0].strip('\n').split()[0])
        else:
            with open(os.path.join('/proc', str(self.pid), 'loginuid'), 'r') as loginuid_fd:
                self.real_uid = int(loginuid_fd.readlines()[0].strip('\n'))

    def __str__(self):
        return "Process({'cmdline': '%s', 'pid': %d, 'real_uid': %d})" % \
            (self.cmdline, self.pid, self.real_uid)

    def get_cmdline(self):
        return self.cmdline

    def get_fsnotify_watches(self):
        watches = list()
        fdinfo = os.path.join('/proc', str(self.pid), 'fdinfo')
        for fd in os.listdir(fdinfo):
            with open(os.path.join(fdinfo, str(fd)), 'r') as fdfd:
                content = fdfd.readlines()
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

    def get_real_uid(self):
        return self.real_uid


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
#    parser.add_option('-n', '--no-headers', action='store_true', default=False,
#                      help='do not print column headers')
#    parser.add_option('-o', '--options', action='store', type='str', metavar='STRING',
#                      help='only show given option columns')
    parser.add_option('-p', '--pids', action='store', type='str', metavar='NUM[,NUM]',
                      help='restrict to list of process IDs')
#    parser.add_options('0s', '--sort-by', action='store', type='str', metavar='OPTION',
#                       help='sort output by given column')
    parser.add_option('-u', '--uid', action='store', type='int', metavar='NUM',
                      help='examine processes of given user ID (root only!)')
    (options, args) = parser.parse_args()

    if options.all and options.uid:
        parser.error("cannot use '-a|--all' and '-u|uid' at the same time")

    if options.debug:
        global DEBUG
        DEBUG = True

    if options.pids:
        pids = [int(pid) for pid in options.pids.split(',')]
    else:
        pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]

    debug("checking PIDs: %s" % ", ".join(str(pid) for pid in pids))

    proc_self = Process(os.getpid())
    uid = proc_self.get_real_uid()
    if options.all:
        uid = None
    if options.uid:
        uid = options.uid

    print_inotify_watches(get_inotify_watches(pids, uid))


def get_inotify_watches(pids, uid=None):
    inotify_watches = {}
    for pid in pids:
        try:
            proc = Process(pid)

            # restrict to given uid
            if uid and (proc.get_real_uid() != int(uid)):
                debug("skipping process (PID %d) due to UID restriction" % pid)
                continue

            watches = proc.get_fsnotify_watches()
            if len(watches) == 0:
                debug("no fsnotify watches found for process (PID %d)" % pid)
                continue

#            print("\nINFO : Cmdline(Pid %d): %s" % (proc.pid, proc.cmdline()))

            # get mount manager per namespace
            mm = MountManager(proc.pid)
            for watch in watches:
                fsnotify = watch['fsnotify']
                sdev = fsnotify.get_source_device()
                mount = mm.get_mount_by_device_number(sdev)
                if not mount:
                    # no idea what's going on here, can't find the corresponding device
                    print("WARN : Cannot find sdev = %x" % sdev)
                    continue
                wd = fsnotify.get_watch_descriptor()
                path = fsnotify.get_path(mount)
                uid = proc.get_real_uid()
                key = (wd, sdev, path, uid)

                # create a unique hash to de-duplicate fsnotify entries
                inotify_hash = hash(key)

                if inotify_hash in inotify_watches:
                    # append process if entry already exists
                    inotify_watches[inotify_hash]['procs'].append({'pid': proc.get_pid(),
                                                                   'cmdline': proc.get_cmdline(),
                                                                   'fd': watch['fd'],
                                                                   'uid': uid})
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
                    inotify_watches[inotify_hash] = watch

        # ignore terminated processes
        except IOError:
            pass

        except OSError as e:
            if e.errno == 13:
                print("error: not allowed to query process with PID %d" %
                      pid, file=sys.stderr)
                sys.exit(1)

    return inotify_watches


def get_max_user_watches():
    return int(subprocess.check_output(["cat", "/proc/sys/fs/inotify/max_user_watches"]).strip())


def print_inotify_watches(watches, sort_by='watch_descriptor', summary=True):
    output_list = sorted(watches.values(), key=itemgetter(sort_by))

    if len(output_list) > 0:
        print("{:<6} {:<7} {:<10} {:<90} {:<4} {:<6} {:<6} {:<50}".format(
            'WD', 'SDEV', 'INODE', 'PATH', 'FD', 'PID', 'UID', 'CMD'
        ))

        for item in output_list:
            for proc_idx in range(0, len(item['procs'])):
                # print(item)
                print("{:<6} {:<7} {:<10} {:<90} {:<4} {:<6} {:<6} {:<50}".format(
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
