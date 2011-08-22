# Copyright (C) 2011 Adriano Monteiro Marques.
#
# Author: Dragos Dena <dragos.dena@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import os
import resource

import signal

# An ID for this daemon: agent or server
ni_target = None

# It should be used with umit_daemon_pidfile % target
umit_daemon_pidfile = '/tmp/umit_ni_%s_pidfile'

# The handler which will be called when the daemon exists
ni_daemon_exit_handler = None
ni_daemon_exit_handler_args = list()


def daemonize(target, exit_handler=None, exit_handler_args=list()):
    """
    Daemonizes the current process on POSIX systems.
    target: An unique ID for the process (server, agent, etc.)
    exit_handler: A optional handler that will be called when the
    daemon exists. It should receive one argument: a list with user
    defined parameters.
    exit_handler_args: A list with the arguments to pass to the exit_handler.
    Returns True on success, False on failure.
    """
    global ni_daemon_exit_handler
    global ni_daemon_exit_handler_args
    global ni_target

    ni_target = target

    # Only running on POSIX systems
    if os.name != 'posix':
        print 'ERROR: Daemonizing failed. Not a POSIX system.'
        return False

    # Test if the daemon is not already running
    if not _pidfile_test(target):
        return False

    try:
        pid1 = os.fork()
    except:
        return False
    
    if pid1 is 0:
        os.setsid()

        # Ignore SIGHUP
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        try:
            pid2 = os.fork()
        except:
            return False
        if pid2 is 0:
            try:
                os.chdir("/")
                os.umask(0)
            except:
                return False
        else:
            os._exit(0)
    else:
        os._exit(0)

    # Close all file descriptors
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if (maxfd == resource.RLIM_INFINITY):
        maxfd = 128
    for fd in range(0, maxfd):
        try:
            os.close(fd)
        except:
            pass

    # Redirect stdin and stdout
    os.open(os.devnull, os.O_RDWR)
    os.open(os.devnull, os.O_RDWR)
    os.open(os.devnull, os.O_RDWR)

    # Create the pidfile
    _write_pidfile(target)

    # Set the handler
    ni_daemon_exit_handler = exit_handler
    ni_daemon_exit_handler_args = exit_handler_args
    signal.signal(signal.SIGTERM, _exit_signal_handler)

    return True


def _exit_signal_handler(signum, frame):
    # Call the user exit function
    if ni_daemon_exit_handler is not None:
        ni_daemon_exit_handler(ni_daemon_exit_handler_args)

    # Clean-up operations
    _daemon_exit(ni_target)


def _daemon_exit(target):
    """
    Called when a daemonized process must exit. Does clean-up
    operations.
    """
    pidfile_path = umit_daemon_pidfile % target
    if os.path.exists(pidfile_path):
        try:
            os.remove(pidfile_path)
        except:
            # File was deleted between these 2 instructions
            pass
    

def _pidfile_test(target):
    """
    Tests if the pidfile exists and if the pid contained is in use.
    If it's not in use, it will delete the pidfile and return True.
    If the file doesn't exist, it will return True.
    If the pid is in use, it will return False.
    """
    pidfile_path = umit_daemon_pidfile % target
    if not os.path.exists(pidfile_path):
        return True

    pidfile = open(pidfile_path, 'r')
    pid_in_use = True

    # Try reading the pid
    try:
        pid = int(pidfile.read())
    except:
        # We don't have a pid here
        pid = None
        pid_in_use = False

    # Check the process with the given pid is running
    if pid is not None:
        try:
            # No signal actually sent
            os.kill(pid, 0)
        except OSError:
            # Process doesn't exist
            pid_in_use = False

    # Try removing the pid file
    if not pid_in_use:
        try:
            os.remove(pidfile_path)
        except:
            # File was already deleted
            pass

    return not pid_in_use


def _write_pidfile(target):
    pidfile_path = umit_daemon_pidfile % target
    pidfile = open(pidfile_path, 'w')
    pidfile.write(str(os.getpid()))
    pidfile.close()