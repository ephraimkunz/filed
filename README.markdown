**What I'm doing:**
Porting this project to macOS. Once the basics are done, I'll do some profiling to 
choose compile-time constants and fix hotspots. I'll also write some unit tests and
modernize the code a bit.

**Why I'm doing this:**
It seems like a fun project with a slightly larger C program. I was impressed by the 
clear, simple code of the original project and want to use it to learn to be a better
systems programmer. This will give me an opportunity to apply some software analysis
knowledge I'm learning in my master's program. Later I may use this as an extended 
"Hello World" example and do such things as implement it in Rust and compare performance
characteristics / ease of coding / correctness.


filed Original README
=====

Introduction
------------
"filed" is a simple HTTP server for serving local static files over HTTP from
Linux. It does the least amount of effort possible to get to the point of
handing the actual transfer over to the kernel.

It is multithreaded where every thread services a single concurrent client.
It attempts to reduce latency by caching open file descriptors as well.

It has no configuration file and supports only minimal configuration.
Operation is described in the manual page.

Usage
-----
The simplest usage of "filed" is to run it with no arguments.  This will start
up an HTTP server listening on port 80 and sharing out the root filesystem for
the system as the current user.  You probably do not want to share out your
root filesystem since that will expose information such as "/etc/passwd" to
anonymous access.  You probably also don't want to do that as root since then
sensitive information such as "/etc/shadow" could be used to compromise the
system.

Therefore, the "--user" and "--root" options should be used to specify a user
for "filed" to run as in addition to a directory to change root (chroot(2)) to
prior to serving out files.

Example 1, insecure file sharing:
	$ filed

Example 2, sharing sensitive information:
	# filed

Example 3, sharing only a specific directory:
	# filed --root /www --user nobody

Example 4, running as a daemon:
	# filed --root /www --user nobody --daemon

Build Time Considerations
-------------------------
In general, it is best to leave all configuration to run-time so that a
compiled binary can do as much as possible without needing to be recompiled.
However, there are some things that are best done at compile time for
various reasons, especially in the name of performance or executable size.

filed admits those trade-offs are occasionally required and offers the
following tunables that can only be toggled during compile-time:

   1. Logging (CFLAGS, -DFILED_DONT_LOG=1)
	It is possible to disable ALL logging from filed.  When logging is
	completely disabled interlocks (mutexes) for the logging pointer are
	not engaged and the logging functions are not compiled at all.
	This results in a slightly smaller and faster binary

   2. Kill idle connections (CFLAGS, -DFILED_DONT_TIMEOUT=1)
        Killing idle connections relies heavily upon C11 atomics.  This
        requires a relatively new version of GCC (4.9+) or other C compiler
        that implements this aspect of C11 and so it can be disabled at
        compile time (which is the only time it makes sense).  One day an
        alternate implementation might be present that uses a mutex instead
        of atomics at which point this documentation will be updated.

   3. Debugging (CFLAGS, -DFILED_DEBUG=1)
	This is an internal option and should only be used during development.

   4. Differing HTTP semantics (CFLAGS, -DFILED_NONBLOCK_HTTP=1)
	It is possible that some HTTP clients may not process the HTTP stream
	being delivered if they cannot write to the HTTP stream itself.  This
	has not been observed yet, but it is possible.  If these semantics are
	needed (and they should not be) then they can be enabled with this
	flag at the cost of performance.

   5. Differing chroot() semantics (CFLAGS, -DFILED_FAKE_CHROOT=1)
        In some cases it is desirable to mangle paths with a path prefix
        rather than call chroot() at startup.  This is less secure and slower
        and should be generally avoided -- however it may be necessary to do.
        In these cases the executable may be compiled with the
        FILED_FAKE_CHROOT C preprocessor macro defined and instead of calling
        chroot() all HTTP requests will have the root suffix specified as the
        argument to the "-r" or "--root" option prepended to them.

   6. Differing "index.html" handling (CFLAGS, -DFILED_DONT_REDIRECT_DIRECTORIES=1)
        Normally "filed" redirects users who request a directory to the
        index.html file in that directory so that no memory allocations are
        required;  This option lets the server generate the new path.

   7. MIME Types (MIMETYPES)
	For single-file convenience "filed" compiles the mapping of file
	extensions (the string in the filename following its last dot ("."))
	into the executable.  This mapping comes from a file in the format of
		type1   type1_extension1 type1_extension2...
		type2   type2_extension1 type2_extension2...
		...
	However it may not be desirable to include this mapping, or it may be
	desirable to use your own mapping rather than the default one.  This
	can be done by specifying the MIMETYPES macro to "make".  If no
	mapping is desired, "/dev/null" may be specified.

Log Files
---------
Because "filed" relies on chroot(2) and setuid(2), log files cannot reliably
be re-opened.  If you need log rotation then a second process, which can close
and re-open log files, must be used.  Any process may be used for writing logs
but if the process does not support log rotation then it will not provide that
benefit.  For example, if you wish to write logs to syslogd(8) you can use
logger(1), such as:
	# ./filed --root /www --user nobody --log '|logger -t filed' --daemon

Troubleshooting
---------------
   1. It won't compile, something about stdatomic.h not found or _Atomic not
      a valid type.

      => This is a bug in your compiler:
            https://gcc.gnu.org/bugzilla/show_bug.cgi?id=58016

         GCC 4.7.x and 4.8.x define the macro indicating that they have C11
         support and do not define the macro that C11 requires to indicate
         that C11 atomics are not available.  They should define that macro.

         You can disable the features in "filed" that require C11 atomics by
         defining FILED_DONT_TIMEOUT in the Makefile.
