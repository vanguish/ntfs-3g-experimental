Data deduplication is a feature which has been made available on Windows
Server 2012. This splits the files into chunks and identical chunks from
different files are only stored once, thus avoiding storage redundancy.

Details on data deduplication are available on :
https://technet.microsoft.com/en-us/library/hh831602(v=ws.11).aspx

This archive contains the source code for reading deduplicated files
through ntfs-3g. Only reading is supported, and creating deduplicated files
is not on the agenda, and unlikely to be done in the future.

It has been implemented as a plugin to be used from ntfs-3g, thus retaining
the original organization in Windows. Its loading is delayed until some
deduplicated file is accessed. The minimum version of ntfs-3g which can
use the plugin is 2016.2.22AR.1

For compiling from source, apply the standard procedure :
        ./configure
        make
        # as root :
        make install

The archive also contains the binary plugins for Linux and OpenIndiana
for X86 CPUs in 32-bit and 64-bit modes, and for Linux ARM CPU in 32-bit
mode. They have to be moved to a system directory which depends on the
distribution policy and is defined when ntfs-3g is built. Usually this
is :

/usr/lib/ntfs-3g/ntfs-plugin-80000013.so            for Linux 32-bit
/usr/lib64/ntfs-3g/ntfs-plugin-80000013.so          for Linux 64-bit
/usr/lib/ntfs-3g/ntfs-plugin-80000013.so            for OpenIndiana 32-bit
/usr/lib/amd64/ntfs-3g/ntfs-plugin-80000013.so      for OpenIndiana 64-bit

A simple way to determine the plugin directory is to query where libntfs-3g
is loaded from by running the command (examples below) :
        ldd $(which ntfs-3g)

Another way to determine the directory, is to run the command :
        strings $(which ntfs-3g) | grep ntfs-plugin
This will return the pattern used by ntfs-3g to load the plugin. If you
get something like "/usr/lib64/ntfs-3g/ntfs-plugin-%08lx.so" then the
plugin must be renamed as "/usr/lib64/ntfs-3g/ntfs-plugin-80000013.so".

Either way, if the directory is not present, you have to create it.

Example 1 :

$ ldd $(which ntfs-3g)
        linux-vdso.so.1 (0x00007ffc83dd9000)
        libdl.so.2 => /lib64/libdl.so.2 (0x00007fdfb9486000)
        libpthread.so.0 => /lib64/libpthread.so.0 (0x00007fdfb9269000)
        libntfs-3g.so.872 => /lib64/libntfs-3g.so.872 (0x00007fdfb901c000)
        libc.so.6 => /lib64/libc.so.6 (0x00007fdfb8c5b000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fdfb96af000)

In this case, the fourth output line shows libntfs-3g is loaded from :
        /lib64/libntfs-3g.so.872
so ntfs-plugin-80000013.so must be copied to the directory /lib64/ntfs-3g :
        /lib64/ntfs-3g/ntfs-plugin-80000013.so


Example 2 :

$ ldd $(which ntfs-3g)
        linux-vdso.so.1 (0x7efad000)
        /usr/lib/arm-linux-gnueabihf/libarmmem.so (0x76ee3000)
        libpthread.so.0 => /lib/arm-linux-gnueabihf/libpthread.so.0 (0x76eb4000)
        libntfs-3g.so.861 => /lib/arm-linux-gnueabihf/libntfs-3g.so.861 (0x76e68000)
        libc.so.6 => /lib/arm-linux-gnueabihf/libc.so.6 (0x76d2b000)
        /lib/ld-linux-armhf.so.3 (0x54b53000)

In this case the fourth output line shows libntfs-3g is loaded from :
        /lib/arm-linux-gnueabihf/libntfs-3g.so.861
so ntfs-plugin-80000013.so must be copied to /lib/arm-linux-gnueabihf/ntfs-3g :
        /lib/arm-linux-gnueabihf/ntfs-3g/ntfs-plugin-80000013.so

The plugin should be made executable (permissions 0555) and owned by
root:root on Linux (or root:bin on OpenIndiana).
