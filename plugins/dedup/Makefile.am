ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = README COPYING

plugindir = $(libdir)/ntfs-3g

plugin_LTLIBRARIES = ntfs-plugin-80000013.la

ntfs_plugin_80000013_la_SOURCES =	\
	src/dedup.c

ntfs_plugin_80000013_la_LDFLAGS  = -module -shared -avoid-version
ntfs_plugin_80000013_la_CPPFLAGS = -D_FILE_OFFSET_BITS=64
ntfs_plugin_80000013_la_CFLAGS   = $(LIBNTFS_3G_CFLAGS)
ntfs_plugin_80000013_la_LIBADD   = $(LIBNTFS_3G_LIBS)
