AC_INIT([tests], 0.0.1)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_MACRO_DIR([config])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT

AC_CHECK_HEADERS([ \
	sys/types.h unistd.h fcntl.h strings.h pthread.h time.h \
	errno.h stdarg.h limits.h signal.h stdlib.h
])

AC_CHECK_LIB(pthread, pthread_create)


AC_OPENMP

# be silent by default
AM_SILENT_RULES([yes])

AC_PROG_LIBTOOL
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_FILES([
    Makefile
])

AC_OUTPUT
