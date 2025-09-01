# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = timingmsg

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
  packet-timingmsg.c \
  evt_out.cpp \
  CommonFunctions.cpp \
  Time.cpp

# Non-generated sources
NONGENERATED_C_FILES = \
  $(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES = \
  packet-timingmsg.h \
  evt_out.h \
  CommonFunctions.h \
  Time.h

HEADER_FILES = \
  $(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = timingmsg.la

timingmsg_la_SOURCES = \
  plugin.c \
  moduleinfo.h \
  $(SRC_FILES)  \
  $(HEADER_FILES)

timingmsg_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

timingmsg_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

timingmsg_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
  timingmsg \
  *~

DISTCLEANFILES = \
  plugin.c

MAINTAINERCLEANFILES = \
  Makefile.in

EXTRA_DIST = \
  plugin.rc.in    \
  CMakeLists.txt