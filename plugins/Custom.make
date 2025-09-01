_CUSTOM_SUBDIRS_ = \
  timingmsg \
  etherbone

_CUSTOM_EXTRA_DIST_ = \
  Custom.m4 \
  Custom.make

_CUSTOM_plugin_ldadd_ = \
  -dlopen plugins/epan/timingmsg/timingmsg.la \
  -dlopen plugins/epan/timingmsg/etherbone.la
