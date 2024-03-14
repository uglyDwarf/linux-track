if DARWIN
  SLEOPARD_LDFLAG = -headerpad_max_install_names
  DARWINFLAGS = -undefined dynamic_lookup
  SYSFLAGS = -DIBM=0 -DAPL=1 -DLIN=0
  #If ltr_server is not linked against CoreFoundation, loading libusb-1.0 would
  #  cause SIG_TRAP, since CoreFoundation expects the init takes place
  #  in the main thread. Linking ltr_server against CoreFoundation solves that.
  LTR_SERVER_FLAGS = -framework CoreFoundation
  QMAKE_FLAGS = -spec macx-g++
  LIBLINUXTRACK_FLAGS = -fpic -fPIC -arch i386 -arch x86_64
  XLINUXTRACK_CFLAGS = -arch i386 -arch x86_64
  XLINUXTRACK_LDFLAGS = -Wl,-no_arch_warnings -arch i386 -arch x86_64
  LINUXFLAGS =
  LINUXLDFLAGS =
  ltr_pipe_CPPFLAGS =
  FT_LDFLAGS =
else
  LINUXFLAGS = '-DLIB_PATH="$(pkglibdir)/"'
  LINUXLDLFAGS = '-Wl,-rpath,$(pkglibdir)'
  SYSFLAGS = -DIBM=0 -DAPL=0 -DLIN=1
  QMAKE_FLAGS = -spec linux-g++
  LIBLINUXTRACK_FLAGS = -fpic -fPIC
  LTR_SERVER_FLAGS =
  XLINUXTRACK_CFLAGS =
  XLINUXTRACK_LDFLAGS =  -L/lib32 -L/usr/lib32 -Wl,--no-warn-search-mismatch
  ltr_pipe_CPPFLAGS = -DLINUX
  FT_LDFLAGS = '-Wl,-rpath,$(libdir)'
endif

man_MANS = ltr_gui.1 ltr_server1.1 mickey.1

pkglib_LTLIBRARIES = libltr.la libmacwii.la liblinuxtrack.la
bin_PROGRAMS = ltr_server1
dist_pkgdata_DATA = linuxtrack1.conf linuxtrack.c linuxtrack_hello_world.c linuxtrack_hello_world_adv.c

l32libdir = $(prefix)/$(LIB32DIR)/linuxtrack

if ! DARWIN
if X64
if LTR32ON64
  l32lib_LTLIBRARIES = liblinuxtrack32.la
endif
endif
endif

liblinuxtrack32_la_SOURCES = ltlib.c linuxtrack.h utils.c utils.h \
  ipc_utils.c ipc_utils.h
liblinuxtrack32_la_CFLAGS = $(LINUXFLAGS) -m32
liblinuxtrack32_la_LDFLAGS = -export-symbols "${srcdir}/liblt.sym" -m32 $(LINUXLDFLAGS)

noinst_LTLIBRARIES = liblinuxtrack_int.la #libfacetrack_int.la
liblinuxtrack_int_la_SOURCES = linuxtrack.c linuxtrack.h
libfacetrack_int_la_SOURCES = facetrack.cpp facetrack.h
libfacetrack_int_la_CFLAGS = $(OPENCV_CFLAGS)
libfacetrack_int_la_CXXFLAGS = $(OPENCV_CFLAGS)

ltr_server1_SOURCES = ltr_srv_comm.c ltr_srv_comm.h ltr_srv_slave.c ltr_srv_slave.h \
	ltr_srv_master.cpp ltr_srv_master.h ltr_server1.c ipc_utils.c ipc_utils.h
ltr_server1_CFLAGS = ${AM_CFLAGS} $(LINUXFLAGS)
ltr_server1_LDADD = -lpthread libltr.la
ltr_server1_LDFLAGS = $(LINUXLDFLAGS) ${SLEOPARD_LDFLAG} ${LTR_SERVER_FLAGS}

if ! DARWIN
pkglib_LTLIBRARIES += libjoy.la
endif

if CWIID
  pkglib_LTLIBRARIES += libwii.la
  man_MANS += wii_server.1
endif

if OSC_SUPPORT
  bin_PROGRAMS += osc_server
endif

if WEBCAM_SUPPORT
  pkglib_LTLIBRARIES += libwc.la
endif

bin_PROGRAMS += ltr_recenter

ltr_recenter_SOURCES = ltr_recenter.c ipc_utils.h ltr_srv_comm.c ltr_srv_comm.h
ltr_recenter_CFLAGS = ${AM_CFLAGS} $(LINUXFLAGS)
ltr_recenter_LDADD = -ldl liblinuxtrack.la libltr.la
ltr_recenter_LDFLAGS = $(LINUXLDFLAGS) ${SLEOPARD_LDFLAG} -pthread

# libmxml are mandatory for the GUI, so this can be added directly
bin_PROGRAMS += ltr_extractor
man_MANS += ltr_extractor.1

ltr_extractor_SOURCES = hashing.c digest.c digest.h game_data.c game_data.h utils.c utils.h extract.c extract.h
ltr_extractor_CFLAGS = ${AM_CFLAGS} $(LINUXFLAGS) -Iqt_gui
ltr_extractor_LDADD = -lmxml
ltr_extractor_LDFLAGS = $(LINUXLDFLAGS) ${SLEOPARD_LDFLAG} -pthread

if TRACKIR_SUPPORT
  pkglib_LTLIBRARIES += libtir.la libltusb1.la
  dist_pkgdata_DATA += 99-TIR.rules 99-Mickey.rules
endif

if FACE_TRACKER
  pkglib_LTLIBRARIES += libft.la libp3eft.la
  dist_pkgdata_DATA += haarcascade_frontalface_alt2.xml
  noinst_LTLIBRARIES += libfacetrack_int.la
endif

pkglib_LTLIBRARIES += libfakeusb.la libp3e.la

include_HEADERS = linuxtrack.h

liblinuxtrack_la_SOURCES =  ../config.h linuxtrack.h utils.h ipc_utils.h ltlib.h \
                            ltlib.c utils.c ipc_utils.c
liblinuxtrack_la_CFLAGS = ${AM_CFLAGS} $(LIBLINUXTRACK_FLAGS) $(LINUXFLAGS)
liblinuxtrack_la_LDFLAGS = -export-symbols "${srcdir}/liblt.sym" ${SLEOPARD_LDFLAG}

libltr_la_SOURCES = ../config.h cal.c cal.h list.c list.h dyn_load.c dyn_load.h\
  math_utils.c math_utils.h pose.c pose.h pref.cpp pref.hpp pref.h pref_bison.ypp \
  pref_bison.hpp pref_flex.lpp pref_global.c pref_global.h \
  utils.c utils.h image_process.c image_process.h tracking.c tracking.h \
  ltlib_int.c ltlib_int.h spline.c spline.h axis.c axis.h wii_driver_prefs.c \
  wii_driver_prefs.h tir_driver_prefs.c tir_driver_prefs.h wc_driver_prefs.c \
  wc_driver_prefs.h ipc_utils.c ipc_utils.h com_proc.c com_proc.h wii_com.c wii_com.h \
  joy_driver_prefs.c joy_driver_prefs.h ps3_prefs.c ps3_prefs.h
libltr_la_LIBADD = -lm -lpthread -ldl
libltr_la_LDFLAGS = -export-symbols-regex '^ltr_int' ${SLEOPARD_LDFLAG} ${AM_CFLAGS} $(LINUXLDFLAGS)
libltr_la_CFLAGS = ${AM_CFLAGS} $(LINUXFLAGS)
libltr_la_CXXFLAGS = ${AM_CFLAGS} $(LINUXFLAGS)

libtir_la_SOURCES = tir.h tir_hw.c tir_hw.h sn4_com.h \
    tir_img.c tir_img.h usb_ifc.h tir_driver.h tir_driver.c runloop.c runloop.h
libtir_la_LIBADD = -lz libltr.la
libtir_la_LDFLAGS = -export-symbols "${srcdir}/tir.sym" $(LINUXLDFLAGS) ${SLEOPARD_LDFLAG}

libjoy_la_SOURCES = runloop.c runloop.h joy.c
libjoy_la_LDFLAGS = -export-symbols "${srcdir}/joy_driver.sym" $(LINUXLDFLAGS)

libltusb1_la_SOURCES = libusb_ifc.c usb_ifc.h
libltusb1_la_CFLAGS = ${AM_CFLAGS}
libltusb1_la_LIBADD = -lusb-1.0 libltr.la
libltusb1_la_LDFLAGS = ${SLEOPARD_LDFLAG} $(LINUXLDFLAGS)
#libltopenusb_la_SOURCES = openusb_ifc.c usb_ifc.h
#libltopenusb_la_CFLAGS = ${AM_CFLAGS}
#libltopenusb_la_LIBADD = -lopenusb libltr.la
#libltopenusb_la_LDFLAGS = ${SLEOPARD_LDFLAG} $(LINUXLDFLAGS)
libfakeusb_la_SOURCES = fakeusb.c usb_ifc.h tir_model.cpp tir_model.h tir4_model.cpp \
                        sn4_model.cpp sn3_model.cpp
libfakeusb_la_CFLAGS = ${AM_CFLAGS}
libfakeusb_la_CXXFLAGS = ${AM_CFLAGS}
libfakeusb_la_LIBADD = libltr.la
libfakeusb_la_LDFLAGS = ${SLEOPARD_LDFLAG} ${AM_CFLAGS} $(LINUXLDFLAGS)

libwii_la_SOURCES = wiimote_driver.c wiimote_driver.h runloop.c runloop.h
libwii_la_CFLAGS = ${AM_CFLAGS}
libwii_la_LIBADD = -lcwiid libltr.la
libwii_la_LDFLAGS = -export-symbols "${srcdir}/drivers.sym" ${SLEOPARD_LDFLAG} $(LINUXLDFLAGS)

libmacwii_la_SOURCES = macwii_driver.c wii_com.h com_proc.h \
  runloop.c runloop.h wii_driver_prefs.c wii_driver_prefs.h ipc_utils.h
libmacwii_la_CFLAGS = ${AM_CFLAGS} -I${srcdir} -I${srcdir}/mac -I..
libmacwii_la_LIBADD = libltr.la
libmacwii_la_LDFLAGS = -export-symbols "${srcdir}/drivers.sym" ${AM_CFLAGS} ${SLEOPARD_LDFLAG}

libwc_la_SOURCES = webcam_driver.c webcam_driver.h runloop.c runloop.h
libwc_la_CFLAGS = ${AM_CFLAGS}
libwc_la_LIBADD = libltr.la -lv4l2
libwc_la_LDFLAGS = -export-symbols "${srcdir}/webcam_driver.sym" ${SLEOPARD_LDFLAG} $(LINUXLDFLAGS)

if DARWIN
  pkglib_LTLIBRARIES += libmacwc.la
endif

libmacwc_la_SOURCES = macwebcam_driver.c com_proc.h runloop.c runloop.h ipc_utils.h
libmacwc_la_CFLAGS = ${AM_CFLAGS} ${SLEOPARD_CFLAG}
libmacwc_la_LIBADD = libltr.la
libmacwc_la_LDFLAGS = -export-symbols "${srcdir}/drivers.sym" ${AM_CFLAGS} ${SLEOPARD_LDFLAG}

libft_la_SOURCES = webcam_driver.c webcam_driver.h runloop.c runloop.h facetrack.cpp facetrack.h
libft_la_CFLAGS = ${AM_CFLAGS} -DOPENCV $(OPENCV_CFLAGS)
libft_la_CXXFLAGS = ${AM_CFLAGS} -DOPENCV $(OPENCV_CFLAGS)
libft_la_LIBADD = libltr.la -lv4l2 -lpthread $(OPENCV_LIBS)
libft_la_LDFLAGS = -export-symbols "${srcdir}/webcam_driver.sym" ${SLEOPARD_LDFLAG} $(LINUXLDFLAGS) $(FT_LDFLAGS)

libp3e_la_SOURCES = ps3eye_driver.c ps3eye_driver.h runloop.c runloop.h
libp3e_la_CFLAGS = ${AM_CFLAGS}
libp3e_la_LIBADD = libltr.la
libp3e_la_LDFLAGS = -export-symbols "${srcdir}/ps3eye.sym" ${SLEOPARD_LDFLAG} $(LINUXLDFLAGS)

libp3eft_la_SOURCES = ps3eye_driver.c ps3eye_driver.h runloop.c runloop.h facetrack.cpp facetrack.h
libp3eft_la_CFLAGS = ${AM_CFLAGS} -DOPENCV $(OPENCV_CFLAGS)
libp3eft_la_CXXFLAGS = ${AM_CFLAGS} -DOPENCV $(OPENCV_CFLAGS)
libp3eft_la_LIBADD = libltr.la -lv4l2 -lpthread $(OPENCV_LIBS)
libp3eft_la_LDFLAGS = -export-symbols "${srcdir}/ps3eye.sym" ${SLEOPARD_LDFLAG} $(LINUXLDFLAGS) $(FT_LDFLAGS)

man_MANS += ltr_pipe.1
bin_PROGRAMS += ltr_pipe
ltr_pipe_CPPFLAGS += -D_GNU_SOURCE
ltr_pipe_SOURCES = ../config.h ltr_pipe.c linuxtrack.h utils.h utils.c linuxtrack.c
ltr_pipe_CFLAGS = ${AM_CFLAGS} $(LINUXFLAGS)
ltr_pipe_LDFLAGS = $(LINUXLDFLAGS) ${LTR_PIPE_FLAGS} -ldl

osc_server_SOURCES = osc_server.c linuxtrack.h linuxtrack.c
osc_server_CFLAGS = ${AM_CFLAGS} $(LINUXFLAGS)
osc_server_LDFLAGS = $(LINUXLDFLAGS) -pthread -llo -ldl

if XPLANE_PLUGIN
pkglib_LTLIBRARIES += xlinuxtrack9.la
if LTR32ON64
  pkglib_LTLIBRARIES += xlinuxtrack9_32.la
  xlinuxtrack9_32_la_SOURCES = xlinuxtrack9.c linuxtrack.c linuxtrack.h
  xlinuxtrack9_32_la_CFLAGS = ${XPL_CPPFLAGS} $(SYSFLAGS) \
    -fPIC -m32 $(DARWINCFLAGS) ${AM_CFLAGS} $(LINUXFLAGS) ${XLINUXTRACK_CFLAGS}
  xlinuxtrack9_32_la_LDFLAGS = -module -shared -fPIC -m32 $(DARWINFLAGS) -dynamiclib \
    -export-symbols "${srcdir}/xlinuxtrack.sym" $(LINUXLDFLAGS) ${SLEOPARD_LDFLAG} ${XLINUXTRACK_LDFLAGS}
  xlinuxtrack9_32_la_LIBADD = -lm -ldl
endif
xlinuxtrack9_la_SOURCES = xlinuxtrack9.c linuxtrack.c linuxtrack.h
xlinuxtrack9_la_CFLAGS = ${XPL_CPPFLAGS} $(SYSFLAGS) \
  -fPIC $(DARWINCFLAGS) ${AM_CFLAGS} $(LINUXFLAGS) ${XLINUXTRACK_CFLAGS}
xlinuxtrack9_la_LDFLAGS = -module -shared -fPIC $(DARWINFLAGS) -dynamiclib \
  -export-symbols "${srcdir}/xlinuxtrack.sym" $(LINUXLDFLAGS) ${SLEOPARD_LDFLAG} ${XLINUXTRACK_LDFLAGS}
xlinuxtrack9_la_LIBADD = -lm -ldl
endif

AM_YFLAGS = -d --name-prefix ltr_int_parser_
AM_LFLAGS = -i
BUILT_SOURCES = pref_flex.cpp pref_bison.cpp pref_bison.hpp

#dirty hack to allow usage of automake > 1.12,
#  that changed naming of headers generated by bison
#  without a way to revert to the backwards compatible behavior.
#  Everyone can install automake 1.12 is not an argument.
#.hpp.h:
#	cp $< $@

#dirty hack to integrate qt_gui

clean-local: clean-local-check
.PHONY: clean-local-check
clean-local-check:
	-cd qt_gui;$(MAKE) clean; rm -f help.qch help.qhc
	-cd mickey;$(MAKE) clean; rm -f help.qch help.qhc
	-cd wii_server;$(MAKE) clean

distclean-local: distclean-local-check
.PHONY: distclean-local-check
distclean-local-check:
	-cd qt_gui;$(MAKE) distclean; rm -f help.qch help.qhc
	-cd mickey;$(MAKE) distclean; rm -f help.qch help.qhc
	-cd wii_server;$(MAKE) distclean


.PHONY: LTR_QT_GUI_TARGET_INST LTR_QT_GUI_TARGET_UNINST \
  LTR_MICKEY_TARGET_INST LTR_MICKEY_TARGET_UNINST \
  LTR_WII_TARGET_INST LTR_WII_TARGET_UNINST

noinst_SCRIPTS = qt_gui/ltr_gui
hook_inst_targets = LTR_QT_GUI_TARGET_INST
hook_uninst_targets = LTR_QT_GUI_TARGET_UNINST

if MICKEY
  noinst_SCRIPTS += mickey/mickey
  hook_inst_targets += LTR_MICKEY_TARGET_INST
  hook_uninst_targets += LTR_MICKEY_TARGET_UNINST
endif

if CWIID
  noinst_SCRIPTS += wii_server/wii_server
  hook_inst_targets += LTR_WII_TARGET_INST
  hook_uninst_targets += LTR_WII_TARGET_UNINST
endif

qt_gui/help.qhc qt_gui/help.qch : qt_gui/ltr_gui.qhcp qt_gui/ltr_gui.qhp qt_gui/help/xpl_setup.htm \
  qt_gui/help/extractor.htm qt_gui/help/misc.htm qt_gui/help/news.htm qt_gui/help/dev_setup.htm \
  qt_gui/help/interface.htm qt_gui/help/axes_setup.htm qt_gui/help/mickey.htm qt_gui/help/model_setup.htm \
  qt_gui/help/hall_of_fame.htm qt_gui/help/wine.htm qt_gui/help/welcome.htm \
  qt_gui/help/Wiimote.png qt_gui/help/KeysSetup1.png qt_gui/help/JoyButtonsSetup1.png \
  qt_gui/help/XplBrowse.png qt_gui/help/Webcam.png qt_gui/help/Extractor.png qt_gui/help/XplInstall.png \
  qt_gui/help/Misc.png qt_gui/help/DetAxis.png qt_gui/help/JoyButtonsSetup4.png qt_gui/help/JoyButtonsSetup5.png \
  qt_gui/help/3dPreview.png qt_gui/help/ModelCreate.png qt_gui/help/JoyButtonsSetup3.png qt_gui/help/CamPreview.png \
  qt_gui/help/Tracking.png qt_gui/help/JoyButtonsSetup2.png qt_gui/help/Model.png qt_gui/help/Trackir.png \
  qt_gui/help/Controller.png qt_gui/help/Facetracker.png
	pushd qt_gui; qcollectiongenerator -o help.qhc ltr_gui.qhcp; popd
qt_gui/ltr_gui : qt_gui/help.qhc qt_gui/help.qch
	pushd qt_gui; ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE); popd

wii_server/wii_server :
	pushd wii_server; ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE); popd

mickey/help.qhc mickey/help.qch : mickey/mickey.qhcp mickey/mickey.qhp \
  mickey/help/tracking.htm mickey/help/misc.htm mickey/help/news.htm mickey/help/welcome.htm
	pushd mickey; qcollectiongenerator -o help.qhc mickey.qhcp; popd
mickey/mickey : mickey/help.qhc mickey/help.qch
	pushd mickey; ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE); popd


install-exec-hook: $(hook_inst_targets)

LTR_QT_GUI_TARGET_INST: qt_gui/help.qhc qt_gui/help.qch
	pushd qt_gui;  ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE) INSTALL_ROOT=${DESTDIR} install; popd

LTR_WII_TARGET_INST:
	pushd wii_server;  ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE) INSTALL_ROOT=${DESTDIR} install; popd

LTR_MICKEY_TARGET_INST: mickey/help.qhc mickey/help.qch
	pushd mickey;  ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE) INSTALL_ROOT=${DESTDIR} install; popd

uninstall-hook: $(hook_uninst_targets)

LTR_QT_GUI_TARGET_UNINST:
	pushd qt_gui;  ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE) INSTALL_ROOT=${DESTDIR} uninstall; popd

LTR_WII_TARGET_UNINST:
	pushd wii_server;  ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE) INSTALL_ROOT=${DESTDIR} uninstall; popd

LTR_MICKEY_TARGET_UNINST:
	pushd mickey;  ${QMAKE_PATH} ${QMAKE_FLAGS} "LIBDIR=$(pkglibdir)"; $(MAKE) INSTALL_ROOT=${DESTDIR} uninstall; popd


EXTRA_DIST = qt_gui/ltr_show.h qt_gui/help_view.cpp qt_gui/ltr_tracking.h \
qt_gui/scp_form.ui qt_gui/logview.ui qt_gui/clip.png qt_gui/webcam_prefs.cpp \
qt_gui/scview.h qt_gui/webcam_ft_prefs.h qt_gui/scview.cpp qt_gui/dl.ui \
qt_gui/ltr_model.h qt_gui/ltr_gui.cpp qt_gui/glwidget.h qt_gui/wiimote_prefs.h \
qt_gui/macwebcam_info.cpp qt_gui/ltr_gui_prefs.cpp qt_gui/objreader.cpp qt_gui/clip_small.png \
qt_gui/cap_small.png qt_gui/dlfirmware.cpp qt_gui/window.cpp qt_gui/model_wizzard.ui \
qt_gui/ltr_tracking.cpp qt_gui/ltr_profiles.cpp qt_gui/objreader.h qt_gui/plugin_install.cpp \
qt_gui/ltr_gui_prefs.h qt_gui/scp_form.h qt_gui/ltr_gui.pro.in qt_gui/scurve.h \
qt_gui/ltr_rc.qrc qt_gui/macwebcamft_prefs.h qt_gui/ltr_state.h qt_gui/model_creation.ui \
qt_gui/macwebcamft_prefs.cpp qt_gui/log_view.cpp qt_gui/ltr_gui.h qt_gui/tracker.h \
qt_gui/macwebcam_info.h qt_gui/webcam_ft_prefs.cpp qt_gui/sparow_glass.obj qt_gui/sparow_opaq.obj \
qt_gui/sphere.obj qt_gui/ltr_dev_help.cpp qt_gui/help_viewer.cpp qt_gui/help_viewer.h \
qt_gui/scp_form.cpp qt_gui/linuxtrack.icns qt_gui/window.h qt_gui/ltr_model.cpp \
qt_gui/help_view.h qt_gui/wiimote_prefs.cpp qt_gui/cap.png qt_gui/ltr_dev_help.h  \
qt_gui/glwidget.cpp qt_gui/scurve.ui qt_gui/tir_prefs.h \
qt_gui/scurve.cpp qt_gui/ltr_gui.ui qt_gui/dev_help.ui qt_gui/ltr_profiles.h \
qt_gui/ltr.ui qt_gui/ltr_state.cpp qt_gui/tir_prefs.cpp qt_gui/ltr_show.cpp \
qt_gui/xm8_detail.png qt_gui/main.cpp qt_gui/prefs_link.h qt_gui/macwebcam_prefs.h \
qt_gui/webcam_info.h qt_gui/help/misc.htm qt_gui/help/dev_setup.htm qt_gui/help/axes_setup.htm \
qt_gui/help/contents.txt qt_gui/help/news.htm qt_gui/help/welcome.htm qt_gui/help/interface.htm \
qt_gui/help/model_setup.htm qt_gui/dlfirmware.h qt_gui/webcam_info.cpp qt_gui/plugin_install.h \
qt_gui/tracker.cpp qt_gui/webcam_prefs.h qt_gui/macwebcam_prefs.cpp ps3eye.sym \
qt_gui/log_view.h tir4_driver.c tir4_driver.h 99-TIR.rules drivers.sym liblt.sym tir.sym webcam_driver.sym \
xlinuxtrack.sym joy_driver.sym linuxtrack_pre.c lt_client.c lt_server.c ltlib_client.c ltlib_client.h \
ltr_server.c ltr_server.h netcomm.c netcomm.h pref_flex.h \
qt_gui/buffering.cpp qt_gui/buffering.h qt_gui/cap_edit.ui qt_gui/cap_tweaking.ui \
qt_gui/clip_edit.ui qt_gui/clip_tweaking.ui qt_gui/device_setup.cpp qt_gui/device_setup.h \
qt_gui/device_setup.ui qt_gui/downloading.cpp qt_gui/downloading.h qt_gui/extractor.ui \
qt_gui/extractor.cpp qt_gui/extractor.h qt_gui/progress.cpp qt_gui/progress.h qt_gui/sources_mfc.txt \
qt_gui/guardian.cpp qt_gui/guardian.h qt_gui/hashing.cpp qt_gui/hashing.h qt_gui/l_wc_setup.ui \
qt_gui/l_wcft_setup.ui qt_gui/m_wc_setup.ui qt_gui/m_wcft_setup.ui qt_gui/model_edit.ui \
qt_gui/profile_selector.cpp qt_gui/profile_selector.h qt_gui/profile_selector.ui \
qt_gui/profile_setup.cpp qt_gui/profile_setup.h qt_gui/profile_setup.ui qt_gui/joy_prefs.cpp qt_gui/joy_prefs.h \
qt_gui/joy_setup.ui qt_gui/m_ps3eye_ft_setup.ui qt_gui/m_ps3eye_setup.ui qt_gui/macps3eyeft_prefs.cpp \
qt_gui/macps3eyeft_prefs.h qt_gui/macps3eye_prefs.cpp qt_gui/macps3eye_prefs.h \
qt_gui/progress.ui qt_gui/single_edit.ui qt_gui/sources.txt qt_gui/sources_mac.txt qt_gui/spec.txt qt_gui/tir_setup.ui \
qt_gui/wii_setup.ui qt_gui/help/extractor.htm qt_gui/sphere.png qt_gui/sphere.txt \
qt_gui/wine_launcher.cpp qt_gui/wine_launcher.h qt_gui/xplugin.cpp qt_gui/xplugin.h \
qt_gui/xplugin.ui qt_gui/help/Wiimote.png qt_gui/help/KeysSetup1.png qt_gui/help/Misc.png \
qt_gui/help/JoyButtonsSetup1.png qt_gui/help/XplBrowse.png qt_gui/help/CamPreview.png \
qt_gui/help/Webcam.png qt_gui/help/Extractor.png qt_gui/help/XplInstall.png \
qt_gui/help/DetAxis.png qt_gui/help/JoyButtonsSetup4.png qt_gui/help/JoyButtonsSetup5.png \
qt_gui/help/3dPreview.png qt_gui/help/ModelCreate.png qt_gui/help/JoyButtonsSetup3.png \
qt_gui/help/Tracking.png qt_gui/help/JoyButtonsSetup2.png qt_gui/help/Model.png qt_gui/help/hall_of_fame.htm \
qt_gui/help/Trackir.png qt_gui/help/Controller.png qt_gui/help/Facetracker.png qt_gui/help/mickey.htm qt_gui/help/wine.htm \
qt_gui/cap_1.png qt_gui/cap_np.png qt_gui/clip_1.png qt_gui/clip_np.png qt_gui/face.svg qt_gui/face.png qt_gui/single.png \
99-Mickey.rules qt_gui/help/xpl_setup.htm qt_gui/wine_warn.cpp qt_gui/wine_warn.h qt_gui/wine_warn.ui \
wii_server/wii_server.cpp wii_server/wiimote.h wii_server/wiimote.cpp wii_server/wii_server.pro.in \
wii_server/main.cpp wii_server/wii_server.h wii_server/wii_server.ui wii_server/wii_server.qrc \
linuxtrack-wii.desktop linuxtrack-wii.png linuxtrack-wii.svg linuxtrack-wii.xpm \
linuxtrack.desktop linuxtrack.png linuxtrack.svg linuxtrack.xpm \
ltr_gui.1 ltr_pipe.1 ltr_server1.1 wii_server.1 mickey.1 mickey/uinput_ifc.h \
mickey/piper.h mickey/keyb_qxt.h mickey/mickey.ui mickey/mickey.cpp mickey/hotkey.cpp mickey/hotkey.h mickey/hotkey.ui \
mickey/piper.c mickey/mickey.pro.in mickey/transform.h mickey/keyb.h mickey/mickey.h mickey/my_line_edit.cpp \
mickey/my_line_edit.h mickey/hotkey_setup_dlg.cpp  mickey/hotkey_setup_dlg.h  mickey/hotkey_setup.ui \
mickey/chsettings.ui mickey/calibration.ui mickey/pref.ui mickey/transform.cpp \
mickey/main.cpp mickey/help/tracking.htm mickey/help/misc.htm \
mickey/help/news.htm mickey/help/contents.txt mickey/help/welcome.htm mickey/uinput_ifc.c \
mickey/keyb.cpp mickey/helpview.ui mickey/keyb_x11.cpp mickey/keyb_x11.h mickey/linuxtrack.icns \
mickey/mouse.h mickey/mouse_linux.cpp mickey/mouse_mac.cpp mickey/mickey.qrc sn4_model.h \
mickey/precomp_headers.h wii_server/precomp_headers.h qt_gui/precomp_headers.h ltr_extractor.1 \
qt_gui/win7.reg qt_gui/ltr_gui.qhcp qt_gui/ltr_gui.qhp mickey/mickey.qhcp mickey/mickey.qhp

desktopdir = $(datadir)/applications
desktop_DATA = linuxtrack.desktop linuxtrack-wii.desktop
icondir = $(datadir)/pixmaps
icon_DATA = linuxtrack.svg linuxtrack.png linuxtrack.xpm \
            linuxtrack-wii.svg linuxtrack-wii.png linuxtrack-wii.xpm

