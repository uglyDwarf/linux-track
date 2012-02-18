#ifndef WEBCAM_FT_PREFS__H
#define WEBCAM_FT_PREFS__H

#include <QObject>
#include <QComboBox>
#include "ui_ltr.h"
#include "pref_int.h"
#include "prefs_link.h"

class WebcamFtPrefs : public QObject{
  Q_OBJECT
 public:
  WebcamFtPrefs(const Ui::LinuxtrackMainForm &ui);
  ~WebcamFtPrefs();
  bool Activate(const QString &ID, bool init = false);
  static bool AddAvailableDevices(QComboBox &combo);
 private:
  const Ui::LinuxtrackMainForm &gui;
  void Connect();
  bool initializing;
 private slots:
  void on_WebcamFtFormats_activated(int index);
  void on_WebcamFtResolutions_activated(int index);
};


#endif
