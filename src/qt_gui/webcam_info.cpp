#include "webcam_info.h"
#include "webcam_driver.h"
#include "list.h"
#include "dyn_load.h"

#include <assert.h>
#include <iostream>
#include <stdint.h>
#include <QtDebug>

typedef int (*enum_webcams_fun_t)(char **ids[]);
typedef int (*enum_webcam_formats_fun_t)(const char *id, webcam_formats *all_formats);
typedef int (*enum_webcam_formats_cleanup_fun_t)(webcam_formats *all_formats);

static enum_webcams_fun_t enum_webcams_fun = NULL;
static enum_webcam_formats_fun_t enum_webcam_formats_fun = NULL;
static enum_webcam_formats_cleanup_fun_t enum_webcam_formats_cleanup_fun = NULL;
static lib_fun_def_t functions[] = {
  {(char *)"ltr_int_enum_webcams", (void*) &enum_webcams_fun},
  {(char *)"ltr_int_enum_webcam_formats", (void*) &enum_webcam_formats_fun},
  {(char *)"ltr_int_enum_webcam_formats_cleanup", (void*) &enum_webcam_formats_cleanup_fun},
  {NULL, NULL}
};

/*
 * Bastardized version of singleton pattern to take care of library 
 * loading/unloading...
 */
class WebcamLibProxy{
 private:
  void *libhandle;
  WebcamLibProxy();
  ~WebcamLibProxy();
  WebcamLibProxy(const WebcamLibProxy&){};
  WebcamLibProxy & operator=(const WebcamLibProxy&);
  static WebcamLibProxy wcl;
};

WebcamLibProxy WebcamLibProxy::wcl;
bool webcamInfoOk = false;

WebcamLibProxy::WebcamLibProxy(){
  if((libhandle = ltr_int_load_library((char *)"libwc", functions)) != NULL){
    webcamInfoOk = true;
  }
}

WebcamLibProxy::~WebcamLibProxy(){
  if(webcamInfoOk){
    ltr_int_unload_library(libhandle, functions);
  }
  libhandle = NULL;
}

static webcam_format def_fmt1 = {0, *"YUYV", 160, 120, 1, 30};
//static webcam_format def_fmt2 = {0, *"YUYV", 320, 240, 1, 30};
//static webcam_format def_fmt3 = {0, *"YUYV", 352, 288, 1, 30};

WebcamInfo::WebcamInfo(const QString &id)
{
  if(!webcamInfoOk){
    throw(0);
  }
  webcam_id = id;
  enum_webcam_formats_fun(webcam_id.toUtf8().constData(), &fmts);
  
  int j;
  fmt_index = -1;
  int index;
  QString item, pixfmt, width, height, fps;

  if(fmts.entries == 0){
    //std::cout<<"Zero entries!\n";
    format_strings.push_back(QString::fromUtf8("YUYV"));
    fmt_descs.push_back(QList<webcam_format*>());
    res_list.push_back(QStringList());
    fmt_descs[0].push_back(&def_fmt1);
    res_list[0].push_back(QString::fromUtf8("160 x 120 @ 30"));
    res_list[0].push_back(QString::fromUtf8("320 x 240 @ 30"));
    res_list[0].push_back(QString::fromUtf8("352 x 288 @ 30"));
  }else{
    for(j = 0; j < fmts.entries; ++j){
      index = fmts.formats[j].i;
      if(fmt_index != index){
	fmt_index = index;
	format_strings.push_back(QString::fromUtf8(fmts.fmt_strings[index]));
	fmt_descs.push_back(QList<webcam_format*>());
	res_list.push_back(QStringList());
      }
      fmt_descs.back().push_back(&(fmts.formats[j]));
      width = QString::number(fmts.formats[j].w);
      height = QString::number(fmts.formats[j].h);
      fps = QString::number((float)fmts.formats[j].fps_den 
			    / fmts.formats[j].fps_num);
      item = QString::fromUtf8("%2 x %3 @ %4").arg(width, height, fps);
      res_list.back().push_back(item);
    }
  }
}

const QStringList& WebcamInfo::getFormats()
{
  return format_strings;
}

const QStringList& WebcamInfo::getResolutions(int index)
{
  //std::cout<<"Selecting format index "<<index<<"\n";
  if((index >=0) && (index <= fmt_index)){
    return res_list[index];
  }else{
    return res_list[0];
  }
}

static QString U32_2_String(uint32_t fourcc)
{
  char *fcc = (char *)&(fourcc);
  char fcc1[5];
  qstrncpy(fcc1, fcc, 5);
  fcc1[4] = '\0';
  return QString(QString::fromUtf8(fcc1));
}

QString WebcamInfo::getFourcc(int index)
{
  if((index >=0) && (index <= fmt_index)){
    return U32_2_String(fmt_descs[index][0]->fourcc);
  }else{
    return U32_2_String(*"YUYV");
  }
}

int WebcamInfo::findFourcc(const QString &fcc)
{
  for(int i = 0; i < fmt_descs.length(); ++i){
    if(getFourcc(i) == fcc){
      return i;
    }
  }
  return 0;
}

typedef struct{
  int w, h;
  int fps_num, fps_den;
} res_struct;

bool WebcamInfo::decodeRes(const QString &res, int &res_x, int &res_y)
{
  const QRegExp &res_rexp = QRegExp(QString::fromUtf8("^\\s*(\\d+)\\s*[xX]\\s*(\\d+)\\s*$"));
  if(res_rexp.indexIn(res) == -1){
    return false;
  }
  res_x = res_rexp.cap(1).toInt();
  res_y = res_rexp.cap(2).toInt();
  return true;
}

bool WebcamInfo::decodeFps(const QString &fps, int &num, int &den)
{
  const QRegExp &fps_rexp = QRegExp(QString::fromUtf8("^(\\d+)\\s*/\\s*(\\d+)\\s*$"));
  if(fps_rexp.indexIn(fps) == -1){
    return false;
  }
  num = fps_rexp.cap(1).toInt();
  den = fps_rexp.cap(2).toInt();
  return true;
}



/*
static bool decodeRes(const QString &res, const QString &fps, res_struct &decoded)
{
  const QRegExp &res_rexp = QRegExp("^\\s*(\\d+)\\s*[xX]\\s*(\\d+)\\s*$");
  const QRegExp &fps_rexp = QRegExp("^(\\d+)\\s*-- remove! --/\\s*(\\d+)\\s*$");

  if(res_rexp.indexIn(res) == -1){
    return false;
  }
  if(fps_rexp.indexIn(fps) == -1){
    return false;
  }
  decoded.w = res_rexp.cap(1).toInt();
  decoded.h = res_rexp.cap(2).toInt();
  decoded.fps_num = fps_rexp.cap(1).toInt();
  decoded.fps_den = fps_rexp.cap(2).toInt();
  return true;
}
*/

int WebcamInfo::findRes(const int &res_x, const int &res_y, const int &fps_num, 
	      const int &fps_den, const QString &fourcc)
{
  res_struct fmt = {res_x, res_y, fps_num, fps_den};
  int index = findFourcc(fourcc);
  QList<webcam_format*>::const_iterator i;
  int counter = 0;
  webcam_format* tested;
  for(i = (fmt_descs[index]).begin(); i != (fmt_descs[index]).end(); ++i, ++counter){
    tested = *i;
    if((tested->w == fmt.w) && (tested->h == fmt.h) && 
       (tested->fps_num == fmt.fps_den) && (tested->fps_den == fmt.fps_num)){
      if(U32_2_String(tested->fourcc) == fourcc){
	return counter;
      }
    }
  }
  return 0;
}

bool WebcamInfo::findFmtSpecs(int i_fmt, int i_res, QString &res, 
			      QString &fps, QString &fmt)
{
  if((i_fmt >= fmt_descs.size()) || (i_res >= fmt_descs[i_fmt].size())){
    return false;
  }
  webcam_format* format = fmt_descs[i_fmt][i_res];
  res = QString::fromUtf8("%1 x %2").arg(QString::number(format->w))
                          .arg(QString::number(format->h));
  fps = QString::fromUtf8("%1/%2").arg(QString::number(format->fps_den))
                          .arg(QString::number(format->fps_num));
  fmt = getFourcc(i_fmt);
  return true;
}

WebcamInfo::~WebcamInfo()
{
  enum_webcam_formats_cleanup_fun(&fmts);
}

QStringList& WebcamInfo::EnumerateWebcams()
{
  QStringList *res = new QStringList();
  if(!webcamInfoOk){
    return *res;
  }
  char **ids = NULL;
  
  if(enum_webcams_fun(&ids) > 0){
    int id_num = 0;
    
    while((ids[id_num]) != NULL){
      res->append(QString::fromUtf8(ids[id_num]));
      ++id_num;
    }
    ltr_int_array_cleanup(&ids);
  }
  return *res;
}
