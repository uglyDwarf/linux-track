#include <vector>
#include <iostream>
#include "facetrack.h"
#include "wc_driver_prefs.h"

#include <opencv2/core/core.hpp>
#include <opencv2/objdetect/objdetect.hpp>
#include <opencv2/imgproc/imgproc.hpp>

#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <utils.h>

static cv::CascadeClassifier *cascade = NULL;
static double scale = 0.5;
static const double roi_factor = 0.3;

static float face_x = 0;
static float face_y = 0;
static float face_w = 0;
static float face_h = 0;
static float face_x1 = 0;
static float face_y1 = 0;
static float face_x2 = 0;
static float face_y2 = 0;

static float last_face_x = 0.0f;
static float last_face_y = 0.0f;
static float last_face_w = 0.0f;
static float last_face_h = 0.0f;

static std::vector<cv::Rect> faces;
static cv::Rect lastCandidate;

//static int frame_size = 0;
static int frame_w = 0;
static int frame_h = 0;
static uint8_t *frame = NULL;
static cv::Mat *cvimage;
static cv::Mat scaled;
static cv::Size minFace(40, 40);
static float expFiltFactor = 0.2;
static bool init = true;


float ltr_int_expfilt(float x,
              float y_minus_1,
              float filterfactor);

void ltr_int_find_faces(cv::Mat &img, float factor)
{
  cv::Size s(lastCandidate.width*roi_factor, lastCandidate.height*roi_factor);
  cv::Rect new_roi(lastCandidate.x - s.width, lastCandidate.y - s.height,
    lastCandidate.width + 2 * s.width, lastCandidate.height + 2 * s.height);
  new_roi &= cv::Rect(0,0,img.cols, img.rows);
  cv::Mat roi(img, new_roi);
  faces.clear();
  if((new_roi.width > 0) && (new_roi.height > 0)){
    cascade->detectMultiScale(roi, faces, factor, 2, 0, minFace);
  }
  if(faces.size() == 0){
    cascade->detectMultiScale(img, faces, factor, 2, 0, minFace);
  }else{
    for(std::vector<cv::Rect>::iterator i = faces.begin(); i != faces.end(); ++i){
      i->x += new_roi.x;
      i->y += new_roi.y;
    }
  }
}

void ltr_int_detect(cv::Mat& img)
{
  double current_scale;
  switch(ltr_int_wc_get_optim_level()){
    case 0:
      cv::equalizeHist(img, img);
      //cascade->detectMultiScale(img, faces, 1.1, 2, 0, minFace);
      ltr_int_find_faces(img, 1.1);
      current_scale = 1;
      break;
    case 1:
      cv::equalizeHist(img, img);
      //cascade->detectMultiScale(img, faces, 1.2, 2, 0, minFace);
      ltr_int_find_faces(img, 1.2);
      current_scale = 1;
      break;
    case 2:
      cv::resize(img, scaled, cv::Size(), scale, scale);
      cv::equalizeHist(scaled, scaled);
      //cascade->detectMultiScale(scaled, faces, 1.1, 2, 0, minFace);
      ltr_int_find_faces(scaled, 1.1);
      current_scale = scale;
      break;
    case 3:
    default:
      cv::resize(img, scaled, cv::Size(), scale, scale);
      cv::equalizeHist(scaled, scaled);
      //cascade->detectMultiScale(scaled, faces, 1.2, 2, 0, minFace);
      ltr_int_find_faces(scaled, 1.2);
      current_scale = scale;
      break;
  }

  double area = -1;
  const cv::Rect *candidate = NULL;
  for(std::vector<cv::Rect>::const_iterator i = faces.begin(); i != faces.end(); ++i){
    if(i->area() > area){
      candidate = &(*i);
      area = i->area();
    }
  }
  if(candidate != NULL){
    lastCandidate = *candidate;
    expFiltFactor = ltr_int_wc_get_eff();

    face_x1 = candidate->x/ current_scale;
    face_y1 = candidate->y/ current_scale;
    face_x2 = (candidate->x + candidate->width) / current_scale;
    face_y2 = (candidate->y + candidate->height) / current_scale;

    float x = (candidate->x + candidate->width / 2) / current_scale - frame_w/2;
    float y = (candidate->y + candidate->height / 2) / current_scale - frame_h/2;
    float w = candidate->width / current_scale;
    float h = candidate->height / current_scale;

    if(init){
      last_face_x = face_x = x;
      last_face_y = face_y = y;
      last_face_w = face_w = w;
      last_face_h = face_h = h;
      init = false;
    }else{
      face_x = ltr_int_expfilt(x, last_face_x, expFiltFactor);
      face_y = ltr_int_expfilt(y, last_face_y, expFiltFactor);
      face_w = ltr_int_expfilt(w, last_face_w, expFiltFactor);
      face_h = ltr_int_expfilt(h, last_face_h, expFiltFactor);
      last_face_x = face_x;
      last_face_y = face_y;
      last_face_w = face_w;
      last_face_h = face_h;
    }
  }
//  std::cout<<"Done\n";
}

static bool run = true;
static enum {READY, PROCESSING, DONE} frame_status  = DONE;
//static bool request_frame = false;
static pthread_cond_t frame_cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t frame_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_t detect_thread_handle;


void *ltr_int_detector_thread(void *)
{
  while(run){
    pthread_mutex_lock(&frame_mx);
    while(frame_status != READY){
      pthread_cond_wait(&frame_cv, &frame_mx);
    }
    frame_status = PROCESSING;
    pthread_mutex_unlock(&frame_mx);
    if(!run){
      break;
    }
    double t = (double)cv::getTickCount();
    ltr_int_detect(*cvimage);
    t = (double)cv::getTickCount() - t;
    //std::cout<<"detection time = "<<t/((double)cvGetTickFrequency()*1000.)<<" ms\n";

    pthread_mutex_lock(&frame_mx);
    frame_status = DONE;
    pthread_mutex_unlock(&frame_mx);
  }
  delete cascade;
  cascade = NULL;
  delete cvimage;
  cvimage = NULL;
  free(frame);
  frame = NULL;
  return NULL;
}

bool ltr_int_init_face_detect()
{
  cv::setNumThreads(1);
  cascade = new cv::CascadeClassifier();
  const char *cascade_path = ltr_int_wc_get_cascade();
  if(cascade_path == NULL){
    ltr_int_log_message("Cascade path not specified!\n");
    return false;
  }
  if(!cascade->load(cascade_path)){
    ltr_int_log_message("Could't load cascade '%s'!\n", cascade_path);
    return false;
  }
  lastCandidate = cv::Rect(0, 0, 0, 0);
  run = true;
  return pthread_create(&detect_thread_handle, NULL, ltr_int_detector_thread, NULL) == 0;
}


void ltr_int_stop_face_detect()
{
  run = false;
  pthread_mutex_lock(&frame_mx);
  frame_status = READY;
  pthread_cond_broadcast(&frame_cv);
  pthread_mutex_unlock(&frame_mx);
  pthread_join(detect_thread_handle, NULL);
  ltr_int_log_message("Facetracker thread joined!\n");
  init = true;
  frame_status = DONE;
}

void ltr_int_face_detect(image_t *img, struct bloblist_type *blt)
{
  if((frame_w != img->w) || (frame_h != img->h) || (frame == NULL)){
    if(frame != NULL){
      free(frame);
    }
    if(cvimage != NULL){
      delete cvimage;
    }
    frame_w = img->w;
    frame_h = img->h;
    frame = (uint8_t*)malloc(frame_w * frame_h);
    cvimage = new cv::Mat(frame_h, frame_w, CV_8U, frame);
  }
  if(frame_status == DONE){
    memcpy(frame, img->bitmap, frame_w * frame_h);
    pthread_mutex_lock(&frame_mx);
    frame_status = READY;
    pthread_cond_broadcast(&frame_cv);
    pthread_mutex_unlock(&frame_mx);
  }
  if(face_w * face_h > 0){
    blt->num_blobs = 1;
    blt->blobs[0].x = -face_x;
    blt->blobs[0].y = -face_y;
    blt->blobs[0].score = face_w * face_h;
    ltr_int_draw_empty_square(img, face_x1, face_y1, face_x2, face_y2);
  }else{
    blt->num_blobs = 0;
  }
}


float ltr_int_expfilt(float x,
               float y_minus_1,
               float filterfactor)
{
  float y;

  y = y_minus_1*(1.0-filterfactor) + filterfactor*x;
  return y;
}

