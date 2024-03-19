#define _GNU_SOURCE
#include <features.h>
#include <stdio.h>
#undef _GNU_SOURCE

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include "webcam_driver.h"
#include "wc_driver_prefs.h"
#include "utils.h"
#include "pref.h"
#include "pref_global.h"
#include "runloop.h"

#ifndef OPENCV
#include "image_process.h"
#else
#include "facetrack.h"
#endif

#include <libv4l2.h>

#define NUM_OF_BUFFERS 8
typedef struct {
        void *start;
        size_t length;
} mmap_buffer;

static mmap_buffer *buffers = NULL;

typedef struct{
  int fd;
  int expecting_blobs;
  bool is_diag;
  unsigned int buffers;
  int w;
  int h;
  unsigned char *bw_frame;
  unsigned int threshold;
  int min_blob_pixels;
  int max_blob_pixels;
  __u32 fourcc;
  bool flip;
} webcam_info;

static webcam_info wc_info;
/*************/
/* interface */
/*************/

int ltr_int_tracker_wakeup();
int ltr_int_tracker_suspend();



static char *get_webcam_id(int fd)
{
  struct v4l2_capability capability;

  //Query device capabilities
  int ioctl_res = v4l2_ioctl(fd, VIDIOC_QUERYCAP, &capability);
  if(ioctl_res == 0){
    __u32 cap = capability.capabilities;
    __u32 dev_cap = capability.device_caps;
    ltr_int_log_message("  Found V4L2 webcam: '%s'\n",
      		capability.card);
    //Look for capabilities we need
    if((cap & V4L2_CAP_VIDEO_CAPTURE) &&
      (cap & V4L2_CAP_STREAMING) && (dev_cap & V4L2_CAP_VIDEO_CAPTURE)){
      ////for leading space infested name verification
      //  char *spaced_name = NULL;
      //  asprintf(&spaced_name, " %s",(char *)capability.card);
      //  return spaced_name;
      return ltr_int_my_strdup((char *)capability.card);
    }else{
      ltr_int_log_message("  Found V4L2 webcam but it doesn't support streaming:-(\n");
    }
  }
  return NULL;
}

static int is_our_webcam(const char *fname, const char *webcam_id)
{
  int fd = v4l2_open(fname, O_RDWR | O_NONBLOCK);
  if(fd == -1){
    ltr_int_log_message("Can't open file '%s'!\n", fname);
    return -1;
  }

  char *current_id = get_webcam_id(fd);
  if(current_id == NULL){
    v4l2_close(fd);
    return -1;
  }
  char *stripped = current_id + strspn(current_id, " \t");
  if(strncasecmp(stripped, webcam_id, strlen(webcam_id)) == 0){
    //this is the device we are looking for!
    free(current_id);
    return fd;
  }else{
    free(current_id);
    v4l2_close(fd);
  }
  return -1;
}

int ltr_int_enum_webcams(char **ids[])
{
  assert(ids != NULL);
  int counter = 1; //Already plus one!!!
  plist wc_list = ltr_int_create_list();
  char *id;
  DIR *dev = opendir("/dev");
  if(dev == NULL){
    ltr_int_log_message("Can't open /dev for reading!\n");
    return -1;
  }
  struct dirent *de;
  //Get list of all wabcams
  while((de = readdir(dev)) != NULL){
    if(strncmp("video", de->d_name, 5) == 0){
      char *fname;
      if(asprintf(&fname, "/dev/%s", de->d_name) < 0){
        continue;
      }

      int fd = v4l2_open(fname, O_RDWR | O_NONBLOCK);
      if(fd == -1){
	ltr_int_log_message("Can't open file '%s'!\n", fname);
	free(fname);
	continue;
      }

      id = get_webcam_id(fd);
      if(id != NULL){
        //get rid of leading spaces!
        char *tmp = id + strspn(id, " \t");
	++counter;
	ltr_int_add_element(wc_list, ltr_int_my_strdup(tmp));
	free(id);
      }
      v4l2_close(fd);
      free(fname);
    }
  }
  closedir(dev);
  //Convert list to array
  return ltr_int_list2string_list(wc_list, ids);
}


static int search_for_webcam(const char *webcam_id);

int ltr_int_enum_webcam_formats(const char *id, webcam_formats *all_formats)
{
  int fd = search_for_webcam(id);
  if(fd < 0){
    return -1;
  }

  int fmt_cntr = 0;
  int sizes_cntr;
  int ival_cntr;
  int items = 0;
  struct v4l2_fmtdesc fmt;
  struct v4l2_frmsizeenum frm;
  struct v4l2_frmivalenum ival;
  plist fmt_strings = ltr_int_create_list();
  plist formats = ltr_int_create_list();
/*
  strcpy(fmt.description, "YUYVVV");
  ltr_int_log_message("Supported format: %s\n", (char *)fmt.description);
  ltr_int_add_element(fmt_strings, ltr_int_my_strdup((char *)fmt.description));
  fmt_cntr++;
  strcpy(fmt.description, "XYZ");
  ltr_int_log_message("Supported format: %s\n", (char *)fmt.description);
  ltr_int_add_element(fmt_strings, ltr_int_my_strdup((char *)fmt.description));
  fmt_cntr++;
  ival.discrete.denominator = 22;
  ival.discrete.numerator = 1;
  	    ltr_int_log_message("Supported framerate: %f\n",
				(float)ival.discrete.denominator / ival.discrete.numerator);
	    webcam_format *new_fmt = (webcam_format*)ltr_int_my_malloc(sizeof(webcam_format));
	    new_fmt->i = fmt_cntr - 1;
	    new_fmt->fourcc = 0x6768696a;
	    new_fmt->w = 333;
	    new_fmt->h = 222;
	    new_fmt->fps_num = ival.discrete.numerator;
	    new_fmt->fps_den = ival.discrete.denominator;
	    ltr_int_add_element(formats, new_fmt);
	    ++items;
*/

  //Enumerate all available formats
  while(1){
    fmt.index = fmt_cntr;
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if(v4l2_ioctl(fd, VIDIOC_ENUM_FMT, &fmt) != 0){
      if(errno != EINVAL){
        ltr_int_my_perror("VIDIOC_ENUM_FMT");
      }
      break;
    }
    ++fmt_cntr;
    ltr_int_log_message("Supported format: %s\n", (char *)fmt.description);
    ltr_int_add_element(fmt_strings, ltr_int_my_strdup((char *)fmt.description));
    sizes_cntr = 0;
    while(1){
      frm.index = sizes_cntr++;
      frm.pixel_format = fmt.pixelformat;
      if(v4l2_ioctl(fd, VIDIOC_ENUM_FRAMESIZES, &frm) != 0){
        if(errno != EINVAL){
          ltr_int_my_perror("VIDIOC_ENUM_FRAMESIZES");
        }
	break;
      }
      if(frm.type == V4L2_FRMSIZE_TYPE_DISCRETE){
	ltr_int_log_message("Frame size %d x %d\n", frm.discrete.width, frm.discrete.height);
	ival_cntr = 0;
	while(1){
	  ival.index = ival_cntr++;
	  ival.pixel_format = fmt.pixelformat;
	  ival.width = frm.discrete.width;
	  ival.height = frm.discrete.height;
          webcam_format *new_fmt;
	  if(v4l2_ioctl(fd, VIDIOC_ENUM_FRAMEINTERVALS, &ival) != 0){
            if(errno != EINVAL){
              ltr_int_my_perror("VIDIOC_ENUM_FRAMEINTERVALS");
            }
            if(ival_cntr == 1){
              //to have at least something - webcam will make its own mind anyway...
	      new_fmt = (webcam_format*)ltr_int_my_malloc(sizeof(webcam_format));
	      new_fmt->i = fmt_cntr - 1;
	      new_fmt->fourcc = fmt.pixelformat;
	      new_fmt->w = frm.discrete.width;
	      new_fmt->h = frm.discrete.height;
	      new_fmt->fps_num = 30;
	      new_fmt->fps_den = 1;
	      ltr_int_add_element(formats, new_fmt);
	      ++items;
            }
	    break;
	  }
	  if(ival.type == V4L2_FRMIVAL_TYPE_DISCRETE){
	    ltr_int_log_message("Supported framerate: %f\n",
				(float)ival.discrete.denominator / ival.discrete.numerator);
	    new_fmt = (webcam_format*)ltr_int_my_malloc(sizeof(webcam_format));
	    new_fmt->i = fmt_cntr - 1;
	    new_fmt->fourcc = fmt.pixelformat;
	    new_fmt->w = frm.discrete.width;
	    new_fmt->h = frm.discrete.height;
	    new_fmt->fps_num = ival.discrete.numerator;
	    new_fmt->fps_den = ival.discrete.denominator;
	    ltr_int_add_element(formats, new_fmt);
	    ++items;
	  }else if(ival.type == V4L2_FRMIVAL_TYPE_STEPWISE){
	    ltr_int_log_message("Supported framerate from %d/%d to %d/%d with step %d/%d",
				ival.stepwise.min.denominator, ival.stepwise.min.numerator,
				ival.stepwise.max.denominator, ival.stepwise.max.numerator,
				ival.stepwise.step.denominator, ival.stepwise.step.numerator);
	    new_fmt = (webcam_format*)ltr_int_my_malloc(sizeof(webcam_format));
	    new_fmt->i = fmt_cntr - 1;
	    new_fmt->fourcc = fmt.pixelformat;
	    new_fmt->w = frm.discrete.width;
	    new_fmt->h = frm.discrete.height;
	    new_fmt->fps_num = ival.stepwise.min.numerator;
	    new_fmt->fps_den = ival.stepwise.min.denominator;
	    ltr_int_add_element(formats, new_fmt);
	    ++items;
	    new_fmt = (webcam_format*)ltr_int_my_malloc(sizeof(webcam_format));
	    new_fmt->i = fmt_cntr - 1;
	    new_fmt->fourcc = fmt.pixelformat;
	    new_fmt->w = frm.discrete.width;
	    new_fmt->h = frm.discrete.height;
	    new_fmt->fps_num = ival.stepwise.max.numerator;
	    new_fmt->fps_den = ival.stepwise.max.denominator;
	    ltr_int_add_element(formats, new_fmt);
	    ++items;
	    break;
	  }else if(ival.type == V4L2_FRMIVAL_TYPE_CONTINUOUS){
	    ltr_int_log_message("Supported framerate from %d/%d to %d/%d with step %d/%d",
				ival.stepwise.min.denominator, ival.stepwise.min.numerator,
				ival.stepwise.max.denominator, ival.stepwise.max.numerator,
				ival.stepwise.step.denominator, ival.stepwise.step.numerator);
	    new_fmt = (webcam_format*)ltr_int_my_malloc(sizeof(webcam_format));
	    new_fmt->i = fmt_cntr - 1;
	    new_fmt->fourcc = fmt.pixelformat;
	    new_fmt->w = frm.discrete.width;
	    new_fmt->h = frm.discrete.height;
	    new_fmt->fps_num = ival.stepwise.min.numerator;
	    new_fmt->fps_den = ival.stepwise.min.denominator;
	    ltr_int_add_element(formats, new_fmt);
	    ++items;
	    new_fmt = (webcam_format*)ltr_int_my_malloc(sizeof(webcam_format));
	    new_fmt->i = fmt_cntr - 1;
	    new_fmt->fourcc = fmt.pixelformat;
	    new_fmt->w = frm.discrete.width;
	    new_fmt->h = frm.discrete.height;
	    new_fmt->fps_num = ival.stepwise.max.numerator;
	    new_fmt->fps_den = ival.stepwise.max.denominator;
	    ltr_int_add_element(formats, new_fmt);
	    ++items;
	    break;
	  }else{
	    ltr_int_log_message("Unsupported framerate spec format %d!\n", ival.type);
	    break;
	  }
	}
      }else{
	ltr_int_log_message("Unsupported framesize format! %d\n", frm.type);
	break;
      }
    }
  }


  //Make table of all format descriptions
  char **strs = (char **)ltr_int_my_malloc((fmt_cntr + 1) * sizeof(char *));
  int cntr = 0;
  iterator i;
  char *desc;
  ltr_int_init_iterator(fmt_strings, &i);

  while((desc = (char *)ltr_int_get_next(&i)) != NULL){
    strs[cntr++] = desc;
  }
  strs[cntr] = NULL;
  all_formats->fmt_strings = strs;

  //Make table of all formats
  webcam_format *fmt_array = (webcam_format*)ltr_int_my_malloc(items * sizeof(webcam_format));
  ltr_int_init_iterator(formats, &i);
  webcam_format *wf;
  cntr = 0;
  while((wf = (webcam_format*)ltr_int_get_next(&i)) != NULL){
    fmt_array[cntr++] = *wf;
  }
  all_formats->formats = fmt_array;
  all_formats->entries = items;

  ltr_int_free_list(formats, true);
  ltr_int_free_list(fmt_strings, false);
  v4l2_close(fd);
  return items;
}

int ltr_int_enum_webcam_formats_cleanup(webcam_formats *all_formats)
{
  int j = 0;
  while(all_formats->fmt_strings[j] != NULL){
    free(all_formats->fmt_strings[j++]);
  }
  free(all_formats->fmt_strings);
  all_formats->fmt_strings = NULL;
  free(all_formats->formats);
  all_formats->formats = NULL;
  return 0;
}


int search_for_webcam(const char *webcam_id)
{
  if(webcam_id == NULL){
    ltr_int_log_message("Please spacify webcam Id!\n");
    return -1;
  }
  DIR *dev = opendir("/dev");
  int wfd = -1;
  if(dev == NULL){
    ltr_int_log_message("Can't open /dev for reading!\n");
    return -1;
  }
  struct dirent *de;
  while((de = readdir(dev)) != NULL){
    if(strncmp("video", de->d_name, 5) == 0){
      char *fname;
      if(asprintf(&fname, "/dev/%s", de->d_name) < 0){
        continue;
      }
      if((wfd = is_our_webcam(fname, webcam_id)) != -1){
        ltr_int_log_message("Found webcam '%s' (%s)\n", de->d_name, fname);
        free(fname);
        break;
      }
      free(fname);
    }
  }
  closedir(dev);
  return wfd;
}



static bool read_pref_format(struct v4l2_format *fmt)
{
  memset(fmt, 0, sizeof(struct v4l2_format));
  if(!ltr_int_wc_init_prefs()){
    ltr_int_log_message("Can't read webcam prefs!\n");
  }
  const char *pix = ltr_int_wc_get_pixfmt();
  if(pix == NULL){
    ltr_int_log_message("No pixel format specified!\n");
    return false;
  }

  int x, y;
  if(!ltr_int_wc_get_resolution(&x, &y)){
    return false;
  }

  fmt->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  fmt->fmt.pix.width = x;
  fmt->fmt.pix.height = y;
  fmt->fmt.pix.pixelformat = *(__u32*)pix;
  fmt->fmt.pix.field = V4L2_FIELD_ANY;

  wc_info.fourcc = *(__u32*)pix;
  return true;
}


static bool set_capture_format(struct camera_control_block *ccb)
{
  struct v4l2_format fmt;
  if(read_pref_format(&fmt) != true){
    return false;
  }

  if(0 != v4l2_ioctl(wc_info.fd, VIDIOC_S_FMT, &fmt)){
    switch(errno){
      case EBUSY:
        ltr_int_log_message("Can't switch formats right now!\n");
        break;
      case EINVAL:
        ltr_int_log_message("Using wrong data to switch formats!\n");
        break;
    }
    return false;
  }
  ccb->pixel_width = wc_info.w = fmt.fmt.pix.width;
  ccb->pixel_height = wc_info.h = fmt.fmt.pix.height;
  wc_info.bw_frame = (unsigned char *)ltr_int_my_malloc(wc_info.w * wc_info.h);
  ltr_int_log_message("Switch of the format successfull!\n");
  return true;
}

static bool set_stream_params()
{
  int num, den;
  if(!ltr_int_wc_get_fps(&num, &den)){
    ltr_int_log_message("I don't understand fps specification!\n");
    return false;
  }

  struct v4l2_streamparm sp;
  memset(&sp, 0, sizeof(sp));
  sp.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  //Switched num and den - to get time instead of fps;
  sp.parm.capture.timeperframe.numerator = den;
  sp.parm.capture.timeperframe.denominator = num;

  if(-1 == v4l2_ioctl(wc_info.fd, VIDIOC_S_PARM, &sp)){
    ltr_int_log_message("Stream parameters setup failed! (%s)\n", strerror(errno));
    return false;
  }
  return true;
}


/*
 * Sends request to driver for mmap-able buffers
 * Uses constant NUM_OF_BUFFERS
 *
 * Returns number of buffers granted
 */
static int request_streaming_buffers()
{
  struct v4l2_requestbuffers reqb;
  memset(&reqb, 0, sizeof(reqb));
  reqb.count = NUM_OF_BUFFERS;
  reqb.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  reqb.memory = V4L2_MEMORY_MMAP;

  //request buffers from driver
  if(0 != v4l2_ioctl(wc_info.fd, VIDIOC_REQBUFS, &reqb)){
    ltr_int_log_message("Couldn't get streaming buffers! (%s)\n", strerror(errno));
    return 0;
  }
  if(reqb.count < NUM_OF_BUFFERS){
    ltr_int_log_message("Got fewer buffers than expected! (%d instead of %d)\n",
                reqb.count, NUM_OF_BUFFERS);
  }else{
    ltr_int_log_message("Got %d buffers...\n", reqb.count);
  }
  return reqb.count;
}

/*
 * Prepares buffers for streaming (mmaps them and allocs
 * space for output BW frames)
 *
 * Returns TRUE on success, FALSE otherwise
 */
static bool setup_streaming_buffers()
{
  ltr_int_log_message("Setting up buffers for streaming...\n");
  wc_info.buffers = request_streaming_buffers();
  if(0 == wc_info.buffers){
      ltr_int_log_message("Request for buffers failed...\n");
      return false;
  }
  //alloc memory for array of buffers
  buffers = ltr_int_my_malloc(wc_info.buffers * sizeof(mmap_buffer));
  memset(buffers, 0, sizeof(mmap_buffer) * wc_info.buffers);

  //initialize buffer structures...
  unsigned int cntr;
  for(cntr = 0; cntr < wc_info.buffers; ++cntr){
    struct v4l2_buffer buf;
    memset(&buf, 0, sizeof(buf));

    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = cntr;

    if(0 != v4l2_ioctl(wc_info.fd, VIDIOC_QUERYBUF, &buf)){
      ltr_int_log_message("Request for buffer failed...\n");
      return false;
    }

    buffers[cntr].length = buf.length;
    buffers[cntr].start = v4l2_mmap(NULL, buf.length, PROT_READ | PROT_WRITE,
      MAP_SHARED, wc_info.fd, buf.m.offset);
    if(MAP_FAILED == buffers[cntr].start){
      ltr_int_log_message("Mmap failed...\n");
      return false;
    }
  }
  ltr_int_log_message("Mmap setup successfull!\n");
  return true;
}


/*
 * Unmaps and frees streaming buffers...
 *
 * Returns TRUE on success, FALSE otherwise
 */
static bool release_buffers()
{
  if(NULL == buffers){
    ltr_int_log_message("Trying to release already released buffers...\n");
    return false;
  }
  unsigned int cntr;
  for(cntr = 0; cntr < wc_info.buffers; ++cntr){
    if(-1 == v4l2_munmap(buffers[cntr].start, buffers[cntr].length)){
      ltr_int_log_message("Munmap failed!\n");
    }
  }
  free(buffers);
  buffers = NULL;
  ltr_int_log_message("Buffers unmapped!\n");
  return true;
}

static bool read_img_processing_prefs()
{
#ifdef OPENCV
  wc_info.threshold = 0;
#else
  wc_info.threshold = ltr_int_wc_get_threshold();
#endif
  wc_info.min_blob_pixels = ltr_int_wc_get_min_blob();
  wc_info.max_blob_pixels = ltr_int_wc_get_max_blob();
  wc_info.flip = ltr_int_wc_get_flip();
  return true;
}

/*
 * I'm going to actively ignore resolution and I'll set it from prefs...
 */
int ltr_int_tracker_init(struct camera_control_block *ccb)
{
  assert(ccb != NULL);
  assert((ccb->device.category == webcam) || (ccb->device.category == webcam_ft));
  assert(ccb->device.device_id != NULL);
  int fd = search_for_webcam(ccb->device.device_id);
  if(fd == -1){
    ltr_int_log_message("Couldn't open webcam dev file!\n");
    return -1;
  }
  wc_info.fd = fd;
  wc_info.expecting_blobs = MAX_BLOBS;

  if(set_capture_format(ccb) != true){
    ltr_int_log_message("Couldn't set capture format!\n");
    v4l2_close(fd);
    return -1;
  }
  if(set_stream_params() != true){
    ltr_int_log_message("Couldn't set stream parameters!\n");
    v4l2_close(fd);
    return -1;
  }
  if(setup_streaming_buffers() != true){
    ltr_int_log_message("Couldn't initialize mmap!\n");
    v4l2_close(fd);
    return -1;
  }
  if(read_img_processing_prefs() != true){
    ltr_int_log_message("Couldn't initialize mmap!\n");
    v4l2_close(fd);
    return -1;
  }
  ltr_int_prepare_for_processing(ccb->pixel_width, ccb->pixel_height);
  if(ltr_int_tracker_resume() != 0){
    ltr_int_log_message("Couldn't start streaming!\n");
    v4l2_close(fd);
    return -1;
  }
#ifdef OPENCV
  if(!ltr_int_init_face_detect()){
    ltr_int_log_message("Couldn't initialize facetracking!\n");
    v4l2_close(fd);
    return -1;
  }
#endif
  ltr_int_log_message("Webcam initialized OK!\n");
  return 0;
}

int ltr_int_tracker_close()
{
  ltr_int_log_message("Webcam shutting down!\n");
  release_buffers();
  free(wc_info.bw_frame);
  v4l2_close(wc_info.fd);
#ifdef OPENCV
  ltr_int_stop_face_detect();
#endif
  ltr_int_log_message("Webcam shut down!\n");
  ltr_int_cleanup_after_processing();
  ltr_int_wc_close_prefs();
  return 0;
}

int ltr_int_tracker_resume()
{
  ltr_int_log_message("Queuing buffers...\n");
  enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  unsigned int cntr;
  for(cntr = 0; cntr < wc_info.buffers; ++cntr){
    struct v4l2_buffer buf;
    memset(&buf, 0, sizeof(buf));

    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = cntr;

    if(0 != v4l2_ioctl(wc_info.fd, VIDIOC_QBUF, &buf)){
      ltr_int_log_message("Queuing of buffer failed...\n");
      return -1;
    }
  }
  ltr_int_log_message("Buffers queued, starting to stream!\n");

  if(-1 == v4l2_ioctl(wc_info.fd, VIDIOC_STREAMON, &type)){
    ltr_int_log_message("Start of streaming failed!\n");
    return -1;
  }
  return 0;
}

int ltr_int_tracker_pause()
{
  enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if(-1 == v4l2_ioctl(wc_info.fd, VIDIOC_STREAMOFF, &type)){
    ltr_int_log_message("Problem stopping streaming!\n");
    return -1;
  }
  ltr_int_log_message("Streaming stopped!\n");
  return 0;
}

static void get_bw_image(unsigned char *source_buf, unsigned char *dest_buf, unsigned int bytes_used)
{
  unsigned int cntr, cntr1;

  if(wc_info.fourcc == *(__u32*)"YUYV"){
    for(cntr = cntr1 = 0; cntr < bytes_used; cntr += 2, ++cntr1){
      if(source_buf[cntr] > wc_info.threshold){
	dest_buf[cntr1] = source_buf[cntr];
      }else{
	dest_buf[cntr1] = 0;
      }
    }
  }else if((wc_info.fourcc == *(__u32*)"YU12") || (wc_info.fourcc == *(__u32*)"YV12")){
    for(cntr = 0; cntr < (unsigned int)wc_info.w * wc_info.h; ++cntr){
      if(source_buf[cntr] > wc_info.threshold){
	dest_buf[cntr] = source_buf[cntr];
      }else{
	dest_buf[cntr] = 0;
      }
    }
  }else if(wc_info.fourcc == *(__u32*)"RGB3"){
    float y;
    for(cntr = cntr1 = 0; cntr < bytes_used; cntr += 3, ++cntr1){
      //Y  =      (0.257 * R) + (0.504 * G) + (0.098 * B) + 16
      y = 0.257 * ((float)source_buf[cntr])
        + 0.504 * ((float)source_buf[cntr + 1])
        + 0.098 * ((float)source_buf[cntr + 2]) + 16;
      if(y > 255) y = 255.0;
      if(y > wc_info.threshold){
	dest_buf[cntr1] = y;
      }else{
	dest_buf[cntr1] = 0;
      }
    }
  }else if(wc_info.fourcc == *(__u32*)"BGR3"){
    float y;
    for(cntr = cntr1 = 0; cntr < bytes_used; cntr += 3, ++cntr1){
      //Y  =      (0.257 * R) + (0.504 * G) + (0.098 * B) + 16
      y = 0.257 * ((float)source_buf[cntr + 2])
        + 0.504 * ((float)source_buf[cntr + 1])
        + 0.098 * ((float)source_buf[cntr + 0]) + 16;
      if(y > 255) y = 255.0;
      if(y > wc_info.threshold){
	dest_buf[cntr1] = y;
      }else{
	dest_buf[cntr1] = 0;
      }
    }
  }else{
    for(cntr = 0; cntr < (unsigned int)wc_info.w * wc_info.h; ++cntr){
      dest_buf[cntr] = 0;
    }
  }
}

int ltr_int_tracker_get_frame(struct camera_control_block *ccb, struct frame_type *f,
                              bool *frame_acquired)
{
  (void) ccb;
  read_img_processing_prefs();
  f->bloblist.num_blobs = wc_info.expecting_blobs;
  f->width = wc_info.w;
  f->height = wc_info.h;
  struct v4l2_buffer buf;
  memset(&buf, 0, sizeof(buf));
  buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  buf.memory = V4L2_MEMORY_MMAP;

  int res;
  struct pollfd pfd = {
    .fd = wc_info.fd,
    .events = POLLIN | POLLRDNORM,
    .revents = 0
  };

  while(1){
    res = poll(&pfd, 1, 500);
    if(res == 1){
      if(pfd.revents == (POLLIN | POLLRDNORM)){
        //we have data!
        break;
      }else{
        if((pfd.revents & POLLERR) != 0){
          ltr_int_log_message("Poll returned error (%s)!\n", strerror(errno));
	}else{
	  ltr_int_log_message("Poll returned unexpected event! (%X)\n",pfd.revents);
	}
      }
    }else if(res == -1){
      ltr_int_log_message("Poll returned error! (%s)", strerror(errno));
      return -1;
    }else if(res == 0){
      ltr_int_log_message("Poll timed out!\n");
    }else{
      ltr_int_log_message("Poll returned unexpected value %d!\n", res);
      return -1;
    }
  };

  while(-1 == v4l2_ioctl(wc_info.fd, VIDIOC_DQBUF, &buf)){
    switch(errno){
      case EAGAIN:
        continue;
        break;
      default:
        ltr_int_log_message("Problem dequeing buffer! (%s)\n", strerror(errno));
        return -1;
    }
  }
  assert(buf.index < wc_info.buffers);

  unsigned char *source_buf = (buffers[buf.index]).start;
  unsigned char *dest_buf = (f->bitmap != NULL) ? f->bitmap : wc_info.bw_frame;
  get_bw_image(source_buf, dest_buf, buf.bytesused);
  //ltr_int_log_message("%d points found!\n", pts);

  if(-1 == v4l2_ioctl(wc_info.fd, VIDIOC_QBUF, &buf)){
    ltr_int_log_message("Error queuing buffer!\n");
  }
  //ltr_int_log_message("Queued buffer %d\n", buf.index);
  image_t img = {
    .bitmap = dest_buf,
    .w = wc_info.w,
    .h = wc_info.h,
    .ratio = 1.0f
  };

#ifdef DEBUG
  //Save sequence of frames
  static int frm_cntr = 0;
  char fname[] = "FRAMEXXX.bin";
  sprintf(fname, "FRAME%03d.bin", frm_cntr % 100);
  ++frm_cntr;
  fprintf(stderr, "%s\n", fname);
  FILE *ff;
  if((ff = fopen(fname, "wb")) != NULL){
    fwrite(dest_buf, 1, wc_info.w * wc_info.h, ff);
    fclose(ff);
  }
#endif

#ifndef OPENCV
  ltr_int_to_stripes(&img);
  ltr_int_stripes_to_blobs(MAX_BLOBS, &(f->bloblist), wc_info.min_blob_pixels,
		   wc_info.max_blob_pixels, &img);
  if(wc_info.flip){
    unsigned int tmp;
    for(tmp = 0; tmp < f->bloblist.num_blobs; ++tmp){
      f->bloblist.blobs[tmp].x *= -1;
      f->bloblist.blobs[tmp].y *= -1;
    }
  }
#else
  ltr_int_face_detect(&img, &(f->bloblist));
#endif
  *frame_acquired = true;
  return 0;
}
