
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "pref.h"
#include "pref_int.h"
#include "pref_global.h"
#include "utils.h"

#include "pathconfig.h"

static plist opened_prefs = NULL;


void pref_change_callback(void *param)
{
  assert(param != NULL);
  *(bool*)param = true;
}

char *get_device_section()
{
  static pref_id dev_section = NULL;
  if(dev_section == NULL){
    if(!open_pref("Global", "Input", &dev_section)){
      log_message("Entry 'Input' missing in 'Global' section!\n");
      return NULL;
    }
  }
  return get_str(dev_section);
}

const char *get_storage_path()
{
  return DATA_PATH; 
}

bool model_section_changed = false;

char *get_model_section()
{
  static pref_id model_section = NULL;
  static char *name;
  if(model_section == NULL){
    if(!open_pref_w_callback("Global", "Model", &model_section,
      pref_change_callback, (void*)&model_section_changed)){
      log_message("Entry 'Model' missing in 'Global' section!\n");
      return NULL;
    }
    model_section_changed = true;
  }
  
  if(model_section_changed){
    model_section_changed = false;
    name = get_str(model_section);
  }
  return name;
}

bool is_model_active()
{
  char *section = get_model_section();
  pref_id active;
  if(!open_pref(section, "Active", &active)){
    log_message("Unspecified if model is active, assuming it is not...\n");
    return false;
  }
  bool res = (strcasecmp(get_str(active), "yes") == 0) ? true : false;
  close_pref(&active);
  return res;
}

bool get_device(struct camera_control_block *ccb)
{
  bool dev_ok = false;
  char *dev_section = get_device_section();
  if(dev_section == NULL){
    return false;
  }
  char *dev_type = get_key(dev_section, "Capture-device");
  if (dev_type == NULL) {
    dev_ok = false;
  } else {
    if(strcasecmp(dev_type, "Tir") == 0){
      log_message("Device Type: Track IR\n");
      ccb->device.category = tir;
      dev_ok = true;
    }
    if(strcasecmp(dev_type, "Tir4") == 0){
      log_message("Device Type: Track IR 4\n");
      ccb->device.category = tir4_camera;
      dev_ok = true;
    }
    if(strcasecmp(dev_type, "Webcam") == 0){
      log_message("Device Type: Webcam\n");
      ccb->device.category = webcam;
      dev_ok = true;
    }
    if(strcasecmp(dev_type, "Wiimote") == 0){
      log_message("Device Type: Wiimote\n");
      ccb->device.category = wiimote;
      dev_ok = true;
    }
    if(dev_ok == false){
      log_message("Wrong device type found: '%s'\n", dev_type);
      log_message(" Valid options are: 'Tir4', 'Tir', 'Tir_openusb', 'Webcam', 'Wiimote'.\n");
    }
  }
  
  char *dev_id = get_key(dev_section, "Capture-device-id");
  if (dev_id == NULL) {
    dev_ok = false;
  }else{
    ccb->device.device_id = dev_id;
  }
  
  return dev_ok;
}

bool get_coord(char *coord_id, float *f)
{
  char *model_section = get_model_section();
  if(model_section == NULL){
    return false;
  }
  char *str = get_key(model_section, coord_id);
  if(str == NULL){
    log_message("Cannot find key %s in section %s!\n", coord_id, model_section);
    return false;
  }
  *f = atof(str);
  return true;
}

//FIXME Possible race condition!
bool pose_changed = false;

typedef enum {X, Y, Z, H_Y, H_Z} cap_index;

bool setup_cap(reflector_model_type *rm, char *model_section)
{
  static char *ids[] = {"Cap-X", "Cap-Y", "Cap-Z", "Head-Y", "Head-Z"};
  static pref_id prefs[] = {NULL, NULL, NULL, NULL, NULL};
  static bool init_done = false;
  
  if(!init_done){
    cap_index i;
    for(i = X; i<= H_Z; ++i){
      if(!open_pref_w_callback(model_section, ids[i], &(prefs[i]), 
        pref_change_callback, (void *)&pose_changed)){
        log_message("Couldn't setup Cap!\n");
        return false;
      }
    }
  }
  init_done = true;
  
  float x = get_flt(prefs[X]);
  float y = get_flt(prefs[Y]);
  float z = get_flt(prefs[Z]);
  float hy = get_flt(prefs[H_Y]);
  float hz = get_flt(prefs[H_Z]);
  
  rm->p1[0] = -x/2;
  rm->p1[1] = -y;
  rm->p1[2] = -z;
  rm->p2[0] = +x/2;
  rm->p2[1] = -y;
  rm->p2[2] = -z;
  rm->hc[0] = 0.0;
  rm->hc[1] = -hy;
  rm->hc[2] = hz;
  rm->type = CAP;
  return true;
}

typedef enum {Y1, Y2, Z1, Z2, HX, HY, HZ} clip_index;

bool setup_clip(reflector_model_type *rm, char *model_section)
{
  log_message("Setting up Clip...\n");
  static char *ids[] = {"Clip-Y1", "Clip-Y2", "Clip-Z1", "Clip-Z2", 
  			"Head-X", "Head-Y", "Head-Z"};
  static pref_id prefs[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
  static bool init_done = false;
  
  if(!init_done){
    clip_index i;
    for(i = Y1; i<= HZ; ++i){
      if(!open_pref_w_callback(model_section, ids[i], &(prefs[i]),
        pref_change_callback, (void *)&pose_changed)){
        log_message("Couldn't setup Clip!\n");
        return false;
      }
    }
  }
  init_done = true;
  
  float y1 = get_flt(prefs[Y1]);
  float y2 = get_flt(prefs[Y2]);
  float z1 = get_flt(prefs[Z1]);
  float z2 = get_flt(prefs[Z2]);
  float hx = get_flt(prefs[HX]);
  float hy = get_flt(prefs[HY]);
  float hz = get_flt(prefs[HZ]);

  /*
  y1 is vertical dist of upper and middle point
  y2 is vertical dist of upper and lower point
  z1 is horizontal dist of upper and middle point
  z2 is horizontal dist of uper and lower point
  hx,hy,hz are head center coords with upper point as origin
  */ 
  
  rm->p1[0] = 0;
  rm->p1[1] = -y1;
  rm->p1[2] = z1;
  rm->p2[0] = 0;
  rm->p2[1] = -y2;
  rm->p2[2] = -z2;
  rm->hc[0] = hx;
  rm->hc[1] = hy;
  rm->hc[2] = hz;
  rm->type = CLIP;
  return true;
}

bool get_pose_setup(reflector_model_type *rm, bool *changed)
{
  assert(rm != NULL);
  assert(changed != NULL);
  char *model_section = get_model_section();
  if(model_section == NULL){
    return false;
  }
  static pref_id pref_model_type = NULL;
  if(pref_model_type == NULL){
    if(!open_pref_w_callback(model_section, "Model-type", &pref_model_type,
      pref_change_callback, (void *)&pose_changed)){
      log_message("Couldn't find Model-type!\n");
      return false;
    }
    pose_changed = true;
  }
  *changed = false;
  static bool res = false;
  if(pose_changed){
    pose_changed = false;
    *changed = true;
    char *model_type = get_str(pref_model_type);
    assert(model_type != NULL);

    if(strcasecmp(model_type, "Cap") == 0){
      res = setup_cap(rm, model_section);
    }else if(strcasecmp(model_type, "Clip") == 0){
      res = setup_clip(rm, model_section);
    }else{
      log_message("Unknown modeltype specified in section %s\n", model_section);
      res = false;
    }
  }
  return res;
}


bool get_scale_factors(struct lt_scalefactors *sf)
{
  static pref_id pitch_m = NULL;
  static pref_id yaw_m = NULL;
  static pref_id roll_m = NULL;
  static pref_id xm = NULL;
  static pref_id ym = NULL;
  static pref_id zm = NULL;
  
  if(pitch_m == NULL){
    if((
      open_pref(NULL, "Pitch-multiplier", &pitch_m) && 
      open_pref(NULL, "Yaw-multiplier", &yaw_m) &&
      open_pref(NULL, "Roll-multiplier", &roll_m) &&
      open_pref(NULL, "Xtranslation-multiplier", &xm) &&
      open_pref(NULL, "Ytranslation-multiplier", &ym) &&
      open_pref(NULL, "Ztranslation-multiplier", &zm)
      ) != true){
      log_message("Can't read scale factor prefs!\n");
      return false;
    }
    
  }
  sf->pitch_sf = get_flt(pitch_m);
  sf->yaw_sf = get_flt(yaw_m);
  sf->roll_sf = get_flt(roll_m);
  sf->tx_sf = get_flt(xm);
  sf->ty_sf = get_flt(ym);
  sf->tz_sf = get_flt(zm);
  return true; 
}

bool get_filter_factor(float *ff)
{
  static pref_id cff = NULL;
  if(cff == NULL){
    if(open_pref(NULL, "Filter-factor", &cff) != true){
      log_message("Can't read scale factor prefs!\n");
      return false;
    } 
  }
  *ff = get_flt(cff);
  return true;
}

typedef enum{
  SENTRY1, DEADZONE, LCURV, RCURV, LMULT, RMULT, LIMITS, SENTRY_2
}axis_fields;

void set_axis_field(axis_def *axis, axis_fields field, float val)
{
  assert(axis != NULL);
  switch(field){
    case(DEADZONE):
      axis->curves.dead_zone = val;
      break;
    case(LCURV):
      axis->curves.l_curvature = val;
      break;
    case(RCURV):
      axis->curves.r_curvature = val;
      break;
    case(LMULT):
      axis->l_factor = val;
      break;
    case(RMULT):
      axis->r_factor = val;
      break;
    case(LIMITS):
      axis->limits = val;
      break;
    default:
      assert(0);
      break;
  }
}

bool get_axis(const char *prefix, axis_def *axis, bool *change_flag)
{
  static const char *fields[] = {"-deadzone", 
                                 "-left-curvature", "-right-curvature", 
				 "-left-multiplier", "-right-multiplier",
				 "-limits", NULL};
  static const axis_fields af[] = {DEADZONE, LCURV, RCURV, LMULT, RMULT, LIMITS};
  
  pref_id tpid = NULL;
  int i;
  char *field_name = NULL;
  
  assert(prefix != NULL);
  assert(axis != NULL);
  //assert(change_flag != NULL);
  
  for(i = 0; fields[i] != NULL; ++i){
    field_name = my_strcat(prefix, fields[i]);
    if(open_pref(NULL, field_name, &tpid) != true){
      log_message("Can't read '%s' pref!\n", field_name);
      return false;
    }
    set_axis_field(axis, af[i], get_flt(tpid));
    
    close_pref(&tpid);
    free(field_name);
    field_name = NULL;
  }
  return true;
}

