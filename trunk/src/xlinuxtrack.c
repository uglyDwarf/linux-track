#include <string.h>
#include "XPLMDisplay.h"
#include "XPLMUtilities.h"
#include "XPLMDataAccess.h"
#include <stdio.h>
#include <math.h>
#include "ltlib.h"

XPLMHotKeyID	gHotKey = NULL;
XPLMDataRef		head_x = NULL;
XPLMDataRef		head_y = NULL;
XPLMDataRef		head_z = NULL;
XPLMDataRef		head_psi = NULL;
XPLMDataRef		head_the = NULL;

int pos_init_flag = 0;

float base_x;
float base_y;
float base_z;


void	MyHotKeyCallback(void *               inRefcon);    

int	AircraftDrawCallback(	XPLMDrawingPhase     inPhase,
                          int                  inIsBefore,
                          void *               inRefcon);


PLUGIN_API int XPluginStart(
                            char *		outName,
                            char *		outSig,
                            char *		outDesc)
{
  struct lt_configuration_type ltconf;
	strcpy(outName, "linuxTrack");
	strcpy(outSig, "linuxtrack.camera");
	strcpy(outDesc, "A plugin that controls view using your webcam.");

	/* Register our hot key for the new view. */
	gHotKey = XPLMRegisterHotKey(XPLM_VK_F8, xplm_DownFlag, 
                               "3D linuxTrack view",
                               MyHotKeyCallback,
                               NULL);
  head_x = XPLMFindDataRef("sim/graphics/view/pilots_head_x");
  head_y = XPLMFindDataRef("sim/graphics/view/pilots_head_y");
  head_z = XPLMFindDataRef("sim/graphics/view/pilots_head_z");
  head_psi = XPLMFindDataRef("sim/graphics/view/pilots_head_psi");
  head_the = XPLMFindDataRef("sim/graphics/view/pilots_head_the");
  if((head_x==NULL)||(head_y==NULL)||(head_z==NULL)||
     (head_psi==NULL)||(head_the==NULL)){
    return(0);
  }
  if(lt_init(ltconf, "XPlane")!=0){
    return(0);
  }
	return(1);
}

PLUGIN_API void	XPluginStop(void)
{
	XPLMUnregisterHotKey(gHotKey);
  lt_shutdown();
}

PLUGIN_API void XPluginDisable(void)
{
}

PLUGIN_API int XPluginEnable(void)
{
	return 1;
}

PLUGIN_API void XPluginReceiveMessage(
                                      XPLMPluginID	inFromWho,
                                      long			inMessage,
                                      void *			inParam)
{
}

void	MyHotKeyCallback(void *               inRefcon)
{
  static int active=0;
	/* This is the hotkey callback.  First we simulate a joystick press and
	 * release to put us in 'free view 1'.  This guarantees that no panels
	 * are showing and we are an external view. */
	 
	/* Now we control the camera until the view changes. */
	if(active==0){
	  active=1;
      pos_init_flag = 1;
    lt_recenter();
    XPLMRegisterDrawCallback(
                             AircraftDrawCallback,
                             xplm_Phase_LastCockpit,
                             0,
                             NULL);
	}else{
	  active=0;
	  XPLMUnregisterDrawCallback(
                               AircraftDrawCallback,
                               xplm_Phase_LastCockpit,
                               0,
                               NULL);
                               
          XPLMSetDataf(head_x,base_x);
          XPLMSetDataf(head_y,base_y);
          XPLMSetDataf(head_z,base_z);
	  XPLMSetDataf(head_psi,0.0f);
	  XPLMSetDataf(head_the,0.0f);
	}
}

int	AircraftDrawCallback(	XPLMDrawingPhase     inPhase,
                          int                  inIsBefore,
                          void *               inRefcon)
{
  float heading, pitch, roll;
  float tx, ty, tz;
  lt_get_camera_update(&heading,&pitch,&roll,
                       &tx, &ty, &tz);
  tx *= 1e-3;
  ty *= 1e-3;
  tz *= 1e-3;
/*   printf("heading: %f\tpitch: %f\n", heading, pitch); */

  /* Fill out the camera position info. */
  /* FIXME: not doing translation */
  /* FIXME: not roll, is this even possible? */
  
  if(pos_init_flag == 1){
    pos_init_flag = 0;
    base_x = XPLMGetDataf(head_x);
    base_y = XPLMGetDataf(head_y);
    base_z = XPLMGetDataf(head_z);
    
  }
  
  XPLMSetDataf(head_x,base_x + tx);
  XPLMSetDataf(head_y,base_y + ty);
  XPLMSetDataf(head_z,base_z + tz);
  XPLMSetDataf(head_psi,heading);
  XPLMSetDataf(head_the,pitch);
	return 1;
}                                   

//positive x moves us to the right (meters?)
//positive y moves us up
//positive z moves us back