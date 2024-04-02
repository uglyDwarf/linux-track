#define XPLM200

#include "XPLMPlugin.h"
#include "XPLMGraphics.h"
#include "XPLMMenus.h"
#include "XPLMDisplay.h"
#include "XPLMUtilities.h"
#include "XPLMDataAccess.h"
#include "XPLMProcessing.h"
#include "XPWidgets.h"
#include "XPStandardWidgets.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include "linuxtrack.h"
#ifdef HAVE_CONFIG_H
  #include "../config.h"
#endif

#define MSG_ADD_DATAREF 0x01000000

static XPLMDataRef              head_x = NULL;
static XPLMDataRef              head_y = NULL;
static XPLMDataRef              head_z = NULL;
static XPLMDataRef              head_psi = NULL;
static XPLMDataRef              head_the = NULL;
static XPLMDataRef              head_roll = NULL;
static XPLMDataRef              view = NULL;

static XPLMDataRef PV_Enabled_DR = NULL;
static XPLMDataRef PV_TIR_X_DR = NULL;
static XPLMDataRef PV_TIR_Y_DR = NULL;
static XPLMDataRef PV_TIR_Z_DR = NULL;
static XPLMDataRef PV_TIR_Pitch_DR = NULL;
static XPLMDataRef PV_TIR_Heading_DR = NULL;
static XPLMDataRef PV_TIR_Roll_DR = NULL;

static XPLMDataRef head_x_out = NULL;
static XPLMDataRef head_y_out = NULL;
static XPLMDataRef head_z_out = NULL;
static XPLMDataRef head_psi_out = NULL;
static XPLMDataRef head_the_out = NULL;
static XPLMDataRef head_roll_out = NULL;
static XPLMDataRef enable_view_control = NULL;

static float  GetHeadDataRefCB(void* inRefcon);
static int    GetHeadCtrlRefCB(void* inRefcon);
static void   SetHeadCtrlRefCB(void* inRefcon, int outValue);
static void revertView(void);

static float current_head_x;
static float current_head_y;
static float current_head_z;
static float current_head_heading;
static float current_head_pitch;
static float current_head_roll;
static int   head_control_enable;

static XPLMMenuID  setupMenu = NULL;

static int pos_init_flag = 0;
static bool freeze = false;

static float base_x = 0.0f;
static float base_y = 0.0f;
static float base_z = 0.0f;
static XPLMDataRef base_x_dr = NULL;
static XPLMDataRef base_y_dr = NULL;
static XPLMDataRef base_z_dr = NULL;

static bool active_flag = false;
static bool pv_present = false;

static XPLMCommandRef run_cmd;
static XPLMCommandRef pause_cmd;
static XPLMCommandRef recenter_cmd;
static bool initialized = false;

static int xplane_ver;

static int cmd_cbk(XPLMCommandRef       inCommand,
                   XPLMCommandPhase     inPhase,
                   void *               inRefcon);

enum {START, PAUSE, RECENTER};

static float xlinuxtrackCallback(float inElapsedSinceLastCall,    
                                 float inElapsedTimeSinceLastFlightLoop,    
                                 int   inCounter,    
                                 void *inRefcon);

static int setupDialog();
static void messageBox(const char *msgBoxTitle, const char *message);

static void linuxTrackMenuHandler(void *inMenuRef, void *inItemRef)
{
  (void) inMenuRef;
  (void) inItemRef;
  setupDialog();
  return;
}

static float  GetHeadDataRefCB(void* inRefcon)
{
  if(inRefcon == NULL){
    return 0.0f;
  }
  return *(float*)inRefcon;
}

static int  GetHeadCtrlRefCB(void* inRefcon)
{
  if(inRefcon == NULL){
    return 0;
  }
  return *(int*)inRefcon;
}


static void   SetHeadCtrlRefCB(void* inRefcon, int outValue)
{
  if(inRefcon == (void*)&head_control_enable){
    if((head_control_enable != 0) && (outValue == 0) && (XPLMGetDatai(view) == 1026)){
      //Revert only when turning off while in 3D cockpit
      revertView();
    }
  }
  *(int*)inRefcon = outValue;
}

PLUGIN_API int XPluginStart(char *outName,
                            char *outSig,
                            char *outDesc)
{
  strcpy(outName, "linuxTrack_v"VERSION);
  strcpy(outSig, "linuxtrack.headtracker");
  strcpy(outDesc, "A plugin that brings headtracking to Linux and Mac");

  int sdk_ver;
  XPLMHostApplicationID app_id;
  XPLMGetVersions(&xplane_ver, &sdk_ver, &app_id);
  if(xplane_ver > 5000){
    xplane_ver /= 10;
  }
  //fprintf(stderr, "XPlane version: %d\n", xplane_ver);

    run_cmd = XPLMCreateCommand("linuxtrack/ltr_run","Start/stop tracking");
    pause_cmd = XPLMCreateCommand("linuxtrack/ltr_pause","Pause tracking");
    recenter_cmd = XPLMCreateCommand("linuxtrack/ltr_recenter","Recenter tracking");
        XPLMRegisterCommandHandler(
                    run_cmd,
                    cmd_cbk,
                    true,
                    (void *)START);
        XPLMRegisterCommandHandler(
                    pause_cmd,
                    cmd_cbk,
                    true,
                    (void *)PAUSE);
        XPLMRegisterCommandHandler(
                    recenter_cmd,
                    cmd_cbk,
                    true,
                    (void *)RECENTER);

                         
  head_x = XPLMFindDataRef("sim/graphics/view/pilots_head_x");
  head_y = XPLMFindDataRef("sim/graphics/view/pilots_head_y");
  head_z = XPLMFindDataRef("sim/graphics/view/pilots_head_z");
  base_x_dr = XPLMFindDataRef("sim/aircraft/view/acf_peX");
  base_y_dr = XPLMFindDataRef("sim/aircraft/view/acf_peY");
  base_z_dr = XPLMFindDataRef("sim/aircraft/view/acf_peZ");
  
  head_psi = XPLMFindDataRef("sim/graphics/view/pilots_head_psi");
  head_the = XPLMFindDataRef("sim/graphics/view/pilots_head_the");
 
  //New in XP11... 
  head_roll = XPLMFindDataRef("sim/graphics/view/pilots_head_phi");
  if(head_roll == NULL){
    head_roll = XPLMFindDataRef("sim/graphics/view/field_of_view_roll_deg");
  }
  view = XPLMFindDataRef("sim/graphics/view/view_type");
  
  head_x_out = XPLMRegisterDataAccessor(
                      "linuxtrack/pilots_head_x",
                      xplmType_Float,                                // The types we support
                      0,                                             // Writable
                      NULL, NULL,                                    // Integer accessors
                      GetHeadDataRefCB, NULL,                        // Float accessors
                      NULL, NULL,                                    // Doubles accessors
                      NULL, NULL,                                    // Int array accessors
                      NULL, NULL,                                    // Float array accessors
                      NULL, NULL,                                    // Raw data accessors
                      (void*)&current_head_x, (void*)&current_head_x); // Refcons not used

  head_y_out = XPLMRegisterDataAccessor(
                      "linuxtrack/pilots_head_y",
                      xplmType_Float,                                // The types we support
                      0,                                             // Writable
                      NULL, NULL,                                    // Integer accessors
                      GetHeadDataRefCB, NULL,                        // Float accessors
                      NULL, NULL,                                    // Doubles accessors
                      NULL, NULL,                                    // Int array accessors
                      NULL, NULL,                                    // Float array accessors
                      NULL, NULL,                                    // Raw data accessors
                      (void*)&current_head_y, (void*)&current_head_y); // Refcons not used

  head_z_out = XPLMRegisterDataAccessor(
                      "linuxtrack/pilots_head_z",
                      xplmType_Float,                                // The types we support
                      0,                                             // Writable
                      NULL, NULL,                                    // Integer accessors
                      GetHeadDataRefCB, NULL,                        // Float accessors
                      NULL, NULL,                                    // Doubles accessors
                      NULL, NULL,                                    // Int array accessors
                      NULL, NULL,                                    // Float array accessors
                      NULL, NULL,                                    // Raw data accessors
                      (void*)&current_head_z, (void*)&current_head_z); // Refcons not used

  head_psi_out = XPLMRegisterDataAccessor(
                      "linuxtrack/pilots_head_psi",
                      xplmType_Float,                                // The types we support
                      0,                                             // Writable
                      NULL, NULL,                                    // Integer accessors
                      GetHeadDataRefCB, NULL,                        // Float accessors
                      NULL, NULL,                                    // Doubles accessors
                      NULL, NULL,                                    // Int array accessors
                      NULL, NULL,                                    // Float array accessors
                      NULL, NULL,                                    // Raw data accessors
                      (void*)&current_head_heading, (void*)&current_head_heading); // Refcons not used

  head_the_out = XPLMRegisterDataAccessor(
                      "linuxtrack/pilots_head_the",
                      xplmType_Float,                                // The types we support
                      0,                                             // Writable
                      NULL, NULL,                                    // Integer accessors
                      GetHeadDataRefCB, NULL,                        // Float accessors
                      NULL, NULL,                                    // Doubles accessors
                      NULL, NULL,                                    // Int array accessors
                      NULL, NULL,                                    // Float array accessors
                      NULL, NULL,                                    // Raw data accessors
                      (void*)&current_head_pitch, (void*)&current_head_pitch); // Refcons not used
  
  head_roll_out = XPLMRegisterDataAccessor(
                      "linuxtrack/pilots_head_roll",
                      xplmType_Float,                                // The types we support
                      0,                                             // Writable
                      NULL, NULL,                                    // Integer accessors
                      GetHeadDataRefCB, NULL,                        // Float accessors
                      NULL, NULL,                                    // Doubles accessors
                      NULL, NULL,                                    // Int array accessors
                      NULL, NULL,                                    // Float array accessors
                      NULL, NULL,                                    // Raw data accessors
                      (void*)&current_head_roll, (void*)&current_head_roll); // Refcons not used
  
  enable_view_control = XPLMRegisterDataAccessor(
                      "linuxtrack/enable_head_control",
                      xplmType_Int,                                  // The types we support
                      1,                                             // Writable
                      GetHeadCtrlRefCB, SetHeadCtrlRefCB,            // Integer accessors
                      NULL, NULL,                                    // Float accessors
                      NULL, NULL,                                    // Doubles accessors
                      NULL, NULL,                                    // Int array accessors
                      NULL, NULL,                                    // Float array accessors
                      NULL, NULL,                                    // Raw data accessors
                      (void*)&head_control_enable, (void*)&head_control_enable); // Refcons not used
  head_control_enable = 1;
  
  if((head_x == NULL)  ||(head_y == NULL) || (head_z == NULL) ||
     (head_psi == NULL) || (head_the == NULL) || (head_roll == NULL) ||
     (head_x_out == NULL) || (head_y_out == NULL) || (head_z_out == NULL) ||
     (head_psi_out == NULL) || (head_the_out == NULL) || (head_roll_out == NULL) ||
     (enable_view_control == NULL) || (base_x_dr == NULL) || (base_y_dr == NULL) || (base_z_dr == NULL)){
    return(0);
  }
  
  XPLMRegisterFlightLoopCallback(                
        xlinuxtrackCallback,        /* Callback */
        -1.0,                                        /* Interval */
        NULL);                                        /* refcon not used. */
  int menuIndex = XPLMAppendMenuItem(XPLMFindPluginsMenu(), "LinuxTrack", NULL, 1);


  setupMenu = XPLMCreateMenu("LinuxTrack", XPLMFindPluginsMenu(), menuIndex, 
                         linuxTrackMenuHandler, NULL);
  XPLMAppendMenuItem(setupMenu, "Setup", (void *)"Setup", 1);

  if(!initialized){
    linuxtrack_state_type state = linuxtrack_init(NULL);
    if(state < LINUXTRACK_OK){
      messageBox("Linuxtrack Problem", linuxtrack_explain(state));
    }
  }
  return(1);
}

PLUGIN_API void XPluginStop(void)
{
        XPLMUnregisterCommandHandler(
                    run_cmd,
                    cmd_cbk,
                    true,
                    (void *)START);
        XPLMUnregisterCommandHandler(
                    pause_cmd,
                    cmd_cbk,
                    true,
                    (void *)PAUSE);
        XPLMUnregisterCommandHandler(
                    recenter_cmd,
                    cmd_cbk,
                    true,
                    (void *)RECENTER);
  XPLMUnregisterFlightLoopCallback(xlinuxtrackCallback, NULL);
  if(initialized){
    linuxtrack_shutdown();
  }
}

PLUGIN_API void XPluginDisable(void)
{
}

PLUGIN_API int XPluginEnable(void)
{
        return 1;
}

static bool drefsPublished = false;

PLUGIN_API void XPluginReceiveMessage(XPLMPluginID inFromWho,
                                      long inMessage,
                                      void *inParam)
{
  if(inFromWho == XPLM_PLUGIN_XPLANE){
    switch(inMessage){
      case XPLM_MSG_PLANE_LOADED:
        if((intptr_t)inParam == XPLM_PLUGIN_XPLANE){

          PV_Enabled_DR = XPLMFindDataRef("sandybarbour/pilotview/external_enabled");
          PV_TIR_X_DR = XPLMFindDataRef("sandybarbour/pilotview/external_x");
          PV_TIR_Y_DR = XPLMFindDataRef("sandybarbour/pilotview/external_y");
          PV_TIR_Z_DR = XPLMFindDataRef("sandybarbour/pilotview/external_z");
          PV_TIR_Pitch_DR = XPLMFindDataRef("sandybarbour/pilotview/external_pitch");
          PV_TIR_Heading_DR = XPLMFindDataRef("sandybarbour/pilotview/external_heading");
          PV_TIR_Roll_DR = XPLMFindDataRef("sandybarbour/pilotview/external_roll");
          
          if((PV_Enabled_DR == NULL) || (PV_TIR_X_DR == NULL) || 
             (PV_TIR_Y_DR == NULL) || (PV_TIR_Z_DR == NULL) ||
             (PV_TIR_Pitch_DR == NULL) || (PV_TIR_Heading_DR == NULL) || 
             (PV_TIR_Roll_DR == NULL)){
            pv_present = false;
          }else{
            pv_present = true;
            XPLMSetDatai(PV_Enabled_DR, true);
          }
          
          if(!drefsPublished){
            //Publish these datarefs for DataRefEditor plugin
            XPLMPluginID PluginID = XPLMFindPluginBySignature("xplanesdk.examples.DataRefEditor");
            if (PluginID != XPLM_NO_PLUGIN_ID){
              XPLMSendMessageToPlugin(PluginID, MSG_ADD_DATAREF, (void*)"linuxtrack/pilots_head_x");
              XPLMSendMessageToPlugin(PluginID, MSG_ADD_DATAREF, (void*)"linuxtrack/pilots_head_y");
              XPLMSendMessageToPlugin(PluginID, MSG_ADD_DATAREF, (void*)"linuxtrack/pilots_head_z");
              XPLMSendMessageToPlugin(PluginID, MSG_ADD_DATAREF, (void*)"linuxtrack/pilots_head_psi");
              XPLMSendMessageToPlugin(PluginID, MSG_ADD_DATAREF, (void*)"linuxtrack/pilots_head_the");
              XPLMSendMessageToPlugin(PluginID, MSG_ADD_DATAREF, (void*)"linuxtrack/pilots_head_roll");
              XPLMSendMessageToPlugin(PluginID, MSG_ADD_DATAREF, (void*)"linuxtrack/enable_head_control");
	      drefsPublished = true;
            }
	  }
        }
        break;
      default:
        break;
    }
  }
}

static void activate(void)
{
  if(initialized){
          active_flag=true;
          pos_init_flag = 1;
          freeze = false;
          linuxtrack_wakeup();
          linuxtrack_recenter();
    if(PV_Enabled_DR){
          XPLMSetDatai(PV_Enabled_DR, true);
    }
  }
}

static void revertView(void)
{
  int current_view = XPLMGetDatai(view);
  if((!pv_present) && (current_view == 1026)){
    XPLMSetDataf(head_x, base_x);
    XPLMSetDataf(head_y, base_y);
    XPLMSetDataf(head_z, base_z);
    XPLMSetDataf(head_psi, 0.0);
    XPLMSetDataf(head_the, 0.0);
    if(head_roll != NULL){
      XPLMSetDataf(head_roll, 0.0);
    }
  }
}

static void deactivate()
{
  active_flag=false;
  revertView();
  if(PV_Enabled_DR){
          XPLMSetDatai(PV_Enabled_DR, false);
  }
  if(initialized){
    linuxtrack_suspend();
  }
}

static int cmd_cbk(XPLMCommandRef       inCommand,
                   XPLMCommandPhase     inPhase,
                   void *               inRefcon)
{
  (void) inRefcon;
    if(inPhase == xplm_CommandBegin){
      if(inCommand == run_cmd){
        if(active_flag==false){
          activate();
        }else{
          deactivate();
        }
      }else if(inCommand == pause_cmd){
        freeze = (freeze == false)? true : false;
      }else if(inCommand == recenter_cmd){
        linuxtrack_recenter();
      }
    }
    return 1;
}

static float xlinuxtrackCallback(float inElapsedSinceLastCall,    
                              float inElapsedTimeSinceLastFlightLoop,    
                              int   inCounter,    
                              void *inRefcon)
{
  (void) inElapsedSinceLastCall;
  (void) inElapsedTimeSinceLastFlightLoop;
  (void) inCounter;
  (void) inRefcon;
  
  int currentView = XPLMGetDatai(view);
  bool view_changed = (currentView != 1026);

  if(pos_init_flag){
    pos_init_flag = 0;
    base_x = XPLMGetDataf(head_x);
    base_y = XPLMGetDataf(head_y);
    base_z = XPLMGetDataf(head_z);
    view_changed = false;
  }
  //if(PV_Enabled_DR)
  //  fprintf(stderr, "PV_ENABLED=%d\n", XPLMGetDatai(PV_Enabled_DR));
    //XPLMSetDatai(PV_Enabled_DR, active_flag);
  
  if(!initialized){
    if(linuxtrack_get_tracking_state() != STOPPED){
      initialized = true;
      linuxtrack_suspend();
    }
  }
  
  if(!active_flag){
    return -1.0;
  }

  int retval;
  unsigned int counter;
  
  if(initialized && (freeze == false)){
    retval = linuxtrack_get_pose(&current_head_heading,&current_head_pitch,&current_head_roll,
                                   &current_head_x, &current_head_y, &current_head_z, &counter);
    if (retval < 0) {
      return -1.0;
    }
    current_head_x       *= 1e-3f;
    current_head_y       *= 1e-3f;
    current_head_z       *= 1e-3f;
    current_head_heading *= -1.0f;
    current_head_roll    *= -1.0f;
  }
  if(pv_present){
    XPLMSetDataf(PV_TIR_X_DR, current_head_x);
    XPLMSetDataf(PV_TIR_Y_DR, current_head_y);
    XPLMSetDataf(PV_TIR_Z_DR, current_head_z);
    XPLMSetDataf(PV_TIR_Pitch_DR, current_head_pitch);
    XPLMSetDataf(PV_TIR_Heading_DR, current_head_heading);
    XPLMSetDataf(PV_TIR_Roll_DR, current_head_roll);
  }else if(head_control_enable != 0){
    if(!view_changed){
      XPLMSetDataf(head_x, base_x + current_head_x);
      XPLMSetDataf(head_y, base_y + current_head_y);
      XPLMSetDataf(head_z, base_z + current_head_z);
      XPLMSetDataf(head_psi,current_head_heading);
      XPLMSetDataf(head_the,current_head_pitch);
      if(head_roll != NULL){
        XPLMSetDataf(head_roll, current_head_roll);
      }
    }else{
      //Make sure to cancel any roll, otherwise bad things start to happening
      //  e.g. mising HUD in forward with HUD view or rolled view in other
      //  views... Also the roll seems to be persistent!
      if(head_roll != NULL){
        XPLMSetDataf(head_roll, 0);
      }
    }
  }
  return -1.0;
}                                   

//positive x moves us to the right (meters?)
//positive y moves us up
//positive z moves us back


static XPWidgetID		setupWindow;
static XPWidgetID		setupButton;
static int			setupWindowOpened = 0;

static int setupWindowHandler(XPWidgetMessage inMessage,
			XPWidgetID inWidget,
			intptr_t inParam1,
			intptr_t inParam2)
{
  (void) inWidget;
  (void) inParam1;
  (void) inParam2;
  if((inMessage == xpMessage_CloseButtonPushed) || (inMessage == xpMsg_PushButtonPressed)){
    if(setupWindow != NULL){
      XPHideWidget(setupWindow);
      setupWindowOpened = 0;
    }
    return 1;
  }
  return 0;
}

static XPWidgetID		setupText;
static char line1[] = "Linuxtrack setup is now done using either:";
static XPWidgetID		setupText2;
static char line2[] = " - Settings -> Joystick, Keys and Equipment -> Buttons Adv. to setup Joystick";
static XPWidgetID		setupText3;
static char line3[] = " - Settings -> Joystick, Keys and Equipment -> Keys to setup Keyboard";
static XPWidgetID		setupText4;
static char line4[] = "Use commands linuxtrack/ltr_run, linuxtrack/ltr_pause, linuxtrack/ltr_recenter.";
static XPWidgetID		setupText5;
static char line5[] = "For more details refer to https://github.com/uglyDwarf/linuxtrack/wiki/";
static XPWidgetID		setupText6;
static char line6[] = "Pilotview plugin found, chanelling headtracking data through it!";
static char title[] = "Linuxtrack v"
PACKAGE_VERSION;

static int setupDialog()
{
  if(setupWindowOpened != 0){
    return -1;
  }
  setupWindowOpened = 1;
  
  if(setupWindow != NULL){
    XPShowWidget(setupWindow);
  }else{
    int x  = 100;
    int y  = 600;
    int w  = 500;
    int h  = 150;
    if(pv_present){
      h += 20;
    }

    int x2 = x + w;
    int y2 = y - h;

    setupWindow = XPCreateWidget(x, y, x2, y2,
  				  1, //Visible
				  title,
				  1, //Root
				  NULL, //No container
				  xpWidgetClass_MainWindow 
    );
    y -= 20;
    if(pv_present){
      //y -= 20;
      setupText6 = XPCreateWidget(x+20, y, x2 -20, y -20,
    				   1, line6, 0, setupWindow, 
				   xpWidgetClass_Caption);
      y -= 20;
    }
    setupText = XPCreateWidget(x+20, y, x2 -20, y -20 ,
    				   1, line1, 0, setupWindow, 
				   xpWidgetClass_Caption);
    y -= 20;
    setupText2 = XPCreateWidget(x+20, y, x2 -20, y -20 ,
    				   1, line2, 0, setupWindow, 
				   xpWidgetClass_Caption);
    y -= 20;
    setupText3 = XPCreateWidget(x+20, y, x2 -20, y -20 ,
    				   1, line3, 0, setupWindow, 
				   xpWidgetClass_Caption);
    y -= 20;
    setupText4 = XPCreateWidget(x+20, y, x2 -20, y -20 ,
    				   1, line4, 0, setupWindow, 
				   xpWidgetClass_Caption);
    y -= 20;
    setupText5 = XPCreateWidget(x+20, y, x2 -20, y -20 ,
    				   1, line5, 0, setupWindow, 
				   xpWidgetClass_Caption);
    y -= 20;
    setupButton = XPCreateWidget(x+80, y2+27, x2-80, y2+7, 1, 
  				  "Close", 0, setupWindow,
  				  xpWidgetClass_Button);
    XPAddWidgetCallback(setupWindow, (XPWidgetFunc_t)setupWindowHandler);
  }
  return 0;
}

static XPWidgetID msgBox = NULL;

static int msgBoxHandler(XPWidgetMessage inMessage,
			XPWidgetID inWidget,
			intptr_t inParam1,
			intptr_t inParam2)
{
  (void) inWidget;
  (void) inParam1;
  (void) inParam2;
  if((inMessage == xpMessage_CloseButtonPushed) || (inMessage == xpMsg_PushButtonPressed)){
    XPHideWidget(msgBox);
    XPDestroyWidget(msgBox, 1);
    return 1;
  }
  return 0;
}

typedef struct {
  const char *text;
  int width;
} line_t;

static void messageBox(const char *msgBoxTitle, const char *message)
{
  fprintf(stderr, "Messagebox!\n");
  size_t len = strlen(message) + 1; //Count also the \0!
  char *msg_copy = (char *)malloc(len);
  if(msg_copy == NULL){
    return;
  }
  strcpy(msg_copy, message);
  line_t lines[10];
  size_t num_lines = 0;
  size_t i;
  const char *head = msg_copy;
  int max_width = 50;
  int title_width = XPLMMeasureString(xplmFont_Proportional, msgBoxTitle, strlen(msgBoxTitle));
  if(max_width < title_width){
    max_width = title_width;
  }
  for(i = 0; i < len; ++i){
    if(msg_copy[i] == '\0'){
      lines[num_lines].text = head;
      lines[num_lines].width = XPLMMeasureString(xplmFont_Proportional, head, strlen(head));
      if(lines[num_lines].width > max_width){
	max_width = lines[num_lines].width;
      }
      ++num_lines;
      break;
    }
    if(msg_copy[i] == '\n'){
      msg_copy[i] = '\0';
      lines[num_lines].text = head;
      lines[num_lines].width = XPLMMeasureString(xplmFont_Proportional, head, strlen(head));
      head = msg_copy + i + 1;
      if(lines[num_lines].width > max_width){
	max_width = lines[num_lines].width;
      }
      ++num_lines;
    }
  }
  
  int x = 250;
  int y = 700;
  int x2 = x + max_width + 40;
  int y2 = y - (20 * num_lines) - 70;
  int ptr = y - 30;
  msgBox = XPCreateWidget(x, y, x2, y2,
  				  1, //Visible
				  msgBoxTitle,
				  1, //Root
				  NULL, //No container
				  xpWidgetClass_MainWindow 
  );
  for(i = 0; i < num_lines; ++i){
    /*XPWidgetID text = */(void)XPCreateWidget(x+20, ptr, x + 20 + lines[i].width, ptr - 15 ,
                                   1, lines[i].text, 0, msgBox, xpWidgetClass_Caption);
    ptr -= 20;
  }
  ptr -= 10;
  /*XPWidgetID closeButton = */XPCreateWidget(x+30, ptr, x2 - 30, ptr - 15, 1, 
  				  "Close", 0, msgBox, xpWidgetClass_Button);
  XPAddWidgetCallback(msgBox, (XPWidgetFunc_t)msgBoxHandler);
  free(msg_copy);
}
