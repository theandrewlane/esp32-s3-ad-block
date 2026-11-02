/**
 * LVGL 9.x configuration for ESP32-S3 DNS AdBlock display (480x272, RGB565).
 * This file is found via -DLV_CONF_INCLUDE_SIMPLE + project root on include path.
 */
#ifndef LV_CONF_H
#define LV_CONF_H

#include <stdint.h>

/*====================
   COLOR SETTINGS
 *====================*/
/* LVGL 9.2: use LV_COLOR_FORMAT_DEFAULT instead of deprecated LV_COLOR_DEPTH */
#define LV_COLOR_FORMAT_DEFAULT LV_COLOR_FORMAT_RGB565
/* Keep LV_COLOR_DEPTH for backwards-compat with any code that checks it */
#define LV_COLOR_DEPTH 16

/*====================
   STDLIB
 *====================*/
/** Use the C standard library for malloc/string/sprintf */
#define LV_USE_STDLIB_MALLOC  255  /* LV_STDLIB_CUSTOM: PSRAM allocator in display_task.cpp, keeps internal RAM for TLS */
#define LV_USE_STDLIB_STRING  1
#define LV_USE_STDLIB_SPRINTF 1

/*====================
   TICK
 *====================*/
/**
 * Use esp_timer_get_time() so we never have to call lv_tick_inc() manually.
 * Returns microseconds; divide by 1000 to get milliseconds.
 */
#define LV_TICK_CUSTOM 1
#define LV_TICK_CUSTOM_INCLUDE      "esp_timer.h"
#define LV_TICK_CUSTOM_SYS_TIME_EXPR ((uint32_t)(esp_timer_get_time() / 1000ULL))

/*====================
   OS / THREADING
 *====================*/
/* LVGL is only ever called from the display task — no OS integration needed. */
#define LV_USE_OS 0   /* 0 = LV_OS_NONE */

/*====================
   LOGGING
 *====================*/
#define LV_USE_LOG      0
#define LV_USE_ASSERT_NULL          0
#define LV_USE_ASSERT_MALLOC        0
#define LV_USE_ASSERT_STYLE         0
#define LV_USE_ASSERT_MEM_INTEGRITY 0
#define LV_USE_ASSERT_OBJ           0

/*====================
   FONTS
 *====================*/
#define LV_FONT_MONTSERRAT_10 1
#define LV_FONT_MONTSERRAT_12 1
#define LV_FONT_MONTSERRAT_14 1
#define LV_FONT_MONTSERRAT_16 1
#define LV_FONT_MONTSERRAT_20 1
#define LV_FONT_MONTSERRAT_24 1
#define LV_FONT_MONTSERRAT_32 1
#define LV_FONT_DEFAULT &lv_font_montserrat_14

/*====================
   WIDGETS
 *====================*/
#define LV_USE_ARC        1
#define LV_USE_BAR        1
#define LV_USE_BTN        1
#define LV_USE_BTNMATRIX  0
#define LV_USE_CALENDAR   0
#define LV_USE_CANVAS     0
#define LV_USE_CHART      1
#define LV_USE_CHECKBOX   0
#define LV_USE_COLORWHEEL 0
#define LV_USE_DROPDOWN   0
#define LV_USE_IMG        0
#define LV_USE_IMGBTN     0
#define LV_USE_KEYBOARD   0
#define LV_USE_LABEL      1
#define LV_USE_LED        1
#define LV_USE_LINE       1
#define LV_USE_LIST       1
#define LV_USE_MENU       0
#define LV_USE_METER      0
#define LV_USE_MSGBOX     0
#define LV_USE_ROLLER     0
#define LV_USE_SCALE      0
#define LV_USE_SLIDER     0
#define LV_USE_SPANGROUP  0
#define LV_USE_SPINBOX    0
#define LV_USE_SPINNER    0
#define LV_USE_SWITCH     0
#define LV_USE_TABLE      1
#define LV_USE_TABVIEW    0
#define LV_USE_TEXTAREA   0
#define LV_USE_TILEVIEW   0
#define LV_USE_WIN        0

/*====================
   DRAW
 *====================*/
#define LV_DRAW_SW_COMPLEX 1

/*====================
   GPU
 *====================*/
#define LV_USE_GPU_ESP_DMA2D 0

/*====================
   FEATURES
 *====================*/
#define LV_USE_PERF_MONITOR 0
#define LV_USE_MEM_MONITOR  0
#define LV_USE_REFR_DEBUG   0
#define LV_USE_DEMO_WIDGETS 0
#define LV_USE_DEMO_STRESS  0

#define LV_USE_FRAGMENT     0
#define LV_USE_IMGFONT      0
#define LV_USE_SNAPSHOT     0

/*====================
   ENCODER / MOUSE
 *====================*/
#define LV_BUILD_EXAMPLES 0

#endif /* LV_CONF_H */
