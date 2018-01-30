/*
* Copyright (c) 2012 Qualcomm Atheros, Inc.
* Copyright(C) 2014 Foxconn International Holdings, Ltd. All rights reserved.
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

#ifndef WLAN_WAPI_IFACE_OS_SVC_H
#define WLAN_WAPI_IFACE_OS_SVC_H
/*===========================================================================

File: WLAN_WAPI_IFACE_OS_SVC.H

DESCRIPTION
    This header file exposes OS specific Definitions to 3rd party WAPI
    supplicant that wishes to interface with AMSS WLAN framework.
    As of now following OS specific interfaces are defined.
	1. File operation APIs.
	2. Timer operation APIs.


Copyright (c)2009 by QUALCOMM, Incorporated.  All Rights Reserved.
===========================================================================*/

/*===========================================================================

		EDIT HISTORY FOR FILE

This section contains comments describing changes made to the module.
Notice that changes are listed in reverse chronological order.

$Header: $
$Author: $ $DateTime: $

when        who     what, where, why
--------    ---     ----------------------------------------------------------
07/22/09    pbh     Added file operation APIs.
07/21/09    pbh     Initial Creation.
===========================================================================*/

/*===========================================================================

PUBLIC DATA DECLARATIONS

===========================================================================*/

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef NULL
#define NULL                0
#endif


typedef  unsigned char      boolean;     /* Boolean value type */

#ifndef WIN32
typedef  unsigned long long uint64;      /* Unsigned 64 bit value */
#else
typedef  unsigned __int64    uint64;
#endif

typedef  unsigned long int  uint32;      /* Unsigned 32 bit value */
typedef  unsigned short     uint16;      /* Unsigned 16 bit value */
typedef  unsigned char      uint8;       /* Unsigned 8  bit value */

#ifndef WIN32
typedef  signed long long   int64;       /* Signed 64 bit value */
#else
typedef  __int64    int64;
#endif
typedef  signed long int    int32;       /* Signed 32 bit value */
typedef  signed short       int16;       /* Signed 16 bit value */

/* File operation macros */

#define FL_NULL                             ((void *) -1) /* File open failed */
/* Open file for reading only */
#define WLAN_WAPI_IFACE_FLAG_RDONLY         0x00
 /* Open file for writing only */
#define WLAN_WAPI_IFACE_FLAG_WRONLY         0x01
 /* Open file for both reading & writing */
#define WLAN_WAPI_IFACE_FLAG_RDWR           0x02
 /* Create file if it does not exist */
#define WLAN_WAPI_IFACE_FLAG_CREATE         0x04
 /* Set to offset */
#define WLAN_WAPI_IFACE_SEEK_SET            0
 /* Set to offset + current position */
#define WLAN_WAPI_IFACE_SEEK_CUR            1
 /* Set to offset + file size */
#define WLAN_WAPI_IFACE_SEEK_END            2


/* Debug log message pririty */
 /* Lowest priority message */
#define WLAN_WAPI_IFACE_PRINT_PRI_LOW       0
 /* Medium priority message */
#define WLAN_WAPI_IFACE_PRINT_PRI_MED       1
 /* Highest priority message */
#define WLAN_WAPI_IFACE_PRINT_PRI_HIGH      2
 /* Error message */
#define WLAN_WAPI_IFACE_PRINT_PRI_ERROR     3


/*=============================================================

		WAPI IFACE FILE OPERATION APIS

=================================================================*/

/*===============================================================
FUNCTION WLAN_WAPI_IFACE_FOPEN()

DESCRIPTION
    This function is called by WAPI ASUE to open/create a file in the file
    system. If successful, file descriptor will be returned. If error, -1 will
    be returned. To create the file WLAN_WAPI_IFACE_FLAG_CREATE must be ORed
    as part of the flag argument. If the file already exists then
    WLAN_WAPI_IFACE_FLAG_CREATE will be ignored. File will be created with
    Read & Write permission for user and Read permission for others.

PARAMETERS
    file    : Path of the file that needs to be opened/created.
    flag    : Argument describes how this file needs to be opened.
		WLAN_WAPI_IFACE_FLAG_RDONLY - Open file for reading only.
		WLAN_WAPI_IFACE_FLAG_WRONLY - Open file for writing only.
		WLAN_WAPI_IFACE_FLAG_WRWR - Open file for reading & writing only.
		WLAN_WAPI_IFACE_FLAG_CREATE - Create the file if it does not exist.

EXAMPLE
    void *fd;
    fd = wlan_wapi_iface_fopen("/path/file",
	WLAN_WAPI_IFACE_FLAG_RDONLY | WLAN_WAPI_IFACE_FLAG_CREATE);
    if (fd == FL_NULL)
	errorhandling;


RETURN VALUE
    Success - File descriptor.
    Failure - FL_NULL.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
void* wlan_wapi_iface_fopen
(
	const char *file,
	uint32 flag
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_FCLOSE()

DESCRIPTION
    This function is called by WAPI ASUE to close the file.

PARAMETERS
    fd      : File descriptor obtained earlier via FOPEN call.

RETURN VALUE
    Success - 0.
    Failure - -1.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
int32 wlan_wapi_iface_fclose
(
	void *fd
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_FREAD()

DESCRIPTION
    This function is called by WAPI ASUE to read nbytes of data from the file
    associated with the specified file descriptor.

PARAMETERS
    fd      : File descriptor obtained earlier via FOPEN call.
    buf     : Caller owned buffer in which read data will be stored.
    nbytes  : Number of bytes to read from the file.

RETURN VALUE
    Success - Number of bytes successfully read.
	0 indicates end of file reached.
    Failure - -1.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
int32 wlan_wapi_iface_fread
(
	void *fd,
	void *buf,
	uint32 nbytes
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_FWRITE()

DESCRIPTION
    This function is called by WAPI ASUE to write nbytes of data to the file
    associated with the specified file descriptor.

PARAMETERS
    fd      : File descriptor obtained earlier via FOPEN call.
    buf     : Buffer containing the data that needs to get written to the file.
    nbytes  : Number of bytes to write to the file.

RETURN VALUE
    Success - Number of bytes successfully written.
    Failure - -1.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
int32 wlan_wapi_iface_fwrite
(
	void *fd,
	const void *buf,
	uint32 nbytes
 );


/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_FSEEK()

DESCRIPTION
    This function is called by WAPI ASUE change the offset for the opened file
    associated with the specified file descriptor.

PARAMETERS
    fd      : File descriptor obtained earlier via FOPEN call.
    offset  : The new offset of the file.
    whence  : Indicate how the new offset is computed.
		WLAN_WAPI_IFACE_SEEK_SET - Set to offset.
		WLAN_WAPI_IFACE_SEEK_CUR - Set to offset + current position.
		WLAN_WAPI_IFACE_SEEK_END - Set to offset + file size.

RETURN VALUE
    Success - Resulting offset returned.
    Failure - -1.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
int32 wlan_wapi_iface_fseek
(
	void *fd,
	int32 offset,
	int32 whence
 );


/*===========================================================================

		WAPI IFACE TIMER OPERATION APIS

===========================================================================*/

/**
* TYPEDEF WLAN_WAPI_IFACE_TIMER_CNT_TYPE
*
* DESCRIPTION
* Timer value type. In milliseconds.
* */
typedef unsigned long       wlan_wapi_iface_timer_cnt_type;

/**
* TYPEDEF WLAN_WAPI_IFACE_TIMER_CB_TYPE
*
* DESCRIPTION
* This is the prototype of the timer call back function that
* ASUE registers with WAPI IFACE. Call back will be called
* when the timer expires. arg is the argument to the call back.
* */
typedef void (*wlan_wapi_iface_timer_cb_type) (uint32 arg);

/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_CREATE_TIMER()

DESCRIPTION
    This function is called by WAPI ASUE to define a new timer. This function
    returns pointer to timer type which should be used in all subsequent call
    to use the timer facilities.

PARAMETERS
    timer_f_ptr : Call back function that will be called when timer expires
    arg         : Argument to the call back function

RETURN VALUE
    Success - Pointer to timer type.
    Failure - NULL.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
timer_t wlan_wapi_iface_create_timer
(
	wlan_wapi_iface_timer_cb_type  timer_f_ptr,
	uint32                         arg
 );

/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_START_TIMER()

DESCRIPTION
    This function is called by WAPI ASUE to start the timer to expire after the
    specified interval (in ms). If the timer is already running then timer will
    be set with the new passed value.

PARAMETERS
    ptr_timer   : Pointer to timer type returned by create timer.
    msecs       : Time in milliseconds.

RETURN VALUE
    Remaining timer value (In ms).

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
wlan_wapi_iface_timer_cnt_type wlan_wapi_iface_start_timer
(
	timer_t tid,
	wlan_wapi_iface_timer_cnt_type msecs
 );

/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_GET_TIMER()

DESCRIPTION
    This function is called by WAPI ASUE to get the current remaining value of
    a timer (In ms).

PARAMETERS
    ptr_timer   : Pointer to timer type returned by create timer.

RETURN VALUE
    Current remaining timer value (In ms) of the timer or 0 if timer is not
    running.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
wlan_wapi_iface_timer_cnt_type wlan_wapi_iface_get_timer
(
	timer_t tid
 );

/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_STOP_TIMER()

DESCRIPTION
    This function is called by WAPI ASUE to stop the timer.

PARAMETERS
    ptr_timer   : Pointer to timer type returned by create timer.

RETURN VALUE
    Current remaining value of the timer (In ms) or 0 if timer is not running.

DEPENDENCIES
    None

SIDE EFFECTS
    None
===========================================================================*/
wlan_wapi_iface_timer_cnt_type wlan_wapi_iface_stop_timer
(
	timer_t tid
 );

/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_DELETE_TIMER()

DESCRIPTION
    This function is called by WAPI ASUE to delete the timer. This function
    stops the timer and releases the resources allocated for the timer.

PARAMETERS
    ptr_timer   : Pointer to timer type returned by create timer.

RETURN VALUE
    None.

DEPENDENCIES
    None.

SIDE EFFECTS
    None
===========================================================================*/
void wlan_wapi_iface_delete_timer
(
	timer_t tid
 );

/*===========================================================================

		WAPI IFACE MISCELLANEOUS APIS

===========================================================================*/
/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_GET_SYS_TIME()

DESCRIPTION
    This function is called by WAPI ASUE to get the system time in millisecond
    units from 6 Jan 1980 00:00:00.

PARAMETERS
    None.

RETURN VALUE
    The time in ms from 6 Jan 1980 00:00:00.

DEPENDENCIES
    None.

SIDE EFFECTS
    None
===========================================================================*/
uint64 wlan_wapi_iface_get_sys_time(void);

/*===========================================================================
FUNCTION WLAN_WAPI_IFACE_PRINT()

DESCRIPTION
    This function is called by WAPI ASUE for logging the debug messages.

PARAMETERS
    pririty             : Priority of the message. XXX_LOW is lowest priority
			and XXX_ERROR is highest priority.
    format              : Format string that interpret the arguments passed
			after the format. Format can look like
			%<width><conversion specifier>
EXAMPLE
    wlan_wapi_iface_print(<msg priority>, "Decimal: %d", number);
    wlan_wapi_iface_print(<msg priority>, "Hexadecimal: %04x", number);
    wlan_wapi_iface_print(<msg priority>, "String: %s", "some string");
    wlan_wapi_iface_print(<msg priority>, "%02x:%02x", num1, num2);

DEPENDENCIES
    None.

RETURN VALUE
    None.

SIDE EFFECTS
    None.
===========================================================================*/
void wlan_wapi_iface_print
(
	uint32 priority,
	const char *format, ...
 );


#endif /* WLAN_WAPI_IFACE_OS_SVC_H */
