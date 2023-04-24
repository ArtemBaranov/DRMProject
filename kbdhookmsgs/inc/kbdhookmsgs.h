//Header section
//Base type for error
//Base error codes
//Support languages
//Message definitions
//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_STUBS                   0x3
#define FACILITY_RUNTIME                 0x2
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: MSG_INCORRECT_REG_DATA
//
// MessageText:
//
//  Can not check key values because registry data not valid for this service.
//
#define MSG_INCORRECT_REG_DATA           ((DWORD)0xC0020001L)

//
// MessageId: MSG_INTERNAL_DRIVER_ERROR
//
// MessageText:
//
//  Can not perform required operation because in driver internal error occur.
//
#define MSG_INTERNAL_DRIVER_ERROR        ((DWORD)0xC0020002L)

//
// MessageId: MSG_SUCCESS_ERROR
//
// MessageText:
//
//  Required operation perform successfully.
//
#define MSG_SUCCESS_ERROR                ((DWORD)0x00020003L)

//
// MessageId: MSG_INF_ERROR_1
//
// MessageText:
//
//  Driver has passed to a new status: initialization.
//
#define MSG_INF_ERROR_1                  ((DWORD)0x40020004L)

//
// MessageId: MSG_INF_ERROR_2
//
// MessageText:
//
//  Driver has passed to a new status: start log.
//
#define MSG_INF_ERROR_2                  ((DWORD)0x40020005L)

//
// MessageId: MSG_INF_ERROR_3
//
// MessageText:
//
//  Driver has passed to a new status: stop log.
//
#define MSG_INF_ERROR_3                  ((DWORD)0x40020006L)

//
// MessageId: MSG_INF_ERROR_4
//
// MessageText:
//
//  Driver has passed to a new status: not initialize.
//
#define MSG_INF_ERROR_4                  ((DWORD)0x40020007L)

