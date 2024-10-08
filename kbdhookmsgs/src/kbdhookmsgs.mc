; Header section

; Base type for error
MessageIdTypedef=DWORD

; Base error codes
SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
    Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning=0x2:STATUS_SEVERITY_WARNING
    Error=0x3:STATUS_SEVERITY_ERROR
    )

FacilityNames=(System=0x0:FACILITY_SYSTEM
    Runtime=0x2:FACILITY_RUNTIME
    Stubs=0x3:FACILITY_STUBS
    Io=0x4:FACILITY_IO_ERROR_CODE
)

; Support languages
LanguageNames=(English=0x409:MSG00409)
LanguageNames=(Russian=0x419:MSG00419)

;Message definitions

MessageId=0x1
Severity=Error
Facility=Runtime
SymbolicName=MSG_INCORRECT_REG_DATA
Language=English
Can not check key values because registry data not valid for this service.
.
Language=Russian
Нельзя считать начальные настройки, так как раздел содержит неверные данные для этого сервиса.
.

MessageId=0x2
Severity=Error
Facility=Runtime
SymbolicName=MSG_INTERNAL_DRIVER_ERROR
Language=English
Can not perform required operation because in driver internal error occur.
.
Language=Russian
Невозможно выполнить требуемую операцию, т. к. произошла ошибка в драйвере.
.

MessageId=0x3
Severity=Success
Facility=Runtime
SymbolicName=MSG_SUCCESS_ERROR
Language=English
Required operation perform successfully.
.
Language=Russian
Требуемая операция успешно выполнена.
.

MessageId=0x4
Severity=Informational
Facility=Runtime
SymbolicName=MSG_INF_ERROR_1
Language=English
Driver has passed to a new status: initialization.
.
Language=Russian
Драйвер перешел в новое состояние: инициализирован.
.

MessageId=0x5
Severity=Informational
Facility=Runtime
SymbolicName=MSG_INF_ERROR_2
Language=English
Driver has passed to a new status: start log.
.
Language=Russian
Драйвер перешел в новое состояние: старт лога.
.

MessageId=0x6
Severity=Informational
Facility=Runtime
SymbolicName=MSG_INF_ERROR_3
Language=English
Driver has passed to a new status: stop log.
.
Language=Russian
Драйвер перешел в новое состояние: лог остановлен.
.

MessageId=0x7
Severity=Informational
Facility=Runtime
SymbolicName=MSG_INF_ERROR_4
Language=English
Driver has passed to a new status: not initialize.
.
Language=Russian
Драйвер перешел в новое состояние: не инициализирован.
.
