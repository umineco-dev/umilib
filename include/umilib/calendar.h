/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CALENDAR_H
#define UMILIB_CALENDAR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A date of the proleptic Gregorian calendar: a year, a month of 1 to 12 and a day of the month.
 */
typedef struct umilib_calendar_Date {
    int64_t year;
    uint8_t month;
    uint8_t day;
} umilib_calendar_Date;

/**
 * Writes the date of `day` of `month` (1 to 12) of `year` into `out`; fails if the
 * calendar has no such day or the year is out of range.
 */
const umilib_ffi_Status* umilib_calendar_date_new(int64_t year, uint8_t month, uint8_t day, umilib_calendar_Date* out);

/**
 * Returns whether `year` is a leap year.
 */
bool umilib_calendar_date_is_leap_year(int64_t year);

/**
 * Returns the number of days of `month` (1 to 12) in `year`, or 0 for other months.
 */
uint8_t umilib_calendar_date_days_in_month(int64_t year, uint8_t month);

/**
 * Writes the number of days from 1970-01-01 to `date` (negative before it) into `out`.
 */
const umilib_ffi_Status* umilib_calendar_date_days(umilib_calendar_Date date, int64_t* out);

/**
 * Writes the date `days` days after 1970-01-01 (before it if negative) into `out`;
 * fails outside the first and the last date.
 */
const umilib_ffi_Status* umilib_calendar_date_from_days(int64_t days, umilib_calendar_Date* out);

#ifdef __cplusplus
}
#endif

#endif
