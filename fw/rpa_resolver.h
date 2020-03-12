/*
 * Written by Sultan Qasim Khan
 * Copyright (c) 2020, NCC Group plc
 * Released as open source under GPLv3
 */

#ifndef RPA_RESOLVER_H
#define RPA_RESOLVER_H

#include <stdbool.h>

// returns true on RPA matching IRK
bool rpa_match(const void *irk, const void *rpa);

#endif
