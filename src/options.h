/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_TO_OPTIONS_H
#define PIG_TO_OPTIONS_H 1

void register_options(const int argc, char **argv);

char *get_option(const char *option, char *default_value);

#endif
