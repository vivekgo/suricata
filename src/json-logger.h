#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include "zlog.h"
#include "/usr/local/include/jannson.h"

int log_alert(char*, char*, char*, char*, char*, char*, char*);
int log_error(char*, char*);
json_t get_json_info(char*);
