#include "json-logger.h"

#define DELIM "|"

int log_alert(char* ts, char* hId, char* srcip, char* dstip, char* host, char* uri, char* info) {
    json_t *json, *json_info;
    char *result;

    json = json_object();
    json_object_set_new(json, "ts", json_string(ts));
    json_object_set_new(json, "hId", json_string(hId));
    json_object_set_new(json, "srcip", json_string(srcip));
    json_object_set_new(json, "dstip", json_string(dstip));
    json_object_set_new(json, "host", json_string(host));
    json_object_set_new(json, "uri", json_string(uri));
    
    json_info = get_json_info(info);
    json_object_set_new(json, "info", json_info);

    result = json_dumps(json, JSON_PRESERVE_ORDER);

    int rc,rc_t;
    zlog_category_t *c;

    rc = zlog_init("/etc/zlog.conf");
    if (rc) {
        rc_t = zlog_reload("/etc/zlog.conf");
        if(rc_t) {
            printf("Error: json_logger.c : zlog_init failed \n");
            return -1;
        }
        else {
            c = zlog_get_category("alert_cat");
            if (!c) {
                printf("Error: json_logger.c : zlog_get_category failed \n");
                zlog_fini();
                return -1;
            }
        }
    }
    else {
        c = zlog_get_category("alert_cat");
        if (!c) {
            printf("Error: json_logger.c : zlog_get_category failed \n");
            zlog_fini();
            return -1;
        }
    }
    
    zlog_info(c,result);

    free(result);
    json_decref(json_info);
    json_decref(json);
    zlog_fini();
    return 0;
}

json_t* get_json_info(char* info) {
    json_t *json;
    char* param_str;
    char* key;
    char* value;
    int flag = 0;
    json = json_object();
    if(info) {
        param_str = strtok(info,DELIM);
        while(param_str != NULL) {
            int param_str_len = strlen(param_str);
            if(flag) {
                value = (char*)malloc((param_str_len + 1)*sizeof(char));
                memcpy(value,param_str,param_str_len);
                memcpy(value + param_str_len, "\0", 1);
                json_object_set_new(json, key, json_string(value));
                flag = 0;
                free(key);
                free(value);
            }    
            else {
                key = (char*)malloc((param_str_len + 1)*sizeof(char));
                memcpy(key,param_str,param_str_len);
                memcpy(key + param_str_len, "\0", 1);
                flag = 1;
            }
            param_str = strtok(NULL,DELIM);
        }
    }
    return json;
}


int log_error(char* ts, char* info) {

    json_t *json, *json_info;
    char *result;

    json = json_object();
    json_object_set_new(json, "ts", json_string(ts));
    json_object_set_new(json, "info", json_string(info));

    result = json_dumps(json, JSON_PRESERVE_ORDER);

    int rc,rc_t;
    zlog_category_t *c;

    rc = zlog_init("/etc/zlog.conf");
    if (rc) {
        rc_t = zlog_reload("/etc/zlog.conf");
        if(rc_t) {
            printf("Error: json_logger.c : zlog_init failed \n");
            return -1;
        }
        else {
            c = zlog_get_category("alert_cat");
            if (!c) {
                printf("Error: json_logger.c : zlog_get_category failed \n");
                zlog_fini();
                return -1;
            }
        }
    }
    else {
        c = zlog_get_category("alert_cat");
        if (!c) {
            printf("Error: json_logger.c : zlog_get_category failed \n");
            zlog_fini();
            return -1;
        }
    }

    zlog_info(c,result);

    free(result);
    json_decref(json);
    zlog_fini();
    return 0;
}

