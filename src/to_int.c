#include "to_int.h"
#include <string.h>

unsigned int to_int(const char *value) {
    const char *vp = value;
    int retval = 0;
    if (vp == NULL) {
	return 0;
    }
    if (strlen(value) > 3) {
	if (*vp == '0' && *(vp + 1) == 'x') {
	    retval = strtoul(vp + 2, NULL, 16);
	    return retval;
	}	
    }
    retval = atoi(value);
    return retval;
}
