#include "to_str.h"
#include "memory.h"
#include <string.h>
#include <ctype.h>

#define getnibv(n) ( isxdigit((n)) ? toupper((n)) - 55 : (n) - 48 )

char *to_str(const char *value) {
    const char *vp = value, *vp_end = NULL;
    char *retval = NULL, *rp = NULL;
    unsigned char byte = 0;
    if (vp == NULL) {
	return NULL;
    }    
    retval = pig_newseg(strlen(value) + 1);
    memset(retval, 0, strlen(value) + 1);
    rp = retval;
    vp += 1;
    vp_end = value + strlen(value) - 1;
    while (*vp != 0) {
	if (*vp == '\\') {
	    vp++;
	    switch (*(vp + 1)) {
		case 'n':
		    *rp = '\n';
		    break;
		    
		case 't':
		    *rp = '\t';
		    break;
		    
		case 'r':
		    *rp = '\r';
		    break;
		    
		case 'x':
		    vp++;
		    byte = 0;
		    while (isxdigit(*vp) && *vp != 0) {
			byte = (byte << 4) | getnibv(*vp);
			vp++;
		    }
		    *rp = byte;
		    vp--;
		    break;
		    
		default:
		    *rp = *vp;
		    break;
	    }
	    rp++;
	} else {
	    *rp = *vp;
	    rp++;
	}
	vp++;
    }
    return retval;
}
