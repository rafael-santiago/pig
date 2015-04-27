#include <stdio.h>
#include "types.h"
#include "pigsty.h"

int main(int argc, char **argv) {
    pigsty_entry_ctx *pigsty = NULL;
    if ((pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty")) == NULL) {
	printf("*** error! :S\n");
	return 1;
    }
    printf("*** success! ;)\n");
    del_pigsty_entry(pigsty);
    return 0;
}
