#ifndef XT_NOCREATE_H
#define XT_NOCREATE_H

#include <linux/types.h>

struct xt_nocreate_target_info {
	struct nf_conn  *ct __attribute__((aligned(8)));
}
#endif