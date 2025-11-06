/*
 * Copyright (c) 2010-2021 Mathew Heard <mheard@x4b.net>
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "xt_NOCREATE.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static void nocreate_help(void)
{
	printf(
"NOCREATEA target options:\n"
" none\n"
	);
}


static void nocreate_save(const void *ip, const struct xt_entry_target *target)
{
}

static struct xtables_target nocreate_target_reg[] = {
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "NOCREATEA",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_nocreate_target_info)),
     	.save		   = nocreate_save,
		.help		   = nocreate_help,
		.userspacesize = offsetof(struct xt_nocreate_target_info, ct),
	}
};

#ifndef _init
#define _init __attribute__((constructor)) _INIT
#endif
void _init(void)
{
	xtables_register_targets(nocreate_target_reg, ARRAY_SIZE(nocreate_target_reg));
}
