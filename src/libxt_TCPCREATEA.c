/*
 * Copyright (c) 2010-2013 Mathew Heard <mheard@x4b.net>
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "xt_NOCREATE.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static void tcpcreate_help(void)
{
	printf(
"TCPREATEA target options:\n"
" none\n"
	);
}


static void tcpcreate_save(const void *ip, const struct xt_entry_target *target)
{
}

static struct xtables_target tcpcreate_target_reg[] = {
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "TCPCREATEA",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_nocreate_target_info)),
     	.save	       = tcpcreate_save,
		.help		   = tcpcreate_help,
		.userspacesize = offsetof(struct xt_nocreate_target_info, ct),
	}
};

void _init(void)
{
	xtables_register_targets(tcpcreate_target_reg, ARRAY_SIZE(tcpcreate_target_reg));
}