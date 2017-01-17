/*
 * Copyright (c) 2010-2013 Patrick McHardy <kaber@trash.net>
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "xt_NOCREATE.h"

static void ct_help(void)
{
	printf(
"NOCREATE target options:\n"
" none\n"
	);
}

static struct xtables_target ct_target_reg[] = {
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "NOCREATE",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_nocreate_target_info)),
		.userspacesize = offsetof(struct xt_nocreate_target_info, ct),
	}
};

void _init(void)
{
	xtables_register_targets(ct_target_reg, ARRAY_SIZE(ct_target_reg));
}