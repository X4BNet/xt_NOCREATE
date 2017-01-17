/*
 * Copyright (c) 2010-2013 Patrick McHardy <kaber@trash.net>
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/xt_CT.h>

static void ct_help(void)
{
	printf(
"NOCREATE target options:\n"
" none\n"
	);
}

static void nocreate_ct0_tg_init(struct xt_entry_target *target)
{
	struct xt_ct_target_info *info = (void *)target->data;

	info->flags = XT_CT_NOCREATE;
}

static struct xtables_target ct_target_reg[] = {
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "NOCREATE",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(0),
		.userspacesize = 0,
		.init          = nocreate_ct0_tg_init,
	}
};

void _init(void)
{
	xtables_register_targets(ct_target_reg, ARRAY_SIZE(ct_target_reg));
}