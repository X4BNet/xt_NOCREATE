/*
 * Copyright (c) 2010 Mathew Heard <mheard@x4b.net>
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
}

static unsigned int
notrack_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct nf_conn * tmpl = skb->nfctl;
	if (tmpl != NULL)
		return XT_CONTINUE;

	if(tmpl != &nf_ct_untracked_get()->ct_general){
		if(nf_ct_is_template(tmpl)){
			tmpl->status |= IPS_CNTRACK;
		}
	}

	return XT_CONTINUE;
}

static int notrack_chk(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target notrack_tg_reg __read_mostly = {
	.name		= "NOCREATE",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.checkentry	= notrack_chk,
	.target		= notrack_tg,
	.table		= "raw",
	.me		= THIS_MODULE,
};

static int __init xt_ct_tg_init(void)
{
	int ret;

	ret = xt_register_target(&notrack_tg_reg);
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit xt_ct_tg_exit(void)
{
	xt_unregister_target(&notrack_tg_reg);
}

module_init(xt_ct_tg_init);
module_exit(xt_ct_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: nocreate target");
MODULE_ALIAS("ipt_NOCREATE");
MODULE_ALIAS("ip6t_NOCREATE");
MODULE_ALIAS("ipt_NOTRACK");
MODULE_ALIAS("ip6t_NOTRACK");