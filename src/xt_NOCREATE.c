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
#include <net/netfilter/nf_conntrack_zones.h>
#include <uapi/linux/netfilter/xt_state.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/netfilter/nf_conntrack_zones_common.h>
#include "xt_NOCREATE.h"

static unsigned int
nocreate_tg_(struct sk_buff *skb, const struct xt_action_param *par, unsigned int result)
{
	const struct xt_nocreate_target_info *info;
	enum ip_conntrack_info ctinfo;
	struct nf_conn * tmpl = nf_ct_get(skb, &ctinfo);
	if (tmpl == NULL) {
		info = par->targinfo;
		atomic_inc(&info->ct->ct_general.use);
		nf_ct_set(skb, info->ct, IP_CT_NEW);
	}

	return result;
}


static unsigned int
nocreate_tg(struct sk_buff *skb, const struct xt_action_param *par){
	return nocreate_tg_(skb, par, XT_CONTINUE);
}


static unsigned int
nocreatea_tg(struct sk_buff *skb, const struct xt_action_param *par){
	return nocreate_tg_(skb, par, NF_ACCEPT);
}

static inline void nf_conntrack_set_tcp_established(struct nf_conn *ct)
{
	ct->proto.tcp.state = TCP_CONNTRACK_ESTABLISHED;
	__set_bit(IPS_ASSURED_BIT, &ct->status);
	//__set_bit(IPS_CONFIRMED_BIT, &ct->status);
	//ct->proto.tcp.seen[0].td_maxwin = 0;
	//ct->proto.tcp.seen[1].td_maxwin = 0;

	
	ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_SACK_PERM |
						IP_CT_TCP_FLAG_BE_LIBERAL;

	ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_SACK_PERM |
						IP_CT_TCP_FLAG_BE_LIBERAL;

}

static struct nf_conn* 
resolve_normal_ct(const struct nf_conntrack_zone *zone,
		  struct sk_buff *skb,
		  u_int8_t protonum,
		  struct net *net)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_zone tmp;
	struct nf_conn *ct;
	u32 hash;

	if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb),
				 protonum, net,
			     &tuple)) {
		pr_debug("Can't get tuple\n");
		return NULL;
	}

	/* look for tuple match */
	h = nf_conntrack_find_get(net, zone, &tuple);
	if (!h || IS_ERR(h)) {
		return NULL;
	}
	return nf_ct_tuplehash_to_ctrack(h);
}

static unsigned int
tcpcreate_tg_(struct sk_buff *skb, const struct xt_action_param *par, unsigned int result){
	enum ip_conntrack_info ctinfo;
	struct nf_conn * ct = nf_ct_get(skb, &ctinfo);

	if(ct == NULL){
		local_bh_disable();

		ct = resolve_normal_ct(&nf_ct_zone_dflt, skb, xt_family(par), xt_net(par));
		if(ct != NULL) {
			if(nf_ct_protonum(ct) == IPPROTO_TCP) {
				spin_lock(&ct->lock);

				nf_conntrack_set_tcp_established(ct);

				atomic_inc(&ct->ct_general.use);
				nf_ct_set(skb, ct, IP_CT_ESTABLISHED);

				spin_unlock(&ct->lock);
			}
		}

		local_bh_enable();
	}

	return result;
}

static unsigned int
tcpcreate_tg(struct sk_buff *skb, const struct xt_action_param *par){
	return tcpcreate_tg_(skb, par, XT_CONTINUE);
}

static unsigned int
tcpcreatea_tg(struct sk_buff *skb, const struct xt_action_param *par){
	return tcpcreate_tg_(skb, par, NF_ACCEPT);
}

static int nocreate_chk(const struct xt_tgchk_param *par)
{
	struct xt_nocreate_target_info *info = par->targinfo;
	struct nf_conn *ct;
	struct nf_conntrack_zone zone;
	int ret;	

	ret = nf_ct_netns_get(par->net, par->family);
	if (ret < 0){
		pr_info_ratelimited("cannot load conntrack support for proto=%u\n",
				    par->family);
        	goto err1;
	}
	
	memset(&zone, 0, sizeof(zone));
	zone.dir = NF_CT_DEFAULT_ZONE_DIR;

	ct = nf_ct_tmpl_alloc(par->net, &zone, GFP_KERNEL);
	if (!ct) {
		ret = -ENOMEM;
		goto err;
	}
	
	__set_bit(IPS_CONFIRMED_BIT, &ct->status);
	__set_bit(IPS_NOCREATE_BIT, &ct->status);
	
	nf_conntrack_get(&ct->ct_general);

	info->ct = ct;
err:
	return ret;
err1:
//	nf_ct_l3proto_module_put(par->family);
	return ret;
}

static void xt_nocreate_tg_destroy(const struct xt_tgdtor_param *par,
			     struct xt_nocreate_target_info *info)
{
	nf_ct_put(info->ct);
	nf_ct_netns_put(par->net, par->family);
}

static void xt_nocreate_tg_destroy_v0(const struct xt_tgdtor_param *par)
{
	struct xt_nocreate_target_info *info = par->targinfo;

	xt_nocreate_tg_destroy(par, info);
}

static struct xt_target nocreate_tg_reg[] __read_mostly = {
	{
		.name		= "NOCREATE",
		.revision	= 0,
		.family		= NFPROTO_UNSPEC,
		.checkentry	= nocreate_chk,
		.target		= nocreate_tg,
		.destroy	= xt_nocreate_tg_destroy_v0,
		.targetsize     = sizeof(struct xt_nocreate_target_info),
		.table		= "raw",
		.me		= THIS_MODULE,
	},
	{
		.name		= "NOCREATEA",
		.revision	= 0,
		.family		= NFPROTO_UNSPEC,
		.checkentry	= nocreate_chk,
		.target		= nocreatea_tg,
		.destroy	= xt_nocreate_tg_destroy_v0,
		.targetsize     = sizeof(struct xt_nocreate_target_info),
		.table		= "raw",
		.me		= THIS_MODULE,
	},
	{
		.name		= "TCPCREATE",
		.revision	= 0,
		.family		= NFPROTO_UNSPEC,
		.checkentry	= nocreate_chk,
		.target		= tcpcreate_tg,
		.destroy	= xt_nocreate_tg_destroy_v0,
		.targetsize     = sizeof(struct xt_nocreate_target_info),
		.table		= "mangle",
		.me		= THIS_MODULE,
	},
	{
		.name		= "TCPCREATEA",
		.revision	= 0,
		.family		= NFPROTO_UNSPEC,
		.checkentry	= nocreate_chk,
		.target		= tcpcreatea_tg,
		.destroy	= xt_nocreate_tg_destroy_v0,
		.targetsize     = sizeof(struct xt_nocreate_target_info),
		.table		= "mangle",
		.me		= THIS_MODULE,
	}
};

static int __init xt_ct_tg_init(void)
{
	int ret;

	ret = xt_register_targets(nocreate_tg_reg, ARRAY_SIZE(nocreate_tg_reg));
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit xt_ct_tg_exit(void)
{
	xt_unregister_targets(nocreate_tg_reg, ARRAY_SIZE(nocreate_tg_reg));
}

module_init(xt_ct_tg_init);
module_exit(xt_ct_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: nocreate target");

MODULE_ALIAS("ipt_NOCREATE");
MODULE_ALIAS("ip6t_NOCREATE");

MODULE_ALIAS("xt_NOCREATEA");
MODULE_ALIAS("ipt_NOCREATEA");
MODULE_ALIAS("ip6t_NOCREATEA");

MODULE_ALIAS("xt_TCPCREATE");
MODULE_ALIAS("ipt_TCPCREATE");
MODULE_ALIAS("ip6t_TCPCREATE");