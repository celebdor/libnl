/*
 * lib/route/qdisc/htb.c	HFSC Qdisc
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2014 Antoni Segura Puimedon <antonisp@celebdor.com>
 */

/**
 * @ingroup qdisc
 * @ingroup class
 * @defgroup qdisc_hfsc Hierachical Fair Service Curves (HFSC)
 * @{
 */

#include <netlink-private/netlink.h>
#include <netlink-private/tc.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink-private/route/tc-api.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/class.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc/htb.h>

/** @cond SKIP */
#define SCH_HFSC_HAS_DEFCLS		0x01

#define SCH_HFSC_HAS_RSC			0x001
#define SCH_HFSC_HAS_FSC			0x002
#define SCH_HFSC_HAS_USC			0x004
/** @endcond */

static struct nla_policy hfsc_policy[TCA_HFSC_MAX+1] = {
	[TCA_HFSC_UNSPEC]	= { .type = NLA_U16 },
	[TCA_HFSC_RSC] = { .minlen = sizeof(struct tc_service_curve) },
	[TCA_HFSC_FSC] = { .minlen = sizeof(struct tc_service_curve) },
	[TCA_HFSC_USC] = { .minlen = sizeof(struct tc_service_curve) },
};


static int hfsc_qdisc_msg_parser(struct rtnl_tc *tc, void *data)
{
	struct nlattr *tb[TCA_HFSC_MAX+1];
	struct rtnl_hfsc_qdisc *hfsc = data;
	int err;

	if ((err = tca_parse(tb, TCA_HFSC_MAX, tc, hfsc_policy)) < 0)
		return err;
	
	if (tb[TCA_HFSC_UNSPEC]) {
		struct tc_hfsc_qopt qopt;

		nla_memcpy(&qopt, tb[TCA_HFSC_UNSPEC], sizeof(qopt));
		hfsc->defcls = qopt.defcls;
		hfsc->mask = SCH_HFSC_HAS_DEFCLS;
	}

	return 0;
}

static int hfsc_class_msg_parser(struct rtnl_tc *tc, void *data)
{
	struct nlattr *tb[TCA_HFSC_MAX + 1];
	struct rtnl_hfsc_class *hfsc = data;
	int err;

	if ((err = tca_parse(tb, TCA_HFSC_MAX, tc, hfsc_policy)) < 0)
		return err;
	
	if (tb[TCA_HFSC_RSC]) {
		nla_memcpy(&hfsc->rsc, tb[TCA_HFSC_RSC], sizeof(hfsc->rsc));
		hfsc->mask = SCH_HFSC_HAS_RSC;
	}
	if (tb[TCA_HFSC_FSC]) {
		nla_memcpy(&hfsc->fsc, tb[TCA_HFSC_RSC], sizeof(hfsc->fsc));
		hfsc->mask |= SCH_HFSC_HAS_FSC;
	}
	if (tb[TCA_HFSC_USC]) {
		nla_memcpy(&hfsc->usc, tb[TCA_HFSC_RSC], sizeof(hfsc->usc));
		hfsc->mask |= SCH_HFSC_HAS_USC;
	}

	struct tc_hfsc_stats *stats;
    /* Even though the class stats comes as TCA_STATS_APP, since rtnl_tc does
	 * not have a stats_app field, it stores the data in place of xstats */
	if (!(stats = tca_xstats(tc)))
		return -NLE_MISSING_ATTR;
	memcpy(&hfsc->work, stats, sizeof(struct tc_hfsc_stats));

	return 0;
}

static void hfsc_qdisc_dump_line(struct rtnl_tc *tc, void *data,
				struct nl_dump_params *p)
{
	struct rtnl_hfsc_qdisc *hfsc = data;

	if (!hfsc)
		return;

	if (hfsc->mask & SCH_HFSC_HAS_DEFCLS) {
		char buf[64];
		nl_dump(p, " default-class %s",
			rtnl_tc_handle2str(hfsc->defcls, buf, sizeof(buf)));
	}
}

static void hfsc_class_dump_line(struct rtnl_tc *tc, void *data,
				struct nl_dump_params *p)
{
	struct rtnl_hfsc_class *hfsc = data;

	if (!hfsc)
		return;

	char * rsc = NULL;
	char * fsc = NULL;
	char * usc = NULL;
	if (hfsc->mask & SCH_HFSC_HAS_RSC) {
		double m1, m2;
		char *m1_unit, *m2_unit;

		m1 = nl_cancel_down_bytes(hfsc->rsc.m1, &m1_unit);
		m2 = nl_cancel_down_bytes(hfsc->rsc.m2, &m2_unit);

		asprintf(&rsc, "rs m1 %.2f%s/s d %uus m2 %.2f%s/s", m1, m1_unit,
			hfsc->rsc.d, m2, m2_unit);
	}

	if (hfsc->mask & SCH_HFSC_HAS_FSC) {
		double m1, m2;
		char *m1_unit, *m2_unit;

		m1 = nl_cancel_down_bytes(hfsc->fsc.m1, &m1_unit);
		m2 = nl_cancel_down_bytes(hfsc->fsc.m2, &m2_unit);

		asprintf(&fsc, "%sfs m1 %.2f%s/s d %uus m2 %.2f%s/s",
			rsc ? " " : "", m1, m1_unit, hfsc->fsc.d, m2, m2_unit);
	}
	if (hfsc->mask & SCH_HFSC_HAS_USC) {
		double m1, m2;
		char *m1_unit, *m2_unit;

		m1 = nl_cancel_down_bytes(hfsc->usc.m1, &m1_unit);
		m2 = nl_cancel_down_bytes(hfsc->usc.m2, &m2_unit);

		asprintf(&usc, "%sus m1 %.2f%s/s d %uus m2 %.2f%s/s",
			(rsc || fsc) ? " ": "", m1, m1_unit, hfsc->usc.d, m2, m2_unit);
	}

	nl_dump(p, " %s%s%s", rsc ? rsc : "", fsc ? fsc : "", usc ? usc : "");
}

static void hfsc_class_dump_stats(struct rtnl_tc *tc, void *data,
				   struct nl_dump_params *p)
{
	struct rtnl_hfsc_class *hfsc = data;

	if (!hfsc)
		return;

	nl_dump(p, "period %u ", hfsc->period);
	if (hfsc->work != 0) {
		nl_dump(p, "work %llu bytes ", hfsc->work);
	}
	if (hfsc->rtwork != 0) {
		nl_dump(p, "rtwork %llu bytes ", hfsc->rtwork);
	}
	nl_dump(p, "level %u ", hfsc->level);
}

static int htb_qdisc_msg_fill(struct rtnl_tc *tc, void *data,
			      struct nl_msg *msg)
{
	struct rtnl_htb_qdisc *htb = data;
	struct tc_htb_glob opts = {
        	.version = TC_HTB_PROTOVER,
	        .rate2quantum = 10,
        };

	if (htb) {
		if (htb->qh_mask & SCH_HTB_HAS_RATE2QUANTUM)
			opts.rate2quantum = htb->qh_rate2quantum;

		if (htb->qh_mask & SCH_HTB_HAS_DEFCLS)
			opts.defcls = htb->qh_defcls;
	}

	return nla_put(msg, TCA_HTB_INIT, sizeof(opts), &opts);
}

static int htb_class_msg_fill(struct rtnl_tc *tc, void *data,
			      struct nl_msg *msg)
{
	struct rtnl_htb_class *htb = data;
	uint32_t mtu, rtable[RTNL_TC_RTABLE_SIZE], ctable[RTNL_TC_RTABLE_SIZE];
	struct tc_htb_opt opts;
	int buffer, cbuffer;

	if (!htb || !(htb->ch_mask & SCH_HTB_HAS_RATE))
		BUG();

	memset(&opts, 0, sizeof(opts));

	/* if not set, zero (0) is used as priority */
	if (htb->ch_mask & SCH_HTB_HAS_PRIO)
		opts.prio = htb->ch_prio;

	mtu = rtnl_tc_get_mtu(tc);

	rtnl_tc_build_rate_table(tc, &htb->ch_rate, rtable);
	rtnl_rcopy_ratespec(&opts.rate, &htb->ch_rate);

	if (htb->ch_mask & SCH_HTB_HAS_CEIL) {
		rtnl_tc_build_rate_table(tc, &htb->ch_ceil, ctable);
		rtnl_rcopy_ratespec(&opts.ceil, &htb->ch_ceil);
	} else {
		/*
		 * If not set, configured rate is used as ceil, which implies
		 * no borrowing.
		 */
		memcpy(&opts.ceil, &opts.rate, sizeof(struct tc_ratespec));
	}

	if (htb->ch_mask & SCH_HTB_HAS_RBUFFER)
		buffer = htb->ch_rbuffer;
	else
		buffer = opts.rate.rate / nl_get_psched_hz() + mtu; /* XXX */

	opts.buffer = nl_us2ticks(rtnl_tc_calc_txtime(buffer, opts.rate.rate));

	if (htb->ch_mask & SCH_HTB_HAS_CBUFFER)
		cbuffer = htb->ch_cbuffer;
	else
		cbuffer = opts.ceil.rate / nl_get_psched_hz() + mtu; /* XXX */

	opts.cbuffer = nl_us2ticks(rtnl_tc_calc_txtime(cbuffer, opts.ceil.rate));

	if (htb->ch_mask & SCH_HTB_HAS_QUANTUM)
		opts.quantum = htb->ch_quantum;

	NLA_PUT(msg, TCA_HTB_PARMS, sizeof(opts), &opts);
	NLA_PUT(msg, TCA_HTB_RTAB, sizeof(rtable), &rtable);
	NLA_PUT(msg, TCA_HTB_CTAB, sizeof(ctable), &ctable);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static struct rtnl_tc_ops htb_qdisc_ops;
static struct rtnl_tc_ops htb_class_ops;

static struct rtnl_hfsc_qdisc *hfsc_qdisc_data(struct rtnl_qdisc *qdisc)
{
	return rtnl_tc_data_check(TC_CAST(qdisc), &hfsc_qdisc_ops);
}

static struct rtnl_hfsc_class *hfsc_class_data(struct rtnl_class *class)
{
	return rtnl_tc_data_check(TC_CAST(class), &hfsc_class_ops);
}

/**
 * @name Attribute Modifications
 * @{
 */

/**
 * Return rate/quantum ratio of HTB qdisc
 * @arg qdisc		htb qdisc object
 *
 * @return rate/quantum ratio or 0 if unspecified
 */
uint32_t rtnl_htb_get_rate2quantum(struct rtnl_qdisc *qdisc)
{
	struct rtnl_htb_qdisc *htb;

	if ((htb = htb_qdisc_data(qdisc)) &&
	    htb->qh_mask & SCH_HTB_HAS_RATE2QUANTUM)
		return htb->qh_rate2quantum;

	return 0;
}

int rtnl_htb_set_rate2quantum(struct rtnl_qdisc *qdisc, uint32_t rate2quantum)
{
	struct rtnl_htb_qdisc *htb;

	if (!(htb = htb_qdisc_data(qdisc)))
		return -NLE_OPNOTSUPP;

	htb->qh_rate2quantum = rate2quantum;
	htb->qh_mask |= SCH_HTB_HAS_RATE2QUANTUM;

	return 0;
}

/**
 * Return default class of HTB qdisc
 * @arg qdisc		htb qdisc object
 *
 * Returns the classid of the class where all unclassified traffic
 * goes to.
 *
 * @return classid or TC_H_UNSPEC if unspecified.
 */
uint32_t rtnl_htb_get_defcls(struct rtnl_qdisc *qdisc)
{
	struct rtnl_htb_qdisc *htb;

	if ((htb = htb_qdisc_data(qdisc)) &&
	    htb->qh_mask & SCH_HTB_HAS_DEFCLS)
		return htb->qh_defcls;

	return TC_H_UNSPEC;
}

/**
 * Set default class of the htb qdisc to the specified value
 * @arg qdisc		qdisc to change
 * @arg defcls		new default class
 */
int rtnl_htb_set_defcls(struct rtnl_qdisc *qdisc, uint32_t defcls)
{
	struct rtnl_htb_qdisc *htb;

	if (!(htb = htb_qdisc_data(qdisc)))
		return -NLE_OPNOTSUPP;

	htb->qh_defcls = defcls;
	htb->qh_mask |= SCH_HTB_HAS_DEFCLS;

	return 0;
}

uint32_t rtnl_htb_get_prio(struct rtnl_class *class)
{
	struct rtnl_htb_class *htb;

	if ((htb = htb_class_data(class)) && htb->ch_mask & SCH_HTB_HAS_PRIO)
		return htb->ch_prio;

	return 0;
}

int rtnl_htb_set_prio(struct rtnl_class *class, uint32_t prio)
{
	struct rtnl_htb_class *htb;

	if (!(htb = htb_class_data(class)))
		return -NLE_OPNOTSUPP;

	htb->ch_prio = prio;
	htb->ch_mask |= SCH_HTB_HAS_PRIO;

	return 0;
}

/**
 * Return rate of HTB class
 * @arg class		htb class object
 *
 * @return Rate in bytes/s or 0 if unspecified.
 */
uint32_t rtnl_htb_get_rate(struct rtnl_class *class)
{
	struct rtnl_htb_class *htb;

	if ((htb = htb_class_data(class)) && htb->ch_mask & SCH_HTB_HAS_RATE)
		return htb->ch_rate.rs_rate;

	return 0;
}

/**
 * Set rate of HTB class
 * @arg class		htb class object
 * @arg rate		new rate in bytes per second
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_htb_set_rate(struct rtnl_class *class, uint32_t rate)
{
	struct rtnl_htb_class *htb;

	if (!(htb = htb_class_data(class)))
		return -NLE_OPNOTSUPP;

	htb->ch_rate.rs_cell_log = UINT8_MAX; /* use default value */
	htb->ch_rate.rs_rate = rate;
	htb->ch_mask |= SCH_HTB_HAS_RATE;

	return 0;
}

/**
 * Return ceil rate of HTB class
 * @arg class		htb class object
 *
 * @return Ceil rate in bytes/s or 0 if unspecified
 */
uint32_t rtnl_htb_get_ceil(struct rtnl_class *class)
{
	struct rtnl_htb_class *htb;

	if ((htb = htb_class_data(class)) && htb->ch_mask & SCH_HTB_HAS_CEIL)
		return htb->ch_ceil.rs_rate;

	return 0;
}

/**
 * Set ceil rate of HTB class
 * @arg class		htb class object
 * @arg ceil		new ceil rate number of bytes per second
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_htb_set_ceil(struct rtnl_class *class, uint32_t ceil)
{
	struct rtnl_htb_class *htb;

	if (!(htb = htb_class_data(class)))
		return -NLE_OPNOTSUPP;

	htb->ch_ceil.rs_cell_log = UINT8_MAX; /* use default value */
	htb->ch_ceil.rs_rate = ceil;
	htb->ch_mask |= SCH_HTB_HAS_CEIL;

	return 0;
}

/**
 * Return burst buffer size of HTB class
 * @arg class		htb class object
 *
 * @return Burst buffer size or 0 if unspecified
 */
uint32_t rtnl_htb_get_rbuffer(struct rtnl_class *class)
{
	struct rtnl_htb_class *htb;

	if ((htb = htb_class_data(class)) &&
	     htb->ch_mask & SCH_HTB_HAS_RBUFFER)
		return htb->ch_rbuffer;

	return 0;
}

/**
 * Set size of the rate bucket of HTB class.
 * @arg class		HTB class to be modified.
 * @arg rbuffer		New size in bytes.
 */
int rtnl_htb_set_rbuffer(struct rtnl_class *class, uint32_t rbuffer)
{
	struct rtnl_htb_class *htb;

	if (!(htb = htb_class_data(class)))
		return -NLE_OPNOTSUPP;

	htb->ch_rbuffer = rbuffer;
	htb->ch_mask |= SCH_HTB_HAS_RBUFFER;

	return 0;
}

/**
 * Return ceil burst buffer size of HTB class
 * @arg class		htb class object
 *
 * @return Ceil burst buffer size or 0 if unspecified
 */
uint32_t rtnl_htb_get_cbuffer(struct rtnl_class *class)
{
	struct rtnl_htb_class *htb;

	if ((htb = htb_class_data(class)) &&
	     htb->ch_mask & SCH_HTB_HAS_CBUFFER)
		return htb->ch_cbuffer;

	return 0;
}

/**
 * Set size of the ceil bucket of HTB class.
 * @arg class		HTB class to be modified.
 * @arg cbuffer		New size in bytes.
 */
int rtnl_htb_set_cbuffer(struct rtnl_class *class, uint32_t cbuffer)
{
	struct rtnl_htb_class *htb;

	if (!(htb = htb_class_data(class)))
		return -NLE_OPNOTSUPP;

	htb->ch_cbuffer = cbuffer;
	htb->ch_mask |= SCH_HTB_HAS_CBUFFER;

	return 0;
}

/**
 * Return quantum of HTB class
 * @arg class		htb class object
 *
 * See XXX[quantum def]
 *
 * @return Quantum or 0 if unspecified.
 */
uint32_t rtnl_htb_get_quantum(struct rtnl_class *class)
{
	struct rtnl_htb_class *htb;

	if ((htb = htb_class_data(class)) &&
	    htb->ch_mask & SCH_HTB_HAS_QUANTUM)
		return htb->ch_quantum;

	return 0;
}

/**
 * Set quantum of HTB class (overwrites value calculated based on r2q)
 * @arg class		htb class object
 * @arg quantum		new quantum in number of bytes
 *
 * See XXX[quantum def]
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_htb_set_quantum(struct rtnl_class *class, uint32_t quantum)
{
	struct rtnl_htb_class *htb;

	if (!(htb = htb_class_data(class)))
		return -NLE_OPNOTSUPP;

	htb->ch_quantum = quantum;
	htb->ch_mask |= SCH_HTB_HAS_QUANTUM;

	return 0;
}

/**
 * Return level of HFSC class
 * @arg class		hfsc class object
 *
 * Returns the level of the HFSC class. TODO: explain level numbering (check
 * linux sources).
 *
 * @return Level or -NLE_OPNOTSUPP
 */
int rtnl_hfsc_get_level(struct rtnl_class *class)
{
	struct rtnl_hfsc_class *hfsc;

	if (hfsc = hfsc_class_data(class))
		return hfsc->level;

	return -NLE_OPNOTSUPP;
}

/**
 * Set level of HTB class
 * @arg class		htb class object
 * @arg level		new level of HTB class
 *
 * Sets the level of a HTB class. Note that changing the level of a HTB
 * class does not change the level of its in kernel counterpart. This
 * function is provided only to create HTB objects which can be compared
 * against or filtered upon.
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_htb_set_level(struct rtnl_class *class, int level)
{
	struct rtnl_htb_class *htb;

	if (!(htb = htb_class_data(class)))
		return -NLE_OPNOTSUPP;

	htb->ch_level = level;
	htb->ch_mask |= SCH_HTB_HAS_LEVEL;

	return 0;
}

/** @} */

static struct rtnl_tc_ops hfsc_qdisc_ops = {
	.to_kind		= "hfsc",
	.to_type		= RTNL_TC_TYPE_QDISC,
	.to_size		= sizeof(struct rtnl_hfsc_qdisc),
	.to_msg_parser		= hfsc_qdisc_msg_parser,
	.to_dump[NL_DUMP_LINE]	= hfsc_qdisc_dump_line,
	.to_msg_fill		= htb_qdisc_msg_fill,
};

static struct rtnl_tc_ops hfsc_class_ops = {
	.to_kind		= "hfsc",
	.to_type		= RTNL_TC_TYPE_CLASS,
	.to_size		= sizeof(struct rtnl_hfsc_class),
	.to_msg_parser		= hfsc_class_msg_parser,
	.to_dump = {
	    [NL_DUMP_LINE]	= hfsc_class_dump_line,
	    [NL_DUMP_STATS]	= hfsc_class_dump_stats,
	},
	.to_msg_fill		= htb_class_msg_fill,
};

static void __init hfsc_init(void)
{
	rtnl_tc_register(&hfsc_qdisc_ops);
	rtnl_tc_register(&hfsc_class_ops);
}

static void __exit hfsc_exit(void)
{
	rtnl_tc_unregister(&hfsc_qdisc_ops);
	rtnl_tc_unregister(&hfsc_class_ops);
}

/** @} */
