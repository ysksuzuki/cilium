/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

#ifndef __EGRESS_GATEWAY_H_
#define __EGRESS_GATEWAY_H_

#ifdef ENABLE_EGRESS_GATEWAY

#include <bpf/compiler.h>
#include <bpf/ctx/ctx.h>

#include <linux/ip.h>

#include "encap.h"
#include "maps.h"

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32)* 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

static __always_inline
int fill_egress_ct_key(struct ipv4_ct_tuple *ct_key, struct __ctx_buff *ctx,
		       const struct iphdr *ip4, int l4_off)
{
	struct {
		__be16 sport;
		__be16 dport;
	} ports;

	if (ctx_load_bytes(ctx, l4_off, &ports, 4) < 0)
		return DROP_INVALID;

	ct_key->saddr = ip4->saddr;
	ct_key->daddr = ip4->daddr;
	ct_key->nexthdr = ip4->protocol;
	ct_key->sport = ports.sport;
	ct_key->dport = ports.dport;

	return 0;
}

static __always_inline
struct egress_ct *lookup_ip4_egress_ct(struct ipv4_ct_tuple *ct_key)
{
	return map_lookup_elem(&EGRESS_CT_MAP, ct_key);
}

static __always_inline
void update_egress_ct_entry(struct ipv4_ct_tuple *ct_key, __be32 gateway)
{
	struct egress_ct egress_ct = {
		.gateway_ip = gateway
	};

	map_update_elem(&EGRESS_CT_MAP, ct_key, &egress_ct, 0);
}

static __always_inline
void fill_egress_key(struct egress_policy_key *key, __be32 saddr, __be32 daddr)
{
	key->lpm_key.prefixlen = EGRESS_IPV4_PREFIX;
	key->saddr = saddr;
	key->daddr = daddr;
}

static __always_inline
struct egress_policy *lookup_ip4_egress_policy(struct egress_policy_key *key)
{
	return map_lookup_elem(&EGRESS_POLICY_MAP, key);
}

static __always_inline
__be32 pick_egress_gateway(const struct egress_policy *policy)
{
	unsigned int index = get_prandom_u32() % policy->size;

	/* Just being extra defensive here while keeping the verifier happy.
	 * Userspace should always guarantee the invariant:
	 *     policy->size < EGRESS_MAX_GATEWAY_NODES"
	 */
	index %= EGRESS_MAX_GATEWAY_NODES;

	return policy->gateway_ips[index];
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_EGRESS_GATEWAY_REDIRECT)
int egress_gateway_redirect(struct __ctx_buff *ctx)
{
	struct endpoint_key key = {};
	int ret;

	__u32 dst_id = ctx_load_meta(ctx, CB_DST_ENDPOINT_ID);
	__u8 encrypt_key = ctx_load_meta(ctx, CB_ENCRYPT_KEY);
	__u8 reason = ctx_load_meta(ctx, CB_REASON);
	__u32 monitor = ctx_load_meta(ctx, CB_MONITOR);
	__be32 gateway_ip = ctx_load_meta(ctx, CB_GATEWAY_IP);

	/* Encap and redirect the packet to egress gateway node through a tunnel.
	 * Even if the tunnel endpoint is on the same host, follow the same data
	 * path to be consistent. In future, it can be optimized by directly
	 * direct to external interface.
	 */
	ret = encap_and_redirect_lxc(ctx, gateway_ip, encrypt_key, &key,
				     SECLABEL, monitor);
	if (ret == IPSEC_ENDPOINT) {
		send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, dst_id, 0, 0,
				  reason, monitor);
		cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);
		return CTX_ACT_OK;
	}

	return ret;
}

#endif /* ENABLE_EGRESS_GATEWAY */
#endif /* __EGRESS_GATEWAY_H_ */
