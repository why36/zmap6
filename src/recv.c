/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "recv.h"

#include <assert.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/pbm.h"

#include <pthread.h>
#include <unistd.h>

#include "recv-internal.h"
#include "state.h"
#include "validate.h"
#include "fieldset.h"
#include "expression.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/output_modules.h"


#include "../lib/uthash.h"

#define MAX_PROBEPACKETS 10000000

typedef struct {
    struct in6_addr address;
    UT_hash_handle hh;
} IPv6Address;


IPv6Address* findAddress(IPv6Address* set, struct in6_addr address) {
    IPv6Address* foundAddr = NULL;
    HASH_FIND(hh, set, &address, sizeof(struct in6_addr), foundAddr);
    return foundAddr;
}


void insertAddress(IPv6Address** set, struct in6_addr address) {
    IPv6Address* existingAddr = findAddress(*set, address);
    if (existingAddr != NULL) {
        printf("Address already exists\n");
        return;
    }

    IPv6Address* ipv6Addr = (IPv6Address*)malloc(sizeof(IPv6Address));
    ipv6Addr->address = address;
    HASH_ADD(hh, *set, address, sizeof(struct in6_addr), ipv6Addr);
}


size_t getAddressCount(IPv6Address* set) {
    return HASH_COUNT(set);
}


typedef struct {
    struct in6_addr routerIP;
    IPv6Address* nextHops;
    uint32_t flows;
    UT_hash_handle hh;
} Router;


Router* findRouter(Router* routerSet, struct in6_addr searchIP) {
    Router* foundRouter = NULL;
    HASH_FIND(hh, routerSet, &searchIP, sizeof(struct in6_addr), foundRouter);
    return foundRouter;
}

void insertRouter(Router** routerSet, struct in6_addr newRouterIP) {
    Router* existingRouter = findRouter(*routerSet, newRouterIP);
    if (existingRouter != NULL) {
		existingRouter->flows++;
        printf("Router already exists\n");
        return;
    }
    Router* newRouter = (Router*)malloc(sizeof(Router));
    newRouter->routerIP = newRouterIP;
    newRouter->nextHops = NULL;
    newRouter->flows = 0;
    HASH_ADD(hh, *routerSet, routerIP, sizeof(struct in6_addr), newRouter);
}

size_t getRouterCount(Router* routerSet) {
    return HASH_COUNT(routerSet);
}

typedef struct  {
    struct in6_addr saddr; 
    struct in6_addr icmp_responder;
    uint8_t ttl; 
} ProbePacket;

ProbePacket packets[MAX_PROBEPACKETS];
int current_index = 0;

static u_char fake_eth_hdr[65535];
// bitmap of observed IP addresses
static uint8_t **seen = NULL;

// IPv6
static int ipv6 = 0;

//MDA status
static Router* routerSet = NULL;

void handle_packet(uint32_t buflen, const u_char *bytes,
		   const struct timespec ts)
{
	struct ip *ip_hdr;
	uint32_t src_ip;
	uint32_t validation[VALIDATE_BYTES / sizeof(uint8_t)];

	// IPv6
	struct ip6_hdr *ipv6_hdr;

	// IPv6
	if (ipv6) {
		if ((sizeof(struct ip6_hdr) + zconf.data_link_size) > buflen) {
			// buffer not large enough to contain ethernet
			// and ip headers. further action would overrun buf
			return;
		}
		ipv6_hdr = (struct ip6_hdr *)&bytes[zconf.data_link_size];

		validate_gen_ipv6(&ipv6_hdr->ip6_dst, &(ipv6_hdr->ip6_src), (uint8_t *)validation);
		ip_hdr = (struct ip *) ipv6_hdr;
	} else {
		if ((sizeof(struct ip) + zconf.data_link_size) > buflen) {
			// buffer not large enough to contain ethernet
			// and ip headers. further action would overrun buf
			return;
		}
		ip_hdr = (struct ip *)&bytes[zconf.data_link_size];

		src_ip = ip_hdr->ip_src.s_addr;

		// TODO: for TTL exceeded messages, ip_hdr->saddr is going to be
		// different and we must calculate off potential payload message instead
		validate_gen(ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr,
				 (uint8_t *)validation);
	}

	if (!zconf.probe_module->validate_packet(
		ip_hdr,
		buflen - (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header)),
		&src_ip, validation)) {
		zrecv.validation_failed++;
		return;
	} else {
		zrecv.validation_passed++;
	}

	// IPv6
	int is_repeat;
	if (ipv6) {
		is_repeat = 0;
	} else {
		// woo! We've validated that the packet is a response to our scan
		is_repeat = pbm_check(seen, ntohl(src_ip));
		// track whether this is the first packet in an IP fragment.
		if (ip_hdr->ip_off & IP_MF) {
			zrecv.ip_fragments++;
		}
	}

	fieldset_t *fs = fs_new_fieldset(&zconf.fsconf.defs);
	// IPv6
	if (ipv6) {
		fs_add_ipv6_fields(fs, ipv6_hdr);
	} else {
		fs_add_ip_fields(fs, ip_hdr);
	}

	// HACK:
	// probe modules expect the full ethernet frame
	// in process_packet. For VPN, we only get back an IP frame.
	// Here, we fake an ethernet frame (which is initialized to
	// have ETH_P_IP proto and 00s for dest/src).
	if (zconf.send_ip_pkts) {
		if (buflen > sizeof(fake_eth_hdr)) {
			buflen = sizeof(fake_eth_hdr);
		}
		memcpy(&fake_eth_hdr[sizeof(struct ether_header)],
		       bytes + zconf.data_link_size, buflen);
		bytes = fake_eth_hdr;
	}
	//before we process the packet, handle the mda stuff
	if (ipv6) {
		if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6){
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (&ipv6_hdr[1]);
			struct ip6_hdr *ipv6_inner = (struct ip6_hdr *) &icmp6[1];
			struct in6_addr saddr = ipv6_inner->ip6_dst;
			struct in6_addr icmp_responder  = ipv6_inner->ip6_src;
			uint8_t origin_ttl = (uint8_t)(ipv6_inner->ip6_ctlun.ip6_un1.ip6_un1_flow >> 24);
			ProbePacket packet = {saddr, icmp_responder, origin_ttl};
			if (current_index < MAX_PROBEPACKETS) {
				packets[current_index] = packet;
				current_index++;
			}else{
				fprintf(stderr, "Too many packets\n");
			}
		}
	}
	zconf.probe_module->process_packet(bytes, buflen, fs, validation, ts);
	fs_add_system_fields(fs, is_repeat, zsend.complete);
	int success_index = zconf.fsconf.success_index;
	assert(success_index < fs->len);
	int is_success = fs_get_uint64_by_index(fs, success_index);

	if (is_success) {
		zrecv.success_total++;
		if (!is_repeat) {
			zrecv.success_unique++;
			pbm_set(seen, ntohl(src_ip));
		}
		if (zsend.complete) {
			zrecv.cooldown_total++;
			if (!is_repeat) {
				zrecv.cooldown_unique++;
			}
		}
	} else {
		zrecv.failure_total++;
	}
	// probe module includes app_success field
	if (zconf.fsconf.app_success_index >= 0) {
		int is_app_success =
		    fs_get_uint64_by_index(fs, zconf.fsconf.app_success_index);
		if (is_app_success) {
			zrecv.app_success_total++;
			if (!is_repeat) {
				zrecv.app_success_unique++;
			}
		}
	}

	fieldset_t *o = NULL;
	// we need to translate the data provided by the probe module
	// into a fieldset that can be used by the output module
	if (!is_success && zconf.default_mode) {
		goto cleanup;
	}
	if (is_repeat && zconf.default_mode) {
		goto cleanup;
	}
	if (!evaluate_expression(zconf.filter.expression, fs)) {
		goto cleanup;
	}
	zrecv.filter_success++;
	o = translate_fieldset(fs, &zconf.fsconf.translation);
	if (zconf.output_module && zconf.output_module->process_ip) {
		zconf.output_module->process_ip(o);
	}
cleanup:
	fs_free(fs);
	free(o);
	if (zconf.output_module && zconf.output_module->update &&
	    !(zrecv.success_unique % zconf.output_module->update_interval)) {
		zconf.output_module->update(&zconf, &zsend, &zrecv);
	}
}

int recv_run(pthread_mutex_t *recv_ready_mutex)
{
	// IPv6
	if (zconf.ipv6_target_filename) {
		ipv6 = 1;
	}

	log_trace("recv", "recv thread started");
	log_debug("recv", "capturing responses on %s", zconf.iface);
	if (!zconf.dryrun) {
		recv_init();
	}
	if (zconf.send_ip_pkts) {
		struct ether_header *eth = (struct ether_header *)fake_eth_hdr;
		memset(fake_eth_hdr, 0, sizeof(fake_eth_hdr));
		eth->ether_type = htons(ETHERTYPE_IP);
	}
	// initialize paged bitmap
	seen = pbm_init();
	if (zconf.default_mode) {
		log_info("recv",
			 "duplicate responses will be excluded from output");
		log_info("recv",
			 "unsuccessful responses will be excluded from output");
	} else {
		log_info(
		    "recv",
		    "duplicate responses will be passed to the output module");
		log_info(
		    "recv",
		    "unsuccessful responses will be passed to the output module");
	}
	pthread_mutex_lock(recv_ready_mutex);
	zconf.recv_ready = 1;
	pthread_mutex_unlock(recv_ready_mutex);
	zrecv.start = now();
	if (zconf.max_results == 0) {
		zconf.max_results = -1;
	}

	do {
		if (zconf.dryrun) {
			sleep(1);
		} else {
			recv_packets();
			if (zconf.max_results &&
			    zrecv.filter_success >= zconf.max_results) {
				break;
			}
		}
	} while (
	    !(zsend.complete && (now() - zsend.finish > zconf.cooldown_secs)));
	zrecv.finish = now();
	// get final pcap statistics before closing
	recv_update_stats();
	if (!zconf.dryrun) {
		pthread_mutex_lock(recv_ready_mutex);
		recv_cleanup();
		pthread_mutex_unlock(recv_ready_mutex);
	}
	zrecv.complete = 1;
	log_debug("recv", "thread finished");
	return 0;
}
