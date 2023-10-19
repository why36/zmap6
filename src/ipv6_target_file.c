/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "../lib/logger.h"

#define LOGGER_NAME "ipv6_target_file"

static FILE *fp;

static char networkAddress[INET6_ADDRSTRLEN + 4];  // 最多支持IPv6地址长度+4个字符的前缀长度
static int prefixLength;
static struct in6_addr network;
static time_t t;

int ipv6_target_file_init(char *file)
{
	if (strcmp(file, "-") == 0) {
		fp = stdin;
	} else {
		fp = fopen(file, "r");
	}
	if (fp == NULL) {
		log_fatal(LOGGER_NAME, "unable to open %s file: %s: %s",
				LOGGER_NAME, file, strerror(errno));
		return 1;
	}
	char line[100];

	if (fgets(line, sizeof(line), fp) != NULL) {
		// Remove newline
		char *pos;
		if ((pos = strchr(line, '\n')) != NULL) {
			*pos = '\0';
		}
		

        if (sscanf(line, "%[^/]/%d", networkAddress, &prefixLength) != 2) {
            log_fatal(LOGGER_NAME, "could not parse IPv6 network from line: %s", line);
            return 1;
        }
        if (inet_pton(AF_INET6, networkAddress, &network) != 1) {
            log_fatal(LOGGER_NAME, "could not parse IPv6 address from line: %s: %s", line, strerror(errno));
            return 1;
        }
		srand((unsigned) time(&t));
	} else {
		return 1;
	}

	return 0;
}

struct in6_addr getRandomIPv6Address(struct in6_addr network, int prefix_length) {
    struct in6_addr randomAddress;

    struct in6_addr subnetMask;
    memset(&subnetMask, 0, sizeof(struct in6_addr));
    int prefixLength = prefix_length;
    for (int i = 0; i < 16; i++) {
        if (prefixLength >= 8) {
            subnetMask.s6_addr[i] = 0xFF;
            prefixLength -= 8;
        } else if (prefixLength > 0) {
            subnetMask.s6_addr[i] = (0xFF << (8 - prefixLength)) & 0xFF;
            prefixLength = 0;
        } else {
            subnetMask.s6_addr[i] = 0;
        }
    }

    struct in6_addr randomHost;
    for (int i = 0; i < 16; i++) {
        randomHost.s6_addr[i] = rand() % 256;
    }

    randomAddress = network;
    for (int i = 0; i < 16; i++) {
        randomAddress.s6_addr[i] |= randomHost.s6_addr[i] & ~subnetMask.s6_addr[i];
    }

    return randomAddress;
}

int ipv6_target_file_get_ipv6_random(struct in6_addr *dst) {
	*dst = getRandomIPv6Address(network, prefixLength);
	return 0;
}

int ipv6_target_file_get_ipv6(struct in6_addr *dst)
{
    // ipv6_target_file_init() needs to be called before ipv6_target_file_get_ipv6()
	assert(fp);

	char line[100];

	if (fgets(line, sizeof(line), fp) != NULL) {
		// Remove newline
		char *pos;
		if ((pos = strchr(line, '\n')) != NULL) {
			*pos = '\0';
		}
		int rc = inet_pton(AF_INET6, line, dst);
		if (rc != 1) {
			log_fatal(LOGGER_NAME, "could not parse IPv6 address from line: %s: %s", line, strerror(errno));
			return 1;
		}
	} else {
		return 1;
	}

	return 0;
}

int ipv6_target_file_deinit()
{
	fclose(fp);
	fp = NULL;

	return 0;
}

