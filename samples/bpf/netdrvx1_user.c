#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bpf_load.h"
#include "libbpf.h"

static int set_link_bpf_fd(int ifindex, int fd)
{
	struct sockaddr_nl sa;
	int sock, seq = 0, len, ret = -1;
	char buf[4096];
	struct rtattr *rta;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

        printf("fd is: %d\n", fd);
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;
	rta = (struct rtattr *)(((char *) &req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type = 42/*IFLA_BPF_FD*/;
	rta->rta_len = RTA_LENGTH(sizeof(unsigned int));
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len)
		+ RTA_LENGTH(sizeof(fd));
	memcpy(RTA_DATA(rta), &fd, sizeof(fd));
	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		printf("recv from netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
	     nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_pid != getpid()) {
			printf("Wrong pid %d, expected %d\n",
			       nh->nlmsg_pid, getpid());
			goto cleanup;
		}
		if (nh->nlmsg_seq != seq) {
			printf("Wrong seq %d, expected %d\n",
			       nh->nlmsg_seq, seq);
			goto cleanup;
		}
		switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
			err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (!err->error)
				continue;
			printf("nlmsg error %s\n", strerror(-err->error));
			goto cleanup;
		case NLMSG_DONE:
			break;
		}
	}

	ret = 0;

cleanup:
	close(sock);
	return ret;
}

/* simple per-protocol drop counter
 */
static void poll_stats(int secs)
{
	unsigned int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	__u64 values[nr_cpus];
	__u32 key;
	int i;

	sleep(secs);

	for (key = 0; key < 256; key++) {
		__u64 sum = 0;

		assert(bpf_lookup_elem(map_fd[0], &key, values) == 0);
		for (i = 0; i < nr_cpus; i++)
			sum += values[i];
		if (sum)
			printf("proto %u: %10llu drops/s\n", key, sum/secs);
	}
}

int main(int ac, char **argv)
{
	char filename[256];
	int ifindex;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (ac != 2) {
		printf("usage: %s IFINDEX\n", argv[0]);
		return 1;
	}

	ifindex = strtoul(argv[1], NULL, 0);

        printf("Loading bpf filename %s\n", filename);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

        printf("Checking prog_fd: %d\n", prog_fd[0]);
	if (!prog_fd[0]) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	if (set_link_bpf_fd(ifindex, prog_fd[0]) < 0) {
		printf("link set bpf fd failed\n");
		return 1;
	}

        printf("running poll_stats now \n");
	poll_stats(5);

	set_link_bpf_fd(ifindex, -1);

	return 0;
}
