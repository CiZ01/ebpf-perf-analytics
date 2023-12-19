struct xdp_program *load_bpf_and_xdp_attach(struct config *cfg)
{
	/* In next assignment this will be moved into ../common/ */
	int prog_fd = -1;
	int err;

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	xdp_opts.open_filename = cfg->filename;
	xdp_opts.prog_name = cfg->progname;
	xdp_opts.opts = &opts;

	/* If flags indicate hardware offload, supply ifindex */
	/* if (cfg->xdp_flags & XDP_FLAGS_HW_MODE) */
	/* 	offload_ifindex = cfg->ifindex; */

	struct xdp_program *prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		char errmsg[1024];
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_program__attach(prog, cfg->ifindex, cfg->attach_mode, 0);
	if (err)
		exit(err);

	prog_fd = xdp_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERR: xdp_program__fd failed: %s\n", strerror(errno));
		exit(EXIT_FAIL_BPF);
	}

	return prog;
}
