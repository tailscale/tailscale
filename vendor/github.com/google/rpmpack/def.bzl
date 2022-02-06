def _pkg_tar2rpm_impl(ctx):
    files = [ctx.file.data]
    args = ctx.actions.args()
    args.add("--name", ctx.attr.pkg_name)
    args.add("--version", ctx.attr.version)
    args.add("--release", ctx.attr.release)
    args.add("--epoch", ctx.attr.epoch)
    args.add("--prein", ctx.attr.prein)
    args.add("--postin", ctx.attr.postin)
    args.add("--preun", ctx.attr.preun)
    args.add("--postun", ctx.attr.postun)
    args.add_all("--requires", ctx.attr.requires)
    if ctx.attr.build_time != "":
        args.add("--build_time", ctx.attr.build_time)
    args.add("--file", ctx.outputs.out)
    args.add(ctx.file.data)
    ctx.actions.run(
        executable = ctx.executable.tar2rpm,
        arguments = [args],
        inputs = files,
        outputs = [ctx.outputs.out],
        mnemonic = "tar2rpm",
    )

# A rule for generating rpm files
pkg_tar2rpm = rule(
    implementation = _pkg_tar2rpm_impl,
    attrs = {
        "data": attr.label(mandatory = True, allow_single_file = [".tar"]),
        "pkg_name": attr.string(mandatory = True),
        "version": attr.string(mandatory = True),
        "release": attr.string(),
        "epoch": attr.int(),
        "prein": attr.string(),
        "postin": attr.string(),
        "preun": attr.string(),
        "postun": attr.string(),
        "requires": attr.string_list(),
        "build_time": attr.string(),
        "tar2rpm": attr.label(
            default = Label("//cmd/tar2rpm"),
            cfg = "host",
            executable = True,
        ),
    },
    outputs = {
        "out": "%{name}.rpm",
    },
)
