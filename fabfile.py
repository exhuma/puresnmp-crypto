from fabric import task


@task
def doc(ctx):
    ctx.run(
        "./env/bin/sphinx-build -M html doc/ doc/_build",
        pty=True,
        replace_env=False,
    )
