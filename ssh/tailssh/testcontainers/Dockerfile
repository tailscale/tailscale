ARG BASE
FROM ${BASE}

RUN groupadd -g 10000 groupone
RUN groupadd -g 10001 grouptwo
RUN useradd -g 10000 -G 10001 -u 10002 -m testuser
COPY . .

# First run tests normally.
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.run TestIntegration

# Then remove the login command and make sure tests still pass.
RUN rm `which login`
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.run TestIntegration

# Then run tests as non-root user testuser.
RUN chown testuser:groupone /tmp/tailscalessh.log
RUN TAILSCALED_PATH=`pwd`tailscaled su -m testuser -c "./tailssh.test -test.run TestIntegration"
