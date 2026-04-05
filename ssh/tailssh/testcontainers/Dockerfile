ARG BASE
FROM ${BASE}

ARG BASE

RUN echo "Install openssh, needed for scp. Also install python3"
RUN if echo "$BASE" | grep "ubuntu:"; then apt-get update -y && apt-get install -y openssh-client python3 python3-pip; fi
RUN if echo "$BASE" | grep "alpine:"; then apk add openssh python3 py3-pip; fi

RUN echo "Install paramiko"
RUN pip3 install paramiko==3.5.1 || pip3 install --break-system-packages paramiko==3.5.1

# Note - on Ubuntu, we do not create the user's home directory, pam_mkhomedir will do that
# for us, and we want to test that PAM gets triggered by Tailscale SSH.
RUN if echo "$BASE" | grep "ubuntu:"; then groupadd -g 10000 groupone && groupadd -g 10001 grouptwo && useradd -g 10000 -G 10001 -u 10002 testuser; fi
# On Alpine, we can't configure pam_mkhomdir, so go ahead and create home directory.
RUN if echo "$BASE" | grep "alpine:"; then addgroup -g 10000 groupone && addgroup -g 10001 grouptwo && adduser -u 10002 -D testuser && addgroup testuser groupone && addgroup testuser grouptwo; fi

RUN if echo "$BASE" | grep "ubuntu:"; then \
    echo "Set up pam_mkhomedir." && \
    sed -i -e 's/Default: no/Default: yes/g' /usr/share/pam-configs/mkhomedir && \
    cat /usr/share/pam-configs/mkhomedir && \
    pam-auth-update --enable mkhomedir \
    ; fi

COPY tailscaled .
COPY tailssh.test .

RUN chmod 755 tailscaled

# Run tests normally.
# On Ubuntu, delete testuser's home directory between tests to verify
# that PAM's pam_mkhomedir recreates it each time.
RUN set -e && \
    eval $(ssh-agent -s) && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestSSHAgentForwarding && \
    if echo "$BASE" | grep -q "ubuntu:"; then rm -Rf /home/testuser; fi && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestIntegrationSFTP && \
    if echo "$BASE" | grep -q "ubuntu:"; then rm -Rf /home/testuser; fi && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestIntegrationSCP && \
    if echo "$BASE" | grep -q "ubuntu:"; then rm -Rf /home/testuser; fi && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestIntegrationSSH && \
    if echo "$BASE" | grep -q "ubuntu:"; then rm -Rf /home/testuser; fi && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestIntegrationParamiko && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestLocalUnixForwarding && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestReverseUnixForwarding && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestUnixForwardingDenied && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestUnixForwardingPathRestriction

# Run tests as non-root user testuser and make sure tests still pass.
RUN set -e && \
    touch /tmp/tailscalessh.log && \
    chown testuser:groupone /tmp/tailscalessh.log && \
    export TAILSCALED_PATH=$(pwd)/tailscaled && \
    eval $(su -m testuser -c "ssh-agent -s") && \
    su -m testuser -c "./tailssh.test -test.v -test.run 'TestSSHAgentForwarding|TestIntegration|TestDoDropPrivileges'" && \
    echo "Also, deny everyone access to the user's home directory and make sure non file-related tests still pass." && \
    mkdir -p /home/testuser && chown testuser:groupone /home/testuser && chmod 0000 /home/testuser && \
    SKIP_FILE_OPS=1 su -m testuser -c "./tailssh.test -test.v -test.run TestIntegrationSSH" && \
    chmod 0755 /home/testuser && \
    chown root:root /tmp/tailscalessh.log

# On Ubuntu, run tests pretending to be SELinux in enforcing mode.
RUN if echo "$BASE" | grep -q "ubuntu:"; then \
    set -e && \
    echo "Run tests in a system that's pretending to be SELinux in enforcing mode" && \
    mv /usr/bin/login /tmp/login_orig && \
    echo "adsfasdfasdf" > /usr/bin/login && \
    chmod 755 /usr/bin/login && \
    printf "#!/bin/bash\necho 'Enforcing'" > /usr/bin/getenforce && \
    chmod 755 /usr/bin/getenforce && \
    eval $(ssh-agent -s) && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run 'TestSSHAgentForwarding|TestIntegration' && \
    mv /tmp/login_orig /usr/bin/login && \
    rm /usr/bin/getenforce \
    ; fi

# Remove the login command and make sure tests still pass.
RUN set -e && \
    rm $(which login) && \
    eval $(ssh-agent -s) && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestSSHAgentForwarding && \
    if echo "$BASE" | grep -q "ubuntu:"; then rm -Rf /home/testuser; fi && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestIntegrationSFTP && \
    if echo "$BASE" | grep -q "ubuntu:"; then rm -Rf /home/testuser; fi && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestIntegrationSCP && \
    if echo "$BASE" | grep -q "ubuntu:"; then rm -Rf /home/testuser; fi && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run TestIntegrationSSH

# Remove the su command and make sure tests still pass.
RUN set -e && \
    chown root:root /tmp/tailscalessh.log && \
    rm $(which su) && \
    eval $(ssh-agent -s) && \
    TAILSCALED_PATH=$(pwd)/tailscaled ./tailssh.test -test.v -test.run 'TestSSHAgentForwarding|TestIntegration|TestDoDropPrivileges'
