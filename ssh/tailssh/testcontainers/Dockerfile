ARG BASE
FROM ${BASE}

RUN echo "Install openssh, needed for scp."
RUN apt-get update -y && apt-get install -y openssh-client

RUN groupadd -g 10000 groupone
RUN groupadd -g 10001 grouptwo
# Note - we do not create the user's home directory, pam_mkhomedir will do that
# for us, and we want to test that PAM gets triggered by Tailscale SSH.
RUN useradd -g 10000 -G 10001 -u 10002 testuser

RUN echo "Set up pam_mkhomedir."
RUN sed -i -e 's/Default: no/Default: yes/g' /usr/share/pam-configs/mkhomedir || echo "might not be ubuntu"
RUN cat /usr/share/pam-configs/mkhomedir
RUN pam-auth-update --enable mkhomedir

COPY tailscaled .
COPY tailssh.test .

RUN chmod 755 tailscaled

# RUN echo "First run tests normally."
RUN eval `ssh-agent -s` && TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestSSHAgentForwarding
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSFTP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSCP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSSH

RUN echo "Then run tests as non-root user testuser and make sure tests still pass."
RUN chown testuser:groupone /tmp/tailscalessh.log
RUN TAILSCALED_PATH=`pwd`tailscaled eval `su -m testuser -c ssh-agent -s` && su -m testuser -c "./tailssh.test -test.v -test.run TestSSHAgentForwarding"
RUN TAILSCALED_PATH=`pwd`tailscaled su -m testuser -c "./tailssh.test -test.v -test.run TestIntegration TestDoDropPrivileges"
RUN chown root:root /tmp/tailscalessh.log

RUN echo "Then run tests in a system that's pretending to be SELinux in enforcing mode"
RUN mv /usr/bin/login /tmp/login_orig
# Use nonsense for /usr/bin/login so that it fails.
# It's not the same failure mode as in SELinux, but failure is good enough for test.
RUN echo "adsfasdfasdf" > /usr/bin/login
RUN chmod 755 /usr/bin/login
# Simulate getenforce command
RUN printf "#!/bin/bash\necho 'Enforcing'" > /usr/bin/getenforce
RUN chmod 755 /usr/bin/getenforce
RUN eval `ssh-agent -s` && TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestSSHAgentForwarding
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegration
RUN mv /tmp/login_orig /usr/bin/login
RUN rm /usr/bin/getenforce

RUN echo "Then remove the login command and make sure tests still pass."
RUN rm `which login`
RUN eval `ssh-agent -s` && TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestSSHAgentForwarding
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSFTP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSCP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSSH

RUN echo "Then remove the su command and make sure tests still pass."
RUN chown root:root /tmp/tailscalessh.log
RUN rm `which su`
RUN eval `ssh-agent -s` && TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestSSHAgentForwarding
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegration

RUN echo "Test doDropPrivileges"
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestDoDropPrivileges
