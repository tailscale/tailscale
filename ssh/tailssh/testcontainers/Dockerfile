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

RUN echo "First run tests normally."
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSFTP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSCP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSSH

RUN echo "Then run tests as non-root user testuser and make sure tests still pass."
RUN chown testuser:groupone /tmp/tailscalessh.log
RUN TAILSCALED_PATH=`pwd`tailscaled su -m testuser -c "./tailssh.test -test.v -test.run TestIntegration TestDoDropPrivileges"

RUN echo "Then remove the login command and make sure tests still pass."
RUN chown root:root /tmp/tailscalessh.log
RUN rm `which login`
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSFTP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSCP
RUN rm -Rf /home/testuser
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegrationSSH

RUN echo "Then remove the su command and make sure tests still pass."
RUN chown root:root /tmp/tailscalessh.log
RUN rm `which su`
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestIntegration

RUN echo "Test doDropPrivileges"
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.v -test.run TestDoDropPrivileges
