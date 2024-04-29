ARG BASE
FROM ${BASE}

RUN groupadd -g 10000 groupone
RUN groupadd -g 10001 grouptwo
RUN useradd -g 10000 -G 10001 -u 10002 testuser
RUN sed -i -e 's/Default: no/Default: yes/g' /usr/share/pam-configs/mkhomedir || echo "might not be ubuntu"
RUN cat /usr/share/pam-configs/mkhomedir || echo "might not be ubuntu"
RUN pam-auth-update --enable mkhomedir || echo "might not be ubuntu"
RUN authconfig --enablemkhomedir --update || echo "might not be fedora"
COPY . .
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.run TestIntegration
