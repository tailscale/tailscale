ARG BASE
FROM ${BASE}

RUN groupadd -g 10000 groupone
RUN groupadd -g 10001 grouptwo
RUN useradd -g 10000 -G 10001 -u 10002 -m testuser
COPY . .
RUN TAILSCALED_PATH=`pwd`tailscaled ./tailssh.test -test.run TestIntegration
