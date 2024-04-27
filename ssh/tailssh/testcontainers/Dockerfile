ARG BASE
FROM ${BASE}

RUN groupadd -g 10000 groupone
RUN groupadd -g 10001 grouptwo
RUN useradd -g 10000 -G 10001 -u 10002 -m testuser
COPY . .
RUN ./tailssh.test -test.run TestIntegration
# Remove the su command and run the test again to make sure it works without su
RUN rm `which su`
RUN ./tailssh.test -test.run TestIntegration
