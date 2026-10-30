FROM scratch
COPY k8s-nameserver /k8s-nameserver
COPY controller /controller
USER 65532:65532
ENTRYPOINT ["/k8s-nameserver"]
