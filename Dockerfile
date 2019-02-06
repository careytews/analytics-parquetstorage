FROM fedora:26

RUN dnf install -y libgo

COPY parquetstorage /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/parquetstorage"]
CMD [ "/queue/input" ]


