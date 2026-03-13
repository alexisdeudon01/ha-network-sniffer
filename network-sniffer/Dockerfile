ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache tcpdump python3 py3-requests

COPY run.sh /run.sh
COPY sniffer.py /sniffer.py
RUN chmod +x /run.sh

CMD ["/run.sh"]
