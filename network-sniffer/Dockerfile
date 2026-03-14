ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache tcpdump python3 py3-pip wireless-tools iw
RUN pip3 install flask --break-system-packages

COPY run.sh /run.sh
COPY app.py /app.py
COPY templates/index.html /templates/index.html
RUN chmod +x /run.sh

CMD ["/run.sh"]
