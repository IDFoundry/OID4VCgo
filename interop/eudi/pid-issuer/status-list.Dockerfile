# eudi-srv-statuslist-py, as the PID Issuer's docker-compose builds it
# (docker-compose/status-list/Dockerfile), from a base image pinned by
# digest and the source run-pid-issuer.sh fetched and checked by
# SHA-256 into the build context: the release's app/, and the PID
# Issuer's get_status_list.py, which serves each list by its Accept
# header. Its requirements.txt pins every direct dependency's version.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
WORKDIR /status-list
COPY app/ app/
COPY get_status_list.py /tmp/get_status_list.py
RUN cat /tmp/get_status_list.py >> app/status_list_endpoints.py \
    && rm /tmp/get_status_list.py \
    && pip install --no-cache-dir -r app/requirements.txt
EXPOSE 5000
CMD ["flask", "--app", "app", "run", "--host=0.0.0.0"]
