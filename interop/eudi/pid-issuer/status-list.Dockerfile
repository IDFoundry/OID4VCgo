# eudi-srv-statuslist-py, as the PID Issuer's docker-compose builds it
# (docker-compose/status-list/Dockerfile), from a base image pinned by
# digest and the source run-pid-issuer.sh fetched and checked by
# SHA-256 into the build context: the release's app/, and the PID
# Issuer's get_status_list.py, which serves each list by its Accept
# header. Its dependencies are installed from
# status-list-requirements.txt, binary wheels each pinned by SHA-256,
# so no package's setup script runs. run-pid-issuer.sh copies this file
# and that one into the build context.
FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92
WORKDIR /status-list
COPY app/ app/
COPY get_status_list.py requirements.txt /tmp/
RUN cat /tmp/get_status_list.py >> app/status_list_endpoints.py \
    && pip install --no-cache-dir --no-deps --only-binary :all: --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/get_status_list.py /tmp/requirements.txt
EXPOSE 5000
CMD ["flask", "--app", "app", "run", "--host=0.0.0.0"]
