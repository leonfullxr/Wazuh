# EXPERIMENTAL depth-lane shim (README s3.4). CPU torch wheel by default to
# keep the image sane; for CUDA build with
#   --build-arg TORCH_CHANNEL=https://download.pytorch.org/whl/cu124   (verify
# the channel against your driver) and uncomment the GPU deploy stanza in the
# compose file. Layer streaming without a GPU is unverified upstream and
# slower still.
FROM python:3.12-slim
WORKDIR /app
ARG TORCH_CHANNEL=https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir torch --index-url ${TORCH_CHANNEL}
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
