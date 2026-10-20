# linux/amd64 image identity is pinned in dev/toolchain.lock.json.
FROM uv-base AS uv-bin
FROM python-base AS build

ARG SOURCE_DATE_EPOCH
ENV UV_CACHE_DIR=/root/.cache/uv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
WORKDIR /service
COPY --from=uv-bin /uv /usr/local/bin/uv
COPY --from=uv-cache / /root/.cache/uv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN test -n "$SOURCE_DATE_EPOCH" \
    && find /service/src -type f -exec touch -d "@$SOURCE_DATE_EPOCH" {} + \
    && touch -d "@$SOURCE_DATE_EPOCH" pyproject.toml uv.lock README.md \
    && uv sync --offline --locked --no-dev --no-install-project \
    && uv build --offline --wheel --out-dir /tmp/ai-soc-wheel

FROM python-base AS runtime
ARG SERVICE_SHA
ARG CONTENT_SHA
ARG PACK_SHA256
ARG CONTRACT_VERSION=1
ENV PATH="/service/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/nonexistent \
    SOC_MODE=live
WORKDIR /service
COPY --from=build /tmp/ai-soc-wheel/ai_soc-0.1.0-py3-none-any.whl /tmp/ai_soc-0.1.0-py3-none-any.whl
COPY --from=build --chown=10001:10001 /service/.venv /service/.venv
COPY --chown=10001:10001 ui/dist /service/ui/dist
RUN /usr/local/bin/python -m pip --python /service/.venv/bin/python install \
        --no-deps --no-index --no-compile --no-cache-dir --no-warn-script-location \
        /tmp/ai_soc-0.1.0-py3-none-any.whl \
    && chmod -R a+rX /service/.venv
USER root
RUN mkdir -p /tmp && chmod 0755 /tmp && chown 10001:10001 /tmp && chmod 1777 /tmp
VOLUME ["/tmp"]
LABEL org.opencontainers.image.revision="$SERVICE_SHA" \
      org.ai-soc.content.revision="$CONTENT_SHA" \
      org.ai-soc.content.pack.sha256="$PACK_SHA256" \
      org.ai-soc.contract.version="$CONTRACT_VERSION"
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"
CMD ["uvicorn", "ai_soc.live.entrypoint:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
