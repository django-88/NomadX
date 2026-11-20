FROM itsafeaturemythic/mythic_python_base:latest

ARG ZIG_VERSION=0.17.1
ARG ZIG_SHA256=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a

RUN apt-get update && apt-get install -y --no-install-recommends \
    mingw-w64 \
    make \
    gcc \
    libc6-dev \
    curl \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz \
    && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/zig.tar.xz -C /opt \
    && ln -sf "/opt/zig-x86_64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig \
    && rm -f /tmp/zig.tar.xz

RUN zig version

RUN pip3 install mythic-container==0.6.0

WORKDIR /Mythic/

COPY . /Mythic/

RUN cd /Mythic/nomadx/custom-donut && make donut \
    && chmod +x /Mythic/nomadx/custom-donut/donut

# PREWARM: populate the global Zig cache so per-payload builds fit inside
# Mythic's RPC timeout even on a freshly recreated container.
RUN cd /Mythic && zig build --release=small

CMD ["python3", "main.py"]
