# Multi-purpose Linux container for SecureFileGuard C++17 + Python testbench
FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required build tools (g++ C++17, make) and Python 3 runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set container working directory on native ext4/overlay filesystem
WORKDIR /app

# Copy project files into container
COPY . /app

# Ensure shell scripts are executable
RUN chmod +x tools/make_fixtures.sh scripts/run.sh scripts/run_all_tests.sh

# Compile all C++17 binaries (guard_cli, toctou_race, run_tests)
RUN make clean && make all

# Generate test fixtures on native Linux filesystem path
RUN bash tools/make_fixtures.sh runtime/fixtures

# Pre-generate baseline results/results.csv during container build and ensure results/ is writable
RUN mkdir -p results && \
    ./build/run_tests runtime/fixtures results/results.csv && \
    cp results/results.csv server/static/results.csv && \
    chmod -R 777 results

# Expose default port (overridden at runtime by cloud hosts via $PORT)
ENV HOST=0.0.0.0
ENV PORT=10000
EXPOSE 10000

# Launch server binding to 0.0.0.0 and dynamically reading $PORT, $HOST, and $ALLOWED_HOSTS
CMD ["sh", "-c", "exec python3 server/app.py --host ${HOST:-0.0.0.0} --port ${PORT:-10000} ${ALLOWED_HOST:+--allowed-host \"$ALLOWED_HOST\"}"]
