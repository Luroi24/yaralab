FROM debian:bookworm-slim

# Install YARA and its dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        automake libtool make gcc pkg-config \
        libssl-dev libmagic-dev git ca-certificates && \
    git clone https://github.com/VirusTotal/yara.git && \
    cd yara && \
    git submodule update --init --recursive && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-magic --enable-dotnet && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf yara && \
    apt-get purge -y git gcc automake libtool pkg-config && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
    
# Set up python3, pip3, yara-python
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip3 install yara-python --break-system-packages

# Set the working directory
WORKDIR /rules

# Copy YARA rules into the container
COPY rules/raw/*.yar /rules/

# Expose port if necessary (not needed for local rule matching)
EXPOSE 3333

# Entrypoint to yara (optional, uncomment if you want direct execution)
# ENTRYPOINT ["yara"]

# Copy YARA rules into the container
#COPY rules/*.yar /rules/
# Set the entrypoint to run YARA
#ENTRYPOINT ["yara"]
# Default command to run YARA with the rules
#CMD ["-r", "/rules/"]
# Expose the default YARA port (if applicable, otherwise this line can be omitted)