# Debian based container to run YARA rules
FROM debian:bookworm-slim
# Install YARA and its dependencies
RUN apt-get update && \
    apt-get install -y yara && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
    # Set the working directory
    WORKDIR /rules
    # Copy YARA rules into the container
    COPY rules/*.yar /rules/
    # Set the entrypoint to run YARA
    ENTRYPOINT ["yara"]
    # Default command to run YARA with the rules
    CMD ["-r", "/rules/"]
    # Expose the default YARA port (if applicable, otherwise this line can be omitted)
EXPOSE 3333