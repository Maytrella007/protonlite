# Container image for the protonlite MCP server (stdio transport).
# An MCP client -- or Glama's introspection probe -- connects over stdio and
# the server answers tools/list without needing a Proton session; a real call
# reuses a session created out of band by `protonlite login`.
FROM python:3.12-slim

# gpg is only used for calendar/Drive key provisioning. It is not needed to
# start the server or to list tools, but a real deployment wants it present.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[mcp]"

# Speak MCP over stdio. This is what an MCP client launches.
ENTRYPOINT ["protonlite-mcp"]
