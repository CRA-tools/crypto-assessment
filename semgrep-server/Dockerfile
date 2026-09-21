# Use the packaged scanner, Python, and Git instead of resolving and compiling
# Semgrep dependencies on each machine during the application build.
FROM semgrep/semgrep:1.177.0

WORKDIR /app

COPY semgrep_server.py /app/semgrep_server.py
COPY http_handler.py /app/http_handler.py
COPY helpers.py /app/helpers.py
COPY run_command.py /app/run_command.py
COPY semgrep_types.py /app/semgrep_types.py

EXPOSE 9091

ENTRYPOINT []
CMD ["python3", "/app/semgrep_server.py"]
