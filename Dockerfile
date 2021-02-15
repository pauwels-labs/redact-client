FROM debian:8
EXPOSE 8080
CMD ["/redact-client"]
COPY target/release/ /
