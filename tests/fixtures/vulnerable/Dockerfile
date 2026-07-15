# Deliberately vulnerable Dockerfile fixture for scanner tests.
FROM ubuntu:latest

ENV ADMIN_PASSWORD=SuperSecret123!

RUN apt-get update && apt-get install -y curl

USER root

EXPOSE 22

CMD ["bash"]
