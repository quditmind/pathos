FROM ubuntu
RUN apt-get update && apt-get install -y curl wget
ADD https://example.com/tool.tar.gz /opt/
WORKDIR /opt
RUN cd /opt && tar xzf tool.tar.gz
USER root
CMD /opt/tool/run
