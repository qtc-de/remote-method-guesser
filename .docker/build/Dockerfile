FROM openjdk:8

COPY . /usr/rmg/testserver

WORKDIR /usr/rmg/testserver
RUN set -ex \
    && javac -d "./" src/IServer.java \
    && javac -d "./" src/Server.java \
    && javac -d "./" src/IServer2.java \
    && javac -d "./" src/Server2.java

CMD ["bash", "entrypoint.sh"]
