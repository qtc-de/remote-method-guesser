###########################################
###            Build Stage 1            ###
###########################################
FROM maven:3.8.6-openjdk-8-slim AS maven-builder
COPY ./resources/server /usr/src/app
WORKDIR /usr/src/app
RUN mvn clean package

###########################################
###            Build Stage 2            ###
###########################################
FROM ghcr.io/qtc-de/remote-method-guesser/rmg-ssrf-server:1.4 AS jdk-builder
RUN set -ex \
    && mv /usr/lib/jvm/java-9-openjdk /jdk

###########################################
###          Container Stage            ###
###########################################
FROM curlimages/curl:7.71.0
USER root

COPY ./resources/scripts/start.sh /opt/start.sh
COPY --from=maven-builder /usr/src/app/target/rmg-ssrf-server-*-jar-with-dependencies.jar /opt/ssrf-server.jar
COPY --from=jdk-builder /jdk /usr/lib/jvm/java-9-openjdk

RUN set -ex \
    && ln -s /usr/lib/jvm/java-9-openjdk/bin/java /usr/bin/java \
    && chmod +x /opt/start.sh

EXPOSE 8000/tcp

CMD ["/opt/start.sh"]
