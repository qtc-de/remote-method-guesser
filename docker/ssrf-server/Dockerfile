###########################################
###            Build Stage 1            ###
###########################################
FROM maven:3.8.2-openjdk-8 AS maven-builder
COPY ./resources/server /usr/src/app
WORKDIR /usr/src/app
RUN mvn clean package

###########################################
###            Build Stage 2            ###
###########################################
FROM alpine:latest AS jdk-builder
RUN set -ex \
    && apk add --no-cache openjdk9 \
    && /usr/lib/jvm/java-9-openjdk/bin/jlink --add-modules java.rmi,java.management.rmi,jdk.management.agent,jdk.naming.rmi,jdk.httpserver \
    --verbose --strip-debug --compress 2 --no-header-files --no-man-pages --module-path  /usr/lib/jvm/java-9-openjdk/jmods/ --output /jdk

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
