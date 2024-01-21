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
FROM alpine:latest AS jdk-builder
RUN set -ex \
    && apk add --no-cache openjdk11 \
    && /usr/lib/jvm/java-11-openjdk/bin/jlink --add-modules java.rmi,java.management.rmi,jdk.unsupported,java.desktop --verbose --strip-debug --compress 2 \
       --no-header-files --no-man-pages --output /jdk

###########################################
###          Container Stage            ###
###########################################
FROM alpine:latest

COPY ./resources/scripts/start.sh /opt/start.sh
COPY --from=maven-builder /usr/src/app/target/rmg-quartz-scheduler-server-*-jar-with-dependencies.jar /opt/quartz-server.jar
COPY --from=jdk-builder /jdk /usr/lib/jvm/java-11-openjdk

RUN set -ex \
    && ln -s /usr/lib/jvm/java-11-openjdk/bin/java /usr/bin/java \
    && chmod +x /opt/start.sh

ENV _JAVA_OPTIONS -Djava.rmi.server.hostname=iinsecure.example \
    -Dorg.quartz.scheduler.rmi.export=true \
    -Dorg.quartz.scheduler.rmi.createRegistry=true \
    -Dorg.quartz.scheduler.rmi.serverPort=4444

EXPOSE 1099/tcp 4444/tcp

CMD ["/opt/start.sh"]
