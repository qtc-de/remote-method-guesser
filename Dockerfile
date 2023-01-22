###########################################
###            Build Stage 1            ###
###########################################
FROM maven:3.8.6-openjdk-8-slim AS maven-builder
COPY ./resources /usr/src/app/resources
COPY ./src /usr/src/app/src
COPY ./pom.xml /usr/src/app/pom.xml
WORKDIR /usr/src/app
RUN mvn clean package

###########################################
###            Build Stage 2            ###
###########################################
FROM alpine:latest AS jdk-builder
RUN set -ex \
    && apk add --no-cache openjdk11 \
    && /usr/lib/jvm/java-11-openjdk/bin/jlink --add-modules java.desktop,java.rmi,java.management.rmi,jdk.unsupported \
       --verbose --strip-debug --compress 2 --no-header-files --no-man-pages --output /jdk

###########################################
###          Container Stage            ###
###########################################
FROM alpine:latest

COPY --from=maven-builder /usr/src/app/target/rmg-*-jar-with-dependencies.jar /opt/rmg.jar
COPY --from=jdk-builder /jdk /usr/lib/jvm/java-11-openjdk

RUN set -ex                                                         \
    && ln -s /usr/lib/jvm/java-11-openjdk/bin/java /usr/bin/java    \
    && adduser -g '' -D -u 1000 rmg-user                            \
    && wget -O /opt/ysoserial.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

USER rmg-user:rmg-user

ENTRYPOINT ["java", "-jar", "/opt/rmg.jar"]
