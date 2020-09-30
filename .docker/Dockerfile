FROM alpine:latest

# Copy server code and keystore
COPY ./resources/trust/store.p12 /opt/store.p12
COPY ./resources/rmg-example-server.jar /opt/example-server.jar
COPY ./resources/commons-collections-3.1.jar /usr/lib/jvm/java-1.8-openjdk/jre/lib/ext/commons-collections-3.1.jar

# Install openjdk8
RUN set -ex \
    && apk update \
    && apk add openjdk8 \
    && rm -rf /var/cache/apk/*

# Set required java options
ENV _JAVA_OPTIONS -Djava.rmi.server.hostname=iinsecure.dev \
    -Djavax.net.ssl.keyStorePassword=password \
    -Djavax.net.ssl.keyStore=/opt/store.p12 \
    -Djavax.net.ssl.keyStoreType=pkcs12

# Run the server
CMD ["/usr/lib/jvm/java-1.8-openjdk/bin/java", "-jar", "/opt/example-server.jar"]
