FROM alpine:latest

# Copy server code and keystore
COPY ./resources/trust/store.p12 /opt/store.p12
COPY ./resources/example-server /opt/example-server

# Compile server code
RUN set -ex \
    && apk update \
    && apk add maven \
    && apk add openjdk8 \
    && cd /opt/example-server \
    && mvn clean package

# Set required java options
ENV _JAVA_OPTIONS -Djava.rmi.server.hostname=iinsecure.dev \
    -Djavax.net.ssl.keyStorePassword=password \
    -Djavax.net.ssl.keyStore=/opt/store.p12 \
    -Djavax.net.ssl.keyStoreType=pkcs12

# Run the server
CMD ["java", "-jar", "/opt/example-server/target/rmg-example-server.jar"]
