FROM alpine:latest

COPY ./resources/trust/store.p12 /opt/store.p12
COPY ./resources/scripts/start.sh /opt/start.sh
COPY ./resources/conf/policy /opt/policy
COPY ./resources/example-server /opt/server

RUN set -ex \
    && apk add --no-cache openjdk8 maven \
    && cd /opt/server \
    && mvn package \
    && mv target/rmg-example-server-*.jar /opt/example-server.jar \
    && apk del maven \
    && rm -rf ~/.m2 \
    && chmod +x /opt/start.sh

ENV _JAVA_OPTIONS -Djava.rmi.server.hostname=iinsecure.dev \
    -Djavax.net.ssl.keyStorePassword=password \
    -Djavax.net.ssl.keyStore=/opt/store.p12 \
    -Djavax.net.ssl.keyStoreType=pkcs12 \
    -Djava.rmi.server.useCodebaseOnly=false \
    -Djava.security.policy=/opt/policy \
    -Djava.rmi.server.codebase=http://iinsecure.dev/well-hidden-development-folder/

EXPOSE 1090/tcp 9010/tcp

CMD ["/opt/start.sh"]
