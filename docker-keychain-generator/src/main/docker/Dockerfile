FROM ${docker.java.image}

USER root
RUN mkdir -p /opt/keychain-generator/data

COPY maven/libs/*.jar /opt/keychain-generator
COPY maven/*.sh /opt/keychain-generator

RUN chmod 755 /opt/keychain-generator/*.sh && chown -R java /opt/keychain-generator && chgrp -R java /opt/keychain-generator

USER java

ENTRYPOINT ["/opt/keychain-generator/startup.sh"]
