FROM alibabadragonwell/dragonwell:21-ubuntu
LABEL author="netbuffer"
WORKDIR /
COPY target/spring-security-demo.jar /
ENV SERVER_PORT=18000
EXPOSE 18000
ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar /spring-security-demo.jar"]
