# Build stage
FROM openjdk:11-jdk as build

WORKDIR /workspace/app

ARG ID_LOG_VERSION=1.0.0-SNAPSHOT
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src
COPY libs libs
#COPY conf conf


RUN ./mvnw install:install-file -Dfile=libs/id-log-${ID_LOG_VERSION}.jar -DgroupId=ee.ria.commons -DartifactId=id-log -Dversion=${ID_LOG_VERSION} -Dpackaging=jar -DgeneratePom=true

# Build the Spring Boot application
RUN ./mvnw package

# Tomcat installation stage
FROM tomcat:latest

#COPY ./target /usr/local/tomcat/webapps/

# Copy the WAR file built in the previous stage to Tomcat's webapps directory
COPY --from=build /workspace/app/target/ /usr/local/tomcat/webapps/

# Copy your custom server.xml to the Tomcat conf directory
#COPY conf/server.xml /usr/local/tomcat/conf/

# Keytool
#ARG KEY_PASS="ppjjpp"
#RUN keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -keystore "/usr/local/tomcat/conf/keystore.jks" -dname "CN=, OU=, O=, L=, ST=, C=" -storepass $KEY_PASS -validity 3650
#RUN keytool -genkeypair -alias jwtsign -keyalg RSA -keysize 2048 -keystore "/usr/local/tomcat/conf/jwtkeystore.jks" -dname "CN=, OU=, O=, L=, ST=, C=" -storepass $KEY_PASS -validity 3650

# Expose the default Tomcat port
EXPOSE 8085
EXPOSE 8443
EXPOSE 8080

CMD ["catalina.sh", "run"]
