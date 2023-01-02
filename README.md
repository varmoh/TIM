# TARA-integration module installation and configuration guide.



# 0. Used variables description

* `${PROJECT_ROOT}` - root folder of the project
* `${version}` - project version (defined in build.gradle)
* `${PATH_TO_APPLICATION_PROPERTIES}` - path to externalized configuration (can be relative)
* `${TOMCAT_BASE}` - path to Tomcat installation


# 1. Building from source

inside project root folder `${PROJECT_ROOT}` execute the following: 

```mvn clean -U package```

This should produce an executable war file at following location:

`${PROJECT_ROOT}/target/tim.war`


# 2. Configuration

Spring Boot applications support externalized configuration through *.properties files

Sample configuration can be found here: `${PROJECT_ROOT}/src/main/application.example.properties`.

**Jenkins** picks up the configuration from `${PROJECT_ROOT}/conf` folder.

Configuration parameters are described in the sample configuration properties file.

## 2.1 Certificates generation

**Note!** Both keystore password and alias password should be the same.

### 2.1.1 Tomcat SSL support
```
keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -keystore "keystore.jks" -validity 3650
```

* When starting application using `java -jar`, the generated keystore should be configured in the `application.properties`
* When starting from tomcat, the configuration is located in `${PROJECT_ROOT}/conf/server.xml`


### 2.1.2 Certificate for JWT signature
```
keytool -genkeypair -alias jwtsign -keyalg RSA -keysize 2048 -keystore "jwtkeystore.jks" -validity 3650
```

relevant configuration properties:

```
jwt-integration.signature.key-store=classpath:jwtkeystore.jks
jwt-integration.signature.key-store-password=ppjjpp
jwt-integration.signature.keyStoreType=JKS
jwt-integration.signature.keyAlias=jwtsign
```

### 2.1.3 Regenerating Certificates

To generate a new key pair with certificate:
1. backup the original keystore file.
2. run certificate generation `keytool` command from previous step(s)
3. update configuration with new keystore file and password 

### 2.1.4 Changing Keystore password

To change keystore password, 
1. run the following command
    ```
    keytool -keystore <keystore file name> -storepasswd
    # (old and new password asked)
    ```
2. update configuration with new password

## 2.2 Tomcat configuration

**Note!** Application can be run without deployment to Tomcat. Next section is needed only for Tomcat deployment

Tomcat should be configured to accept HTTPS connections.[Tomcat SSL configuration guide](https://www.mulesoft.com/tcat/tomcat-ssl) 

In order for application to start, the externalized configuration file location should be defined in the `${TOMCAT_BASE}/conf/context.xml` of the tomcat
 
``` 
<Context>
...
     <Parameter name="tara-integration.properties" value="/path/to/your/properties/application.properties"/>
...
</Context>
 ```
 
 
## 3. Running in Tomcat

Deploy the application as usual

## 3. Running with plain java

Executable WAR file contains an embedded Tomcat installation and can be started with the following command (assuming application version 0.1-SNAPSHOT):  

java -jar TARA-integration-module-0.1-SNAPSHOT.war ---spring.config.location=${PATH_TO_APPLICATION_PROPERTIES}

Integration module 


## Licence

See licence [here](LICENCE.md).
