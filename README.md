# fineract-grpc

This project uses Spring Boot 3.0

## Packaging and running the application

The application can be packaged using Java 17:

```shell script
./mvnw clean package -Dmaven.test.skip=true
```

It produces the `vnext.connector-0.0.1-SNAPSHOT.jar` file in the `target/` directory.

The application is now runnable using `java -jar target/vnext.connector-0.0.1-SNAPSHOT.jar`.

## Provided Code

### REST

Easily start your REST Web Services
