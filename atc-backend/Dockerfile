# Use an official Maven image with Java 17 preinstalled
FROM maven:3.9.6-eclipse-temurin-17

# Set work directory
WORKDIR /app

# Copy the pom.xml and download dependencies early (layer caching)
COPY pom.xml .

RUN mvn dependency:go-offline

# Copy the rest of the application code
COPY src ./src

# Package the application
RUN mvn clean package -DskipTests

# Run the application
CMD ["java", "-jar", "target/atc-backend-0.0.1-SNAPSHOT.jar"]
