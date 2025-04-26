# First stage: Build the application
FROM maven:3.9.6-eclipse-temurin-17 as builder

# Set the working directory
WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy the rest of the application source code
COPY src ./src

# Package the application
RUN mvn clean package -DskipTests

# Second stage: Run the application
FROM eclipse-temurin:17-jdk-jammy

# Set the working directory
WORKDIR /app

# Copy the jar file from the builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose port 8080
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
