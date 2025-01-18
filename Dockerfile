# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy csproj and restore dependencies
COPY *.csproj ./
RUN dotnet restore

# Copy everything else and build
COPY . ./
RUN dotnet publish -c Release -o /app

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./

# Copy the SuperAdmin certificate
COPY docker-containers/SuperAdmin.p12 /app/certs/SuperAdmin.p12

# Set environment variables
ENV ASPNETCORE_URLS=http://+:5000;https://+:5001
ENV ASPNETCORE_ENVIRONMENT=Production

# Create volume for certificates
VOLUME /app/certs

# Expose both ports
EXPOSE 5000
EXPOSE 5001

ENTRYPOINT ["dotnet", "LeopardApp.dll"] 