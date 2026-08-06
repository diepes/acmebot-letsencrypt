# syntax=docker/dockerfile:1
# Builds Acmebot.App as a custom Azure Functions (.NET isolated worker) container image,
# suitable for running on Kubernetes with KEDA-based scaling.

ARG DOTNET_VERSION=10.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src

# Copy only the project files first to leverage Docker layer caching for restore.
COPY Acmebot.slnx .
COPY src/Acmebot.App/Acmebot.App.csproj src/Acmebot.App/
COPY src/Acmebot.Acme/Acmebot.Acme.csproj src/Acmebot.Acme/
RUN dotnet restore src/Acmebot.App/Acmebot.App.csproj

# Copy the rest of the source and publish.
COPY src/Acmebot.App/ src/Acmebot.App/
COPY src/Acmebot.Acme/ src/Acmebot.Acme/
RUN dotnet publish src/Acmebot.App/Acmebot.App.csproj \
    --configuration Release \
    --output /home/site/wwwroot \
    --no-restore

FROM mcr.microsoft.com/azure-functions/dotnet-isolated:4-dotnet-isolated${DOTNET_VERSION}
WORKDIR /home/site/wwwroot

ENV AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
    FUNCTIONS_WORKER_RUNTIME=dotnet-isolated

COPY --from=build /home/site/wwwroot /home/site/wwwroot
