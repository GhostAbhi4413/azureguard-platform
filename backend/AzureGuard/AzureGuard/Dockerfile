FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY backend/NuGet.Config ./NuGet.Config
COPY backend/AzureGuard/ .
RUN dotnet restore AzureGuard.sln --configfile NuGet.Config -m:1
RUN dotnet publish AzureGuard/AzureGuard.csproj -c Release -o /out --no-restore -m:1
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /out .
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "AzureGuard.dll"]
