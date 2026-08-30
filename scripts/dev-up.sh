#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run local SQL Server. Install Docker Desktop or the Docker Engine, then retry." >&2
  exit 1
fi

docker compose up -d sqlserver
echo "SQL Server is starting on localhost:1433 (sa / LocalDev_Sql#2026)."
echo "Run the API with: dotnet run --project Authorization.API --launch-profile http"
