#!/bin/bash
# Wait for SQL Server to be ready
sleep 30

# Run the migration
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P Cyblore123! -d master -i /docker-entrypoint-initdb.d/init.sql 