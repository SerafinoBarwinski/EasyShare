# Basis-Image Node.js 22
FROM node:22

# Arbeitsverzeichnis im Container erstellen
WORKDIR /app

# package.json und package-lock.json kopieren
COPY package*.json ./

# Abhängigkeiten installieren
RUN npm install

# Restlichen Code kopieren
COPY . .

# Port, auf dem die App läuft
EXPOSE 8099

# Standardbefehl zum Starten der App
CMD ["node", "server.js"]