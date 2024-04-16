# Guia de Instalación

```bash
git clone https://github.com/dgox16/axum-react.git
cd axum-react
```

## Configuración del backend

_Previo a todos los pasos debe tener instalado postgresql y creada la base de datps a usar_

Para configurar el backend realizado en AXUM deberemos dirigirnos a la carpeta de backend y crear un archivo de configuracion:

```bash
cd backend
touch .env
```

Debemos modificar el archivo .env donde se alojará datos importantes como el url de tu base de datos y una palabra secreta para más protección

```env
DATABASE_URL=<your database url>
JWT_SECRET=<palabra secreta>
JWT_EXPIRED_IN=60m
JWT_MAXAGE=60
```

Para conseguir que las migraciones funcionen debemos realizar los siguientes comandos para que hagan efecto y creen la tabla correspondiente:

```bash
cargo install sqlx-cli
sqlx migrate run
```

Finalmente compilamos el proyecto y lo corremos con el comando:

```bash
cargo run
```

## Configuración del frontend

Simplemente necesitas estos tres comandos para tener la página:

```bash
cd frontend
npm install
npm run dev
```
