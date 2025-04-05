-- Tabla Locales (actualizada)
    CREATE TABLE Locales (
        ID SERIAL PRIMARY KEY,
        Nombre VARCHAR(255) NOT NULL,
        Direccion VARCHAR(255) NOT NULL,
        ResponsableNombre VARCHAR(255) -- Nueva columna para el nombre del responsable
    );

    -- Tabla Usuarios
    CREATE TABLE Usuarios (
        ID SERIAL PRIMARY KEY,
        Nombre VARCHAR(255) NOT NULL,
        Apellido VARCHAR(255) NOT NULL,
        Correo VARCHAR(255) UNIQUE NOT NULL,
        Contrasena VARCHAR(255) NOT NULL,
        Rol VARCHAR(255) NOT NULL,
        LocalID INTEGER REFERENCES Locales(ID)
    );

    CREATE TABLE Productos (
    ID SERIAL PRIMARY KEY,
    Nombre VARCHAR(255) NOT NULL,
    Precio DECIMAL NOT NULL,
    Stock INTEGER NOT NULL,
    LocalID INTEGER REFERENCES Locales(ID),
    Descripcion TEXT -- Columna Descripción agregada
);

CREATE TABLE Imagenes (
    ID SERIAL PRIMARY KEY,
    NombreArchivo VARCHAR(255) NOT NULL,
    ProductoID INT REFERENCES Productos(ID)
);

    -- Tabla Inventario
    CREATE TABLE Inventario (
        ID SERIAL PRIMARY KEY,
        ProductoID INTEGER REFERENCES Productos(ID) NOT NULL,
        LocalID INTEGER REFERENCES Locales(ID) NOT NULL,
        Cantidad INTEGER NOT NULL
    );



    -- Tabla Proveedores
    CREATE TABLE Proveedores (
        ID SERIAL PRIMARY KEY,
        Nombre VARCHAR(255) NOT NULL,
        Contacto VARCHAR(255) NOT NULL,
        Telefono VARCHAR(255) NOT NULL,
        Correo VARCHAR(255)
    );


---actualizaar


    -- Insertar usuario admin (miguel25@gmail.com)
    INSERT INTO Usuarios (Nombre, Apellido, Correo, Contrasena, Rol, LocalID)
    VALUES ('Miguel', 'Admin', 'miguel25@gmail.com', '$2b$12$1yxExtPEwbeTOI1ec20qV.f4GBiba6DXV4qTcCAwJk41Zq5FtjZe6', 'admin', NULL);