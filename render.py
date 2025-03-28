import psycopg2

DATABASE_URL= "postgresql://demo_inventario_user:mBVQjVforH9dA0EEYzxm4qlhKpGQhGRu@dpg-cvj59r6mcj7s7389up1g-a.oregon-postgres.render.com/demo_inventario"

try:
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # Ejecuta tus consultas SQL aquí
    cur.execute("SELECT * FROM Productos;")
    rows = cur.fetchall()
    for row in rows:
        print(row)

    cur.close()
    conn.close()
except psycopg2.Error as e:
    print(f"Error connecting to database: {e}")
    #paella
    