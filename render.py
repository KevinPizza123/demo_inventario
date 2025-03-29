import psycopg2

DATABASE_URL= "postgresql://inventario_demo_user:0JHo3ykKm1zhLWRoWJaDsmZCI8no8X3f@dpg-cvk3cmmuk2gs73cuebf0-a.oregon-postgres.render.com/inventario_demo"

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
    