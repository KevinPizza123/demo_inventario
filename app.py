import io
from tkinter.font import Font
import bcrypt
import openpyxl
import psycopg2
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle  # Importación corregida
from reportlab.pdfgen import canvas
from flask import Flask, jsonify, render_template, request, redirect, send_file, session, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import requests

load_dotenv()

app = Flask(__name__)
#app.secret_key = os.environ.get('SECRET_KEY')

#DATABASE_URL = os.environ.get('DATABASE_URL')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

#render bdd
app.secret_key = os.environ.get('SECRET_KEY')

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def create_tables():
    conn = get_db_connection()
    cur = conn.cursor()

    # Nombres de las tablas que deseas verificar
    tablas = ['Locales', 'Usuarios', 'Productos', 'Inventario', 'Proveedores']

    # Verificar si cada tabla existe
    table_exists = True
    for tabla in tablas:
        cur.execute(f"SELECT to_regclass('{tabla}');")
        result = cur.fetchone()
        if result is None or result[0] is None:
            table_exists = False
            break

    # Si alguna tabla no existe, ejecutar el script schema.sql
    if not table_exists:
        with open('schema.sql', 'r') as f:
            cur.execute(f.read())
        conn.commit()

    cur.close()
    conn.close()

# Crea las tablas al inicio de la aplicación
with app.app_context():
    create_tables()

UPLOAD_FOLDER = 'static/images'  # Carpeta para guardar imágenes
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#pdf y excel
def obtener_datos_tabla(nombre_tabla):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(f'SELECT * FROM {nombre_tabla};')
        datos = cur.fetchall()
        encabezados = [desc[0] for desc in cur.description]
        cur.close()
        conn.close()
        return encabezados, datos

def generar_reporte_excel(encabezados, datos, nombre_archivo):
        libro = openpyxl.Workbook()
        hoja = libro.active

        # Encabezados
        hoja.append(encabezados)

        # Datos
        for fila in datos:
            hoja.append(fila)

        # Eliminar esto:
        # Estilo de encabezados (opcional)
        # fuente = Font(bold=True)
        # for celda in hoja[1]:
        #     celda.font = fuente

        libro.save(nombre_archivo)
        
def generar_reporte_pdf(encabezados, datos, nombre_archivo):
        doc = SimpleDocTemplate(nombre_archivo, pagesize=letter)
        elementos = []

        # Datos
        data = [encabezados]
        data.extend(datos)

        tabla_pdf = Table(data)
        tabla_pdf.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        elementos.append(tabla_pdf)
        doc.build(elementos)

@app.route('/reporte/<nombre_tabla>/<formato>')
def reporte(nombre_tabla, formato):
        encabezados, datos = obtener_datos_tabla(nombre_tabla)

        if formato == 'excel':
            nombre_archivo = f'reporte_{nombre_tabla}.xlsx'
            generar_reporte_excel(encabezados, datos, nombre_archivo)
            return send_file(nombre_archivo, as_attachment=True)
        elif formato == 'pdf':
            nombre_archivo = f'reporte_{nombre_tabla}.pdf'
            generar_reporte_pdf(encabezados, datos, nombre_archivo)
            return send_file(nombre_archivo, as_attachment=True)
        else:
            return 'Formato no válido'

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

    # Clase de Usuario para Flask-Login
class Usuario(UserMixin):
        def __init__(self, id, nombre, apellido, correo, contrasena, rol, local_id):
            self.id = id
            self.nombre = nombre
            self.apellido = apellido
            self.correo = correo
            self.contrasena = contrasena
            self.rol = rol
            self.local_id = local_id

    # Función para cargar usuario
@login_manager.user_loader
def load_user(user_id):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM Usuarios WHERE ID = %s;', (user_id,))
        usuario = cur.fetchone()
        cur.close()
        conn.close()
        if usuario:
            return Usuario(usuario[0], usuario[1], usuario[2], usuario[3], usuario[4], usuario[5], usuario[6])
        return None

    # Formulario de Login
class LoginForm(FlaskForm):
        correo = StringField('Correo', validators=[DataRequired(), Email()])
        contrasena = PasswordField('Contraseña', validators=[DataRequired()])
        submit = SubmitField('Iniciar Sesión')

@app.route('/registrar_vendedor', methods=['GET', 'POST'])
def registrar_vendedor():
        if current_user.rol != 'admin':
            flash('No tienes permiso para acceder a esta página', 'danger')
            return redirect(url_for('dashboard'))
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT local_id, Nombre FROM Locales;')
        locales = cur.fetchall()
        cur.close()
        if request.method == 'POST':
            nombre = request.form['nombre']
            apellido = request.form['apellido']
            correo = request.form['correo']
            contrasena = request.form['contrasena']
            local_id = request.form['local_id']
            error = None

            if not nombre:
                error = 'Nombre es requerido.'
            elif not apellido:
                error = 'Apellido es requerido.'
            elif not correo:
                error = 'Correo es requerido.'
            elif not contrasena:
                error = 'Contraseña es requerida.'
            elif not local_id:
                error = 'Local es requerido.'

            if error is None:
                try:
                    cur = conn.cursor()
                    # Hashear la contraseña usando bcrypt
                    contrasena_bytes = contrasena.encode('utf-8')
                    hash_bytes = bcrypt.hashpw(contrasena_bytes, bcrypt.gensalt())
                    hash_str = hash_bytes.decode('utf-8')

                    cur.execute(
                        "INSERT INTO Usuarios (Nombre, Apellido, Correo, Contrasena, Rol, local_id) VALUES (%s, %s, %s, %s, %s, %s);",
                        (nombre, apellido, correo, hash_str, 'vendedor', local_id),
                    )
                    conn.commit()
                except psycopg2.IntegrityError:
                    error = f"El usuario {correo} ya está registrado."
                else:
                    return redirect(url_for("login"))
                finally:
                    cur.close()
            flash(error)
        return render_template('registrar_vendedor.html', locales=locales)

@app.route('/')
def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    
# Ruta de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
        if current_user.is_authenticated:
            if current_user.rol == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif current_user.rol == 'vendedor':
                return redirect(url_for('vendedor_dashboard'))
            else:
                return redirect(url_for('dashboard')) # Manejo por defecto
        form = LoginForm()
        if form.validate_on_submit():
            correo = form.correo.data
            contrasena = form.contrasena.data
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT * FROM Usuarios WHERE Correo = %s;', (correo,))
            usuario = cur.fetchone()
            cur.close()
            conn.close()
            if usuario:
                contrasena_db = usuario[4].encode('utf-8')
                contrasena_ingresada = contrasena.encode('utf-8')
                if bcrypt.checkpw(contrasena_ingresada, contrasena_db):
                    # Manejo de local_id
                    local_id = usuario[6] if usuario[6] is not None else None
                    user = Usuario(usuario[0], usuario[1], usuario[2], usuario[3], usuario[4], usuario[5], local_id) # 7 argumentos
                    login_user(user)
                    if user.rol == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    elif user.rol == 'vendedor':
                        return redirect(url_for('vendedor_dashboard'))
                    else:
                        return redirect(url_for('dashboard')) # Manejo por defecto
                else:
                    flash('Correo o contraseña incorrectos', 'danger')
            else:
                flash('Correo o contraseña incorrectos', 'danger')
        return render_template('login.html', form=form)

    # Ruta de Logout
@app.route('/logout')
@login_required
def logout():
        logout_user()
        return redirect(url_for('login'))
    
# Rutas para Administrador
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
        if current_user.rol != 'admin':
            return redirect(url_for('dashboard'))
        return render_template('admin_dashboard.html')



@app.route('/admin/reportes')
@login_required
def admin_reportes():
        if current_user.rol != 'admin':
            return redirect(url_for('dashboard'))
        # Lógica para generar reportes
        return render_template('admin_reportes.html')

    # Rutas para Vendedor
@app.route('/vendedor/dashboard')
@login_required
def vendedor_dashboard():
        if current_user.rol != 'vendedor':
            return redirect(url_for('dashboard'))
        return render_template('vendedor_dashboard.html')

@app.route('/vendedor/productos')
@login_required
def vendedor_productos():
        if current_user.rol != 'vendedor':
            return redirect(url_for('dashboard'))
        # Lógica para mostrar productos (todos y del local)
        return render_template('vendedor_productos.html')

@app.route('/vendedor/productos/agregar', methods=['GET', 'POST'])
@login_required
def vendedor_agregar_producto():
        if current_user.rol != 'vendedor':
            return redirect(url_for('dashboard'))
        # Lógica para agregar productos al local
        return render_template('vendedor_agregar_producto.html')

    # Búsqueda en tiempo real (ejemplo con productos)
@app.route('/buscar_productos')
@login_required
def buscar_productos():
        query = request.args.get('query', '')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM Productos WHERE Nombre LIKE ?;", ('%' + query + '%',))
        productos = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(productos)

    # Ruta de Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
        return render_template('dashboard.html')


# ... (rutas y funciones para cada tabla) ...
#nuevo

@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT Usuarios.ID, Usuarios.Nombre, Usuarios.Apellido, Usuarios.Correo, Usuarios.Rol, Locales.Nombre
        FROM Usuarios
        LEFT JOIN Locales ON Usuarios.LocalID = Locales.ID;
    ''')
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/usuarios/agregar', methods=['GET', 'POST'])
@login_required
def agregar_usuario():
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT ID, Nombre FROM Locales;')
    locales = cur.fetchall()
    cur.close()
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        rol = request.form['rol']
        local_id = request.form['local_id']
        contrasena = request.form['contrasena']
        contrasena_bytes = contrasena.encode('utf-8')
        hash_bytes = bcrypt.hashpw(contrasena_bytes, bcrypt.gensalt())
        hash_str = hash_bytes.decode('utf-8')
        try:
            cur = conn.cursor()
            cur.execute('INSERT INTO Usuarios (Nombre, Apellido, Correo, Rol, LocalID, Contrasena) VALUES (%s, %s, %s, %s, %s, %s);', (nombre, apellido, correo, rol, local_id, hash_str))
            conn.commit()
            flash('Usuario agregado exitosamente', 'success')
            return redirect(url_for('admin_usuarios'))
        except psycopg2.Error as e:
            flash(f'Error al agregar usuario: {e}', 'danger')
        finally:
            cur.close()
            conn.close()
    conn.close()
    return render_template('agregar_usuario.html', locales=locales)

@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM Usuarios WHERE ID = %s", (id,))
    usuario = cur.fetchone()
    cur.execute('SELECT ID, Nombre FROM Locales;')
    locales = cur.fetchall()
    cur.close()
    conn.close()
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        rol = request.form['rol']
        local_id = request.form['local_id']
        contrasena = request.form.get('contrasena')
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            if contrasena:
                contrasena_bytes = contrasena.encode('utf-8')
                hash_bytes = bcrypt.hashpw(contrasena_bytes, bcrypt.gensalt())
                hash_str = hash_bytes.decode('utf-8')
                cur.execute('UPDATE Usuarios SET Nombre = %s, Apellido = %s, Correo = %s, Rol = %s, LocalID = %s, Contrasena = %s WHERE ID = %s;', (nombre, apellido, correo, rol, local_id, hash_str, id))
            else:
                cur.execute('UPDATE Usuarios SET Nombre = %s, Apellido = %s, Correo = %s, Rol = %s, LocalID = %s WHERE ID = %s;', (nombre, apellido, correo, rol, local_id, id))
            conn.commit()
            flash('Usuario editado exitosamente', 'success')
            return redirect(url_for('admin_usuarios'))
        except psycopg2.Error as e:
            flash(f'Error al editar usuario: {e}', 'danger')
        finally:
            cur.close()
            conn.close()
    return render_template('editar_usuario.html', usuario=usuario, locales=locales)

@app.route('/admin/usuarios/eliminar/<int:id>')
@login_required
def eliminar_usuario(id):
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM Usuarios WHERE ID = %s", (id,))
        conn.commit()
        flash('Usuario eliminado exitosamente', 'success')
    except psycopg2.Error as e:
        flash(f'Error al eliminar usuario: {e}', 'danger')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('admin_usuarios'))

#localesadmin
@app.route('/admin/locales')
@login_required
def admin_locales():
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM Locales;')
    locales = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_locales.html', locales=locales)

@app.route('/admin/locales/agregar', methods=['GET', 'POST'])
@login_required
def agregar_local():
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        nombre = request.form['nombre']
        direccion = request.form['direccion']
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO Locales (Nombre, Direccion) VALUES (%s, %s);', (nombre, direccion))
            conn.commit()
            flash('Local agregado exitosamente', 'success')
            return redirect(url_for('admin_locales'))
        except psycopg2.Error as e:
            flash(f'Error al agregar local: {e}', 'danger')
        finally:
            cur.close()
            conn.close()
    return render_template('agregar_local.html')

@app.route('/admin/locales/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_local(id):
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM Locales WHERE ID = %s;', (id,))
    local = cur.fetchone()
    cur.close()
    conn.close()
    if request.method == 'POST':
        nombre = request.form['nombre']
        direccion = request.form['direccion']
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('UPDATE Locales SET Nombre = %s, Direccion = %s WHERE ID = %s;', (nombre, direccion, id))
            conn.commit()
            flash('Local editado exitosamente', 'success')
            return redirect(url_for('admin_locales'))
        except psycopg2.Error as e:
            flash(f'Error al editar local: {e}', 'danger')
        finally:
            cur.close()
            conn.close()
    return render_template('editar_local.html', local=local)

@app.route('/admin/locales/eliminar/<int:id>')
@login_required
def eliminar_local(id):
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM Locales WHERE ID = %s;', (id,))
        conn.commit()
        flash('Local eliminado exitosamente', 'success')
    except psycopg2.Error as e:
        flash(f'Error al eliminar local: {e}', 'danger')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('admin_locales'))

#productos
@app.route('/admin/productos')
@login_required
def admin_productos():
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT Productos.ID, Productos.Nombre, Productos.Precio, Productos.Stock, Locales.Nombre, Imagenes.NombreArchivo, Productos.Descripcion
        FROM Productos
        LEFT JOIN Imagenes ON Productos.ID = Imagenes.ProductoID
        LEFT JOIN Locales ON Productos.LocalID = Locales.ID;
    ''')
    productos = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_productos.html', productos=productos)

@app.route('/admin/productos/agregar', methods=['GET', 'POST'])
@login_required
def agregar_producto():
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT ID, Nombre FROM Locales;')
    locales = cur.fetchall()
    if request.method == 'POST':
        nombre = request.form['nombre']
        precio = request.form['precio']
        stock = request.form['stock']
        local_id = request.form['local_id']
        descripcion = request.form['descripcion']
        imagen = request.files['imagen']
        if imagen and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            imagen_path = filename
        else:
            imagen_path = None
        try:
            cur.execute('INSERT INTO Productos (Nombre, Precio, Stock, LocalID, Descripcion) VALUES (%s, %s, %s, %s, %s) RETURNING ID;', (nombre, precio, stock, local_id, descripcion))
            producto_id = cur.fetchone()[0]
            if imagen_path:
                cur.execute('INSERT INTO Imagenes (NombreArchivo, ProductoID) VALUES (%s, %s);', (imagen_path, producto_id))
            conn.commit()
            flash('Producto agregado correctamente.', 'success')
            return redirect(url_for('admin_productos'))
        except psycopg2.Error as e:
            flash(f'Error al agregar producto: {e}', 'danger')
        finally:
            cur.close()
            conn.close()
    return render_template('agregar_producto.html', locales=locales)

@app.route('/admin/productos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_producto(id):
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT ID, Nombre FROM Locales;')
    locales = cur.fetchall()
    if request.method == 'POST':
        nombre = request.form['nombre']
        precio = request.form['precio']
        stock = request.form['stock']
        local_id = request.form['local_id']
        descripcion = request.form['descripcion']
        imagen = request.files['imagen']
        if imagen and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            imagen_path = filename
        else:
            imagen_path = None
        try:
            cur.execute('UPDATE Productos SET Nombre = %s, Precio = %s, Stock = %s, LocalID = %s, Descripcion = %s WHERE ID = %s;', (nombre, precio, stock, local_id, descripcion, id))
            if imagen_path:
                cur.execute('UPDATE Imagenes SET NombreArchivo = %s WHERE ProductoID = %s;', (imagen_path, id))
            conn.commit()
            flash('Producto actualizado correctamente.', 'success')
            return redirect(url_for('admin_productos'))
        except psycopg2.Error as e:
            flash(f'Error al actualizar producto: {e}', 'danger')
        finally:
            cur.close()
            conn.close()
    cur.execute('''
        SELECT Productos.ID, Productos.Nombre, Productos.Precio, Productos.Stock, Productos.LocalID, Imagenes.NombreArchivo, Productos.Descripcion
        FROM Productos
        LEFT JOIN Imagenes ON Productos.ID = Imagenes.ProductoID
        WHERE Productos.ID = %s;
    ''', (id,))
    producto = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('editar_producto.html', producto=producto, locales=locales)

@app.route('/admin/productos/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_producto(id):
    if current_user.rol != 'admin':
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM Imagenes WHERE ProductoID = %s;', (id,))
        cur.execute('DELETE FROM Productos WHERE ID = %s;', (id,))
        conn.commit()
        flash('Producto eliminado correctamente.', 'success')
    except psycopg2.Error as e:
        flash(f'Error al eliminar producto: {e}', 'danger')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('admin_productos'))

#iventario
@app.route('/admin/inventario')
def inventario():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT ID, Nombre, Stock FROM Productos;')
    productos = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('inventario.html', productos=productos)



@app.route('/admin/inventario/actualizar/<int:id>', methods=['GET', 'POST'])
def actualizar_inventario(id):
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        stock = request.form['stock']
        try:
            cur.execute('UPDATE Productos SET Stock = %s WHERE ID = %s;', (stock, id))
            conn.commit()
            flash('Inventario actualizado correctamente.', 'success')
            return redirect(url_for('inventario'))
        except psycopg2.Error as e:
            flash(f'Error al actualizar inventario: {e}', 'danger')
            return redirect(url_for('actualizar_inventario', id=id))
    cur.execute('SELECT ID, Nombre, Stock FROM Productos WHERE ID = %s;', (id,))
    producto = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('actualizar_inventario.html', producto=producto)

#proveedores

@app.route('/admin/proveedores')
def proveedores():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT ID, Nombre, Contacto, Telefono, Correo FROM Proveedores;')
    proveedores = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('proveedores.html', proveedores=proveedores)

@app.route('/admin/proveedores/agregar', methods=['GET', 'POST'])
def agregar_proveedor():
    if request.method == 'POST':
        nombre = request.form['nombre']
        contacto = request.form['contacto']
        telefono = request.form['telefono']
        correo = request.form['correo']
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO Proveedores (Nombre, Contacto, Telefono, Correo) VALUES (%s, %s, %s, %s);', (nombre, contacto, telefono, correo))
            conn.commit()
            flash('Proveedor agregado correctamente.', 'success')
            return redirect(url_for('proveedores'))
        except psycopg2.Error as e:
            flash(f'Error al agregar proveedor: {e}', 'danger')
        finally:
            cur.close()
            conn.close()
    return render_template('agregar_proveedor.html')

@app.route('/admin/proveedores/actualizar/<int:id>', methods=['GET', 'POST'])
def actualizar_proveedor(id):
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        nombre = request.form['nombre']
        contacto = request.form['contacto']
        telefono = request.form['telefono']
        correo = request.form['correo']
        try:
            cur.execute('UPDATE Proveedores SET Nombre = %s, Contacto = %s, Telefono = %s, Correo = %s WHERE ID = %s;', (nombre, contacto, telefono, correo, id))
            conn.commit()
            flash('Proveedor actualizado correctamente.', 'success')
            return redirect(url_for('proveedores'))
        except psycopg2.Error as e:
            flash(f'Error al actualizar proveedor: {e}', 'danger')
            return redirect(url_for('actualizar_proveedor', id=id))
    cur.execute('SELECT ID, Nombre, Contacto, Telefono, Correo FROM Proveedores WHERE ID = %s;', (id,))
    proveedor = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('actualizar_proveedor.html', proveedor=proveedor)

@app.route('/admin/proveedores/eliminar/<int:id>', methods=['POST'])
def eliminar_proveedor(id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM Proveedores WHERE ID = %s;', (id,))
        conn.commit()
        flash('Proveedor eliminado correctamente.', 'success')
    except psycopg2.Error as e:
        flash(f'Error al eliminar proveedor: {e}', 'danger')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('proveedores'))


    
if __name__ == '__main__':
        app.run(debug=True)