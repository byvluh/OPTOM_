from flask import Flask, request, jsonify, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta
from flask_cors import CORS
import os
from flask import send_from_directory, send_file 

# Inicialización de la aplicación
app = Flask(__name__)

# CLASE CONFIG
class Config:
    # Clave secreta
    SECRET_KEY = 'clave_super_secreta_para_desarrollo_2025_optometria_ual'
    
    # Configuración de base de datos
    SQLALCHEMY_DATABASE_URI = 'sqlite:///optometria.db'  
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configuración de sesión
    SESSION_COOKIE_NAME = 'optometria_session'
    SESSION_COOKIE_SECURE = False  # False para desarrollo
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # Datos maestros
    HORARIOS_ATENCION = ['12:30:00', '13:30:00', '14:30:00', '15:30:00']

app.config.from_object(Config)

# Configuración CORS
CORS(app, 
     origins=["http://localhost:5000", "http://127.0.0.1:5000"],
     supports_credentials=True,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"])

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin in ["http://localhost:5000", "http://127.0.0.1:5000"]:
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Extensiones
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ----------------------------------------------------
# MODELOS DE LA BASE DE DATOS
# ----------------------------------------------------

# Tablas Auxiliares
rol_permiso = db.Table('rol_permiso',
    db.Column('id_rol', db.Integer, db.ForeignKey('rol.id_rol'), primary_key=True),
    db.Column('id_permiso', db.Integer, db.ForeignKey('permiso.id_permiso'), primary_key=True)
)

usuario_permiso = db.Table('usuario_permiso',
    db.Column('id_usuario', db.Integer, db.ForeignKey('usuario.id_usuario'), primary_key=True),
    db.Column('id_permiso', db.Integer, db.ForeignKey('permiso.id_permiso'), primary_key=True)
)

class Paciente(db.Model):
    id_paciente = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    apellido = db.Column(db.String(50), nullable=False)
    edad = db.Column(db.Integer, nullable=False)
    telefono = db.Column(db.String(15), unique=True, nullable=False)
    citas = db.relationship('Cita', backref='paciente', lazy='dynamic')

    def to_dict(self):
        return {
            'id_paciente': self.id_paciente,
            'nombre': self.nombre,
            'apellido': self.apellido,
            'edad': self.edad,
            'telefono': self.telefono
        }

class MotivoCita(db.Model):
    id_motivo = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String(50), nullable=False)
    citas = db.relationship('Cita', backref='motivo', lazy='dynamic')

class Gabinete(db.Model):
    id_gabinete = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(20), nullable=False)
    citas = db.relationship('Cita', backref='gabinete', lazy='dynamic')

class Usuario(UserMixin, db.Model):
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(50), unique=True, nullable=False)
    contrasena = db.Column(db.String(255), nullable=False)
    id_rol = db.Column(db.Integer, db.ForeignKey('rol.id_rol'), nullable=False)
    rol = db.relationship('Rol', backref='usuarios')
    citas = db.relationship('Cita', backref='optometrista', lazy='dynamic')
    permisos_especificos = db.relationship('Permiso', secondary=usuario_permiso, lazy='dynamic', backref=db.backref('usuarios', lazy='dynamic'))
    
    def get_id(self):
        return str(self.id_usuario)

class Rol(db.Model):
    id_rol = db.Column(db.Integer, primary_key=True)
    nombre_rol = db.Column(db.String(30), unique=True, nullable=False)
    permisos = db.relationship('Permiso', secondary=rol_permiso, lazy='dynamic', backref=db.backref('roles', lazy='dynamic'))

class Permiso(db.Model):
    id_permiso = db.Column(db.Integer, primary_key=True)
    nombre_permiso = db.Column(db.String(20), unique=True, nullable=False)

class Cita(db.Model):
    id_cita = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, nullable=False)
    hora = db.Column(db.Time, nullable=False)
    id_paciente = db.Column(db.Integer, db.ForeignKey('paciente.id_paciente'), nullable=False)
    id_motivo = db.Column(db.Integer, db.ForeignKey('motivo_cita.id_motivo'), nullable=False)
    id_gabinete = db.Column(db.Integer, db.ForeignKey('gabinete.id_gabinete'), nullable=False)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'), nullable=True)
    estado = db.Column(db.String(20), default='Programada')
    
    def to_dict(self):
        return {
            'id_cita': self.id_cita,
            'fecha': self.fecha.strftime('%Y-%m-%d'),
            'hora': str(self.hora),
            'id_paciente': self.id_paciente,
            'id_motivo': self.id_motivo,
            'id_gabinete': self.id_gabinete,
            'estado': self.estado,
            'paciente': self.paciente.to_dict() if self.paciente else None,
            'motivo': self.motivo.descripcion if self.motivo else 'N/A',
            'gabinete': self.gabinete.nombre if self.gabinete else 'N/A'
        }

class CitaRecurrente(db.Model):
    __tablename__ = 'cita_recurrente'
    id_serie = db.Column(db.Integer, primary_key=True)
    id_cita_original = db.Column(db.Integer, db.ForeignKey('cita.id_cita'))
    fecha_inicio = db.Column(db.Date)
    fecha_fin = db.Column(db.Date)
    dia_semana = db.Column(db.Integer)
    hora = db.Column(db.Time)
    creado_por = db.Column(db.Integer, db.ForeignKey('usuario.id_usuario'))
    estado_serie = db.Column(db.String(20))
    citas_generadas = db.relationship('Cita', backref='serie_recurrente', lazy=True)

class CitaRecurrenteDetalle(db.Model):
    id_detalle = db.Column(db.Integer, primary_key=True)
    id_serie = db.Column(db.Integer, db.ForeignKey('cita_recurrente.id_serie'), nullable=False)
    id_cita = db.Column(db.Integer, db.ForeignKey('cita.id_cita'), nullable=False)
    fecha_programada = db.Column(db.Date, nullable=False)
    estado_individual = db.Column(db.String(20), default='Programada')  

    def to_dict(self):
        return {
            'id_cita': self.id_cita,
            'fecha': self.fecha_programada.strftime('%Y-%m-%d'),
            'estado': self.estado_individual
        }

# ----------------------------------------------------
# FUNCIONES AUXILIARES
# ----------------------------------------------------

def get_next_available_gabinete(fecha, hora, id_motivo):
    """
    Asigna gabinete basándose estrictamente en el motivo:
    - id_motivo 1 (Armazón) o 2 (Contacto) -> Busca en Gabinetes [1, 2, 3, 4, 5]
    - id_motivo 3 (Terapia Visual)         -> Busca en Gabinete [6]
    """
    try:
        motivo = int(id_motivo)
        candidates = []
        
        if motivo == 3:
            candidates = [6]
            print(f"🔍 Buscando espacio exclusivo para Terapia en Gabinete 6...")
        else:
            candidates = [1, 2, 3, 4, 5]
            print(f"🔍 Buscando espacio estándar en Gabinetes 1-5...")

        citas_en_ese_horario = Cita.query.filter_by(fecha=fecha, hora=hora).all()
        gabinetes_ocupados = {c.id_gabinete for c in citas_en_ese_horario if c.estado != 'Cancelada'}
        
        for g_id in candidates:
            if g_id not in gabinetes_ocupados:
                print(f"✅ Gabinete {g_id} asignado para {fecha} {hora}")
                return g_id
                
        print(f"❌ No hay gabinetes disponibles del tipo requerido para {fecha} {hora}")
        return None 
        
    except Exception as e:
        print(f"❌ Error calculando gabinete disponible: {e}")
        return None

def verificar_disponibilidad_fecha(fecha, hora, es_terapia=False):
    citas = Cita.query.filter_by(fecha=fecha, hora=hora).all()
    ocupados = {c.id_gabinete for c in citas if c.estado != 'Cancelada'}
    
    if es_terapia:
        return 6 not in ocupados
    else:
        gabinetes_normales = {1, 2, 3, 4, 5}
        return len(gabinetes_normales - ocupados) > 0

def calcular_fecha_fin(fecha_inicio, meses=3):
    return fecha_inicio + relativedelta(months=meses)

def generar_citas_recurrentes(id_serie, id_paciente, fecha_inicio, fecha_fin, dia_semana, hora, id_usuario):
    citas_generadas = []
    fecha_actual = fecha_inicio + timedelta(days=7)
    semana_numero = 1
    
    while fecha_actual <= fecha_fin and semana_numero <= 12:
        if verificar_disponibilidad_fecha(fecha_actual, hora, es_terapia=True):
            id_gabinete = get_next_available_gabinete(fecha_actual, hora, 3)
            
            if id_gabinete:
                cita = Cita(
                    fecha=fecha_actual, hora=hora, id_paciente=id_paciente,
                    id_motivo=3, id_gabinete=id_gabinete, estado='Programada',
                    id_usuario=id_usuario
                )
                db.session.add(cita)
                db.session.flush()
                
                detalle = CitaRecurrenteDetalle(
                    id_serie=id_serie, id_cita=cita.id_cita,
                    fecha_programada=fecha_actual, estado_individual='Programada'
                )
                db.session.add(detalle)
                citas_generadas.append(cita)
        
        fecha_actual += timedelta(days=7)
        semana_numero += 1
    
    return citas_generadas

# ----------------------------------------------------
# RUTAS DE AUTENTICACIÓN
# ----------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'message': 'No autorizado'}), 401

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS': return '', 200
    data = request.get_json()
    
    print(f"🔐 Intentando login con usuario: {data.get('username')}")
    
    user = Usuario.query.filter_by(nombre_usuario=data.get('username')).first()
    
    if not user:
        print("❌ Usuario no encontrado en BD")
        return jsonify({'message': 'Usuario no encontrado'}), 401
        
    if user and check_password_hash(user.contrasena, data.get('password')):
        login_user(user, remember=True)
        print("✅ Login exitoso")
        return jsonify({
            'message': 'Login exitoso', 
            'user': user.nombre_usuario, 
            'rol': user.rol.nombre_rol,
            'id_usuario': user.id_usuario
        }), 200
    
    print("❌ Contraseña incorrecta")
    return jsonify({'message': 'Credenciales inválidas'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return jsonify({'message': 'Logout exitoso'}), 200

@app.route('/api/user/current', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        'id_usuario': current_user.id_usuario,
        'nombre_usuario': current_user.nombre_usuario,
        'rol': current_user.rol.nombre_rol
    }), 200

@app.route('/api/debug/session', methods=['GET'])
def debug_session():
    return jsonify({'current_user_authenticated': current_user.is_authenticated}), 200

# ----------------------------------------------------
# RUTAS DE CITAS PÚBLICAS
# ----------------------------------------------------

@app.route('/api/citas/agendar', methods=['POST'])
def agendar_cita():
    data = request.get_json()
    
    if data.get('es_nuevo'):
        paciente = Paciente(
            nombre=data['nombre'], apellido=data['apellido'],
            edad=data['edad'], telefono=data['telefono']
        )
        db.session.add(paciente)
        db.session.flush()
    else:
        paciente = Paciente.query.filter_by(telefono=data['telefono']).first()
        if not paciente:
            return jsonify({'message': 'Paciente no encontrado'}), 404

    id_motivo = data.get('id_motivo', 1)
    fecha_dt = datetime.strptime(data['fecha'], '%Y-%m-%d').date()
    hora_dt = datetime.strptime(data['hora'], '%H:%M:%S').time()
    
    id_gabinete = get_next_available_gabinete(fecha_dt, hora_dt, id_motivo)

    if id_gabinete is None:
         return jsonify({'message': 'No hay citas disponibles para este horario.'}), 409
    
    try:
        nueva_cita = Cita(
            fecha=fecha_dt, hora=hora_dt,
            id_paciente=paciente.id_paciente,
            id_motivo=id_motivo,
            id_gabinete=id_gabinete,
            estado='Programada'
        )
        db.session.add(nueva_cita)
        db.session.commit()
        return jsonify({'message': 'Cita agendada con éxito', 'cita': nueva_cita.to_dict()}), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al agendar', 'error': str(e)}), 500

@app.route('/api/citas/disponibilidad', methods=['POST'])
def get_disponibilidad():
    data = request.get_json()
    fecha_dt = datetime.strptime(data.get('fecha'), '%Y-%m-%d').date()
    
    if fecha_dt.weekday() >= 5: 
        return jsonify({'disponibilidad': {}, 'message': 'Fin de semana cerrado'}), 200
    
    disponibilidad = {}
    for hora_str in Config.HORARIOS_ATENCION:
        hora_obj = datetime.strptime(hora_str, '%H:%M:%S').time()
        if verificar_disponibilidad_fecha(fecha_dt, hora_obj, es_terapia=False):
            disponibilidad[hora_str] = 'Disponible'
        else:
            disponibilidad[hora_str] = 'Ocupado'

    return jsonify({'disponibilidad': disponibilidad}), 200

@app.route('/api/paciente/buscar', methods=['POST'])
def buscar_paciente():
    data = request.get_json()
    paciente = Paciente.query.filter_by(telefono=data.get('telefono')).first()
    if paciente:
        return jsonify({'es_nuevo': False, 'paciente': paciente.to_dict()}), 200
    return jsonify({'es_nuevo': True, 'message': 'No encontrado'}), 200

# ----------------------------------------------------
# RUTAS DE ADMIN (TERAPIA VISUAL)
# ----------------------------------------------------

@app.route('/api/citas/agendar_terapia', methods=['POST'])
@login_required
def agendar_terapia_visual_api():
    try:
        data = request.get_json()
        
        # Corrección de fecha robusta
        if 'T' in data['fecha_inicio']:
            fecha_str = data['fecha_inicio'].split('T')[0]
        else:
            fecha_str = data['fecha_inicio']
            
        fecha_inicio = datetime.strptime(fecha_str, '%Y-%m-%d').date()
        hora_dt = datetime.strptime(data['hora'], '%H:%M:%S').time()
        
        # VERIFICACIÓN EXPLÍCITA
        ocupada = Cita.query.filter_by(
            fecha=fecha_inicio, 
            hora=hora_dt, 
            id_gabinete=6
        ).filter(Cita.estado != 'Cancelada').first()
        
        if ocupada:
            return jsonify({
                'message': f'Gabinete 6 ocupado por {ocupada.paciente.nombre} ({ocupada.estado})'
            }), 409

        nombre_completo = data['nombre_paciente'].split(' ', 1)
        nombre, apellido = nombre_completo[0], nombre_completo[1] if len(nombre_completo)>1 else ""
        telefono = data.get('telefono', '000-0000') or '000-0000'
        
        paciente = Paciente.query.filter_by(telefono=telefono).first()
        if not paciente:
             paciente = Paciente(nombre=nombre, apellido=apellido, edad=data.get('edad',0), telefono=telefono)
             db.session.add(paciente)
             db.session.flush()

        # Crear cita directa en Gab 6
        cita = Cita(
            fecha=fecha_inicio, hora=hora_dt,
            id_paciente=paciente.id_paciente, id_motivo=3,
            id_gabinete=6, estado='Programada',
            id_usuario=current_user.id_usuario
        )
        db.session.add(cita)
        db.session.flush()
        
        es_recurrente = data.get('es_recurrente', True)
        citas_generadas = []
        fecha_fin = None
        
        if es_recurrente:
            fecha_fin = calcular_fecha_fin(fecha_inicio)
            serie = CitaRecurrente(
                id_cita_original=cita.id_cita, fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin, dia_semana=fecha_inicio.weekday(),
                hora=hora_dt, creado_por=current_user.id_usuario, estado_serie='Activa'
            )
            db.session.add(serie)
            db.session.flush()
            
            db.session.add(CitaRecurrenteDetalle(
                id_serie=serie.id_serie, id_cita=cita.id_cita,
                fecha_programada=fecha_inicio, estado_individual='Programada'
            ))
            
            citas_generadas = generar_citas_recurrentes(
                serie.id_serie, paciente.id_paciente, fecha_inicio,
                fecha_fin, fecha_inicio.weekday(), hora_dt, current_user.id_usuario
            )
            
        db.session.commit()
        
        return jsonify({
            'message': 'Terapia agendada',
            'total_citas': 1 + len(citas_generadas),
            'fecha_fin': fecha_fin.strftime('%Y-%m-%d') if fecha_fin else None
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"ERROR TERAPIA: {e}")
        return jsonify({'message': 'Error', 'error': str(e)}), 500

@app.route('/api/terapia/disponibilidad', methods=['POST'])
@login_required
def get_disponibilidad_terapia():
    data = request.get_json()
    fecha_dt = datetime.strptime(data.get('fecha'), '%Y-%m-%d').date()
    hora_dt = datetime.strptime(data.get('hora'), '%H:%M:%S').time()
    
    if fecha_dt.weekday() >= 5: 
         return jsonify({'disponible': False, 'message': 'Fin de semana'}), 200

    if verificar_disponibilidad_fecha(fecha_dt, hora_dt, es_terapia=True):
         return jsonify({'disponible': True, 'message': 'Disponible'}), 200
    else:
         return jsonify({'disponible': False, 'message': 'Gabinete 6 Ocupado'}), 200

@app.route('/api/terapia/horarios_disponibles', methods=['POST'])
@login_required
def get_horarios_disponibles_terapia():
    data = request.get_json()
    fecha_dt = datetime.strptime(data.get('fecha'), '%Y-%m-%d').date()
    
    disponibles = []
    for hora_str in Config.HORARIOS_ATENCION:
        hora_obj = datetime.strptime(hora_str, '%H:%M:%S').time()
        if verificar_disponibilidad_fecha(fecha_dt, hora_obj, es_terapia=True):
            disponibles.append(hora_str)
            
    return jsonify({'horarios_disponibles': disponibles}), 200

# ----------------------------------------------------
# OTRAS RUTAS DE ADMIN Y REPORTES
# ----------------------------------------------------

@app.route('/api/citas/todas', methods=['GET'])
@login_required
def get_todas_citas():
    citas = Cita.query.order_by(Cita.fecha, Cita.hora).all()
    return jsonify([cita.to_dict() for cita in citas]), 200

@app.route('/api/citas/<int:cita_id>/editar', methods=['PUT', 'OPTIONS'])
@login_required
def editar_cita_completa(cita_id):
    if request.method == 'OPTIONS': return '', 200
    data = request.get_json()
    cita = Cita.query.get_or_404(cita_id)
    
    if data.get('estado'): cita.estado = data['estado']
    if data.get('fecha'): cita.fecha = datetime.strptime(data['fecha'], '%Y-%m-%d').date()
    if data.get('hora'): cita.hora = datetime.strptime(data['hora'], '%H:%M:%S').time()
    
    db.session.commit()
    return jsonify({'message': 'Actualizado', 'cita': cita.to_dict()}), 200

@app.route('/api/reportes/semanal', methods=['GET'])
@login_required
def get_reporte_semanal():
    hoy = date.today()
    inicio = hoy - timedelta(days=6)
    citas = Cita.query.filter(Cita.fecha.between(inicio, hoy)).all()
    
    data = []
    for c in citas:
        cd = c.to_dict()
        cd['nombre_completo'] = f"{c.paciente.nombre} {c.paciente.apellido}" if c.paciente else "N/A"
        cd['telefono'] = c.paciente.telefono if c.paciente else "N/A"
        data.append(cd)
        
    return jsonify({
        'citas': data, 'fecha_inicio': inicio.strftime('%Y-%m-%d'), 
        'fecha_fin': hoy.strftime('%Y-%m-%d')
    }), 200

# ----------------------------------------------------
# RUTA DEBUG PARA REVISAR GABINETE 6
# ----------------------------------------------------
@app.route('/api/debug/check_gabinete6', methods=['GET'])
def check_gabinete6():
    citas_g6 = Cita.query.filter_by(id_gabinete=6).filter(Cita.estado != 'Cancelada').all()
    resultado = []
    for c in citas_g6:
        resultado.append({
            'fecha': str(c.fecha),
            'hora': str(c.hora),
            'paciente': c.paciente.nombre + ' ' + c.paciente.apellido,
            'estado': c.estado
        })
    return jsonify({'total_ocupados_g6': len(resultado), 'detalle': resultado})

# Rutas estáticas
@app.route('/')
def serve_login(): return send_file('login.html')
@app.route('/<path:filename>')
def serve_static(filename): return send_from_directory('.', filename)

# ----------------------------------------------------
# INICIALIZACIÓN DE DATOS (USUARIOS Y ROLES)
# ----------------------------------------------------
def crear_datos_iniciales():
    """Crea roles y usuarios por defecto si no existen"""
    with app.app_context():
        # 1. Crear Roles
        roles = ['Administrador', 'Coordinador', 'Estudiante']
        roles_objs = {}
        
        for r_nombre in roles:
            rol = Rol.query.filter_by(nombre_rol=r_nombre).first()
            if not rol:
                rol = Rol(nombre_rol=r_nombre)
                db.session.add(rol)
            roles_objs[r_nombre] = rol
        
        db.session.commit() # Guardar roles para tener IDs
        
        # 2. Crear Usuarios (contraseñas hasheadas)
        # Refrescar objetos de roles para asegurar que están atados a la sesión
        r_admin = Rol.query.filter_by(nombre_rol='Administrador').first()
        r_coord = Rol.query.filter_by(nombre_rol='Coordinador').first()
        r_est = Rol.query.filter_by(nombre_rol='Estudiante').first()

        usuarios_init = [
            {'user': 'admin', 'pass': 'adminUAL', 'rol': r_admin},
            {'user': 'coordinador', 'pass': 'cooUAL', 'rol': r_coord},
            {'user': 'optometrista', 'pass': 'optoUAL', 'rol': r_est}
        ]

        for u_data in usuarios_init:
            user = Usuario.query.filter_by(nombre_usuario=u_data['user']).first()
            if not user:
                print(f"➕ Creando usuario: {u_data['user']}")
                nuevo_user = Usuario(
                    nombre_usuario=u_data['user'],
                    contrasena=generate_password_hash(u_data['pass']),
                    id_rol=u_data['rol'].id_rol
                )
                db.session.add(nuevo_user)
        
        db.session.commit()
        print("✅ Base de datos inicializada con usuarios y roles.")

def inicializar_db():
    with app.app_context():
        db.create_all()
        # CREACIÓN DE GABINETES
        if not Gabinete.query.first():
            print("➕ Creando gabinetes...")
            gabs = [
                Gabinete(id_gabinete=1, nombre='Gabinete 1'),
                Gabinete(id_gabinete=2, nombre='Gabinete 2'),
                Gabinete(id_gabinete=3, nombre='Gabinete 3'),
                Gabinete(id_gabinete=4, nombre='Gabinete 4'),
                Gabinete(id_gabinete=5, nombre='Gabinete 5'),
                Gabinete(id_gabinete=6, nombre='Gabinete 6 (Terapia)')
            ]
            db.session.add_all(gabs)
            
        # CREACIÓN DE MOTIVOS
        if not MotivoCita.query.first():
            print("➕ Creando motivos...")
            mots = [
                MotivoCita(id_motivo=1, descripcion='Lentes de Armazón'),
                MotivoCita(id_motivo=2, descripcion='Lentes de Contacto'),
                MotivoCita(id_motivo=3, descripcion='Terapia Visual')
            ]
            db.session.add_all(mots)

        db.session.commit()

if __name__ == '__main__':
    inicializar_db()
    crear_datos_iniciales() # <--- AQUÍ SE LLAMA A LA FUNCIÓN QUE CREA LOS USUARIOS
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)