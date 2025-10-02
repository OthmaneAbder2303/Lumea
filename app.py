from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from flask_mail import Mail, Message
import qrcode
import uuid
import os
import sqlite3
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import ssl
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

#SSL POUR HTTPS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')



# --- Configuration Mail  ---
# Mail config
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)
'''
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587 
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''

mail = Mail(app)
'''
# --- Dossier QR ---
QR_FOLDER = "static/qrcodes"
os.makedirs(QR_FOLDER, exist_ok=True)

# --- Dossier Uploads ---
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Base de données ---
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS persons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE,
        nom TEXT,
        infos TEXT,
        contact TEXT,
        canal_alerte TEXT,
        photo TEXT,
        pdf TEXT,
        lien TEXT,
        texte_libre TEXT
    );
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT,
        date TEXT,
        heure TEXT,
        latitude TEXT,
        longitude TEXT,
        user_agent TEXT,
        ip TEXT
    );
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT,
        nom TEXT,
        date TEXT,
        heure TEXT,
        canal TEXT,
        contact TEXT,
        latitude TEXT,
        longitude TEXT,
        message TEXT
    );
    ''')
    db.commit()

    # Ajout d'un admin par défaut si aucun admin n'existe
    existing = db.execute("SELECT * FROM admins").fetchone()
    if not existing:
        hashed_password = generate_password_hash("admin")
        db.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", ("admin", hashed_password))
        db.commit()

init_db()




#Cette fonction per,et de recuperer l'ip local
import socket
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connexion fictive vers internet pour forcer le choix d'interface locale
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip



# --- Authentification ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session['logged_in'] = True
            return redirect(url_for('admin_dashboard'))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# --- Routes ---
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/admin")
@login_required
def admin_dashboard():
    #return render_template("admin_dashboard.html")
    return render_template("admin_dashboard_frame.html")


@app.route("/admin/ajouter", methods=["GET", "POST"])
@login_required
def ajouter():
    if request.method == "POST":
        nom = request.form['nom']
        infos = request.form.get('infos', '')
        contact = request.form['contact']
        canal_alerte = request.form.get('canal_alerte', 'email')
        texte_libre = request.form.get('texte_libre', '')
        lien = request.form.get('lien', '')

        # Upload photo
        photo_file = request.files.get('photo')
        photo_path = None
        if photo_file and photo_file.filename:
            photo_filename = f"{uuid.uuid4()}_{photo_file.filename}"
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo_file.save(photo_path)

        # Upload PDF
        pdf_file = request.files.get('pdf')
        pdf_path = None
        if pdf_file and pdf_file.filename:
            pdf_filename = f"{uuid.uuid4()}_{pdf_file.filename}"
            pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
            pdf_file.save(pdf_path)

        uid = str(uuid.uuid4())

        db = get_db()
        db.execute("""
            INSERT INTO persons (uuid, nom, infos, contact, canal_alerte, photo, pdf, lien, texte_libre)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uid, nom, infos, contact, canal_alerte, photo_path, pdf_path, lien, texte_libre))
        db.commit()
        
        BASE_URL = os.getenv("BASE_URL", "http://localhost:5050")
        full_url = f"{BASE_URL}/scan/{uid}"
        qr = qrcode.make(full_url)
        qr_path = os.path.join(QR_FOLDER, f"{uid}.png")
        qr.save(qr_path)

        return render_template("qr_created.html", uid=uid, qr_path=qr_path)

    return render_template("person_form.html")

@app.route("/admin/personnes")
@login_required
def liste_personnes():
    db = get_db()
    personnes = db.execute("SELECT * FROM persons").fetchall()
    return render_template("admin_persons.html", personnes=personnes)

@app.route("/admin/modifier/<uuid>", methods=["GET", "POST"])
@login_required
def modifier_personne(uuid):
    db = get_db()
    personne = db.execute("SELECT * FROM persons WHERE uuid = ?", (uuid,)).fetchone()

    if request.method == "POST":
        nom = request.form['nom']
        infos = request.form.get('infos', '')
        contact = request.form['contact']
        canal_alerte = request.form.get('canal_alerte', 'email')
        texte_libre = request.form.get('texte_libre', '')
        lien = request.form.get('lien', '')

        db.execute("""
            UPDATE persons SET nom=?, infos=?, contact=?, canal_alerte=?, texte_libre=?, lien=? 
            WHERE uuid=?
        """, (nom, infos, contact, canal_alerte, texte_libre, lien, uuid))
        db.commit()
        return redirect(url_for("liste_personnes"))

    return render_template("edit_person.html", p=personne)


@app.route("/scan/<uuid>")
def scan(uuid):
    return render_template("scan_redirect.html", uuid=uuid)

@app.route("/log_scan/<uuid>", methods=["POST"])
def log_scan(uuid):
    data = request.json
    lat = data.get("latitude")
    lon = data.get("longitude")
    ua = data.get("user_agent")
    ip = request.remote_addr
    now = datetime.now()
    date = now.strftime("%Y-%m-%d")
    heure = now.strftime("%H:%M:%S")

    db = get_db()
    db.execute("INSERT INTO scans (uuid, date, heure, latitude, longitude, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
               (uuid, date, heure, lat, lon, ua, ip))
    db.commit()

    personne = db.execute("SELECT * FROM persons WHERE uuid = ?", (uuid,)).fetchone()
    if personne:
        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        message_content = (
            f"{personne['nom']} a été scanné à {date} {heure}.\n"
            f"Localisation : {lat}, {lon}\n"
            f"📍 Lien Google Maps : {maps_url}"
        )

        # Enregistrer alerte dans la base
        db.execute("""
            INSERT INTO alerts (uuid, nom, date, heure, canal, contact, latitude, longitude, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, personne['nom'], date, heure, personne['canal_alerte'], personne['contact'], lat, lon, message_content))
        db.commit()

        if personne['canal_alerte'] == 'email':
            msg = Message("[Alerte QR Bracelet] Scan détecté",
                          sender="SENDER_EMAIL",
                          recipients=[personne["contact"]])
            msg.body = message_content
            mail.send(msg)
            print(f"EMAIL à envoyer à {personne['contact']} :\n{message_content}")

        elif personne['canal_alerte'] == 'sms':
            print(f"SMS à envoyer à {personne['contact']} :\n{message_content}")
        elif personne['canal_alerte'] == 'whatsapp':
            print(f"WhatsApp à envoyer à {personne['contact']} :\n{message_content}")

    return jsonify({"status": "ok"})

@app.route("/admin/alertes")
@login_required
def alertes():
    db = get_db()
    alertes = db.execute("SELECT * FROM alerts ORDER BY date DESC, heure DESC").fetchall()
    return render_template("admin_alerts.html", alertes=alertes)

@app.route("/fiche", methods=["GET"])
@app.route("/fiche/<uuid>", methods=["GET"])
def fiche(uuid=None):
    if not uuid:
        uuid = request.args.get('uuid')
    if not uuid:
        return render_template("error.html", message="UUID manquant. Veuillez entrer un identifiant valide."), 400
    
    db = get_db()
    personne = db.execute("SELECT * FROM persons WHERE uuid = ?", (uuid,)).fetchone()
    if not personne:
        return render_template("error.html", message="Aucun utilisateur trouvé avec cet UUID."), 404
    
    return render_template("user_profile.html", p=personne, uuid=uuid, now=datetime.now())




@app.route("/admin/supprimer/<uuid>", methods=["POST"])
@login_required
def supprimer_personne(uuid):
    db = get_db()

    # Supprimer QR code
    qr_path = os.path.join(QR_FOLDER, f"{uuid}.png")
    if os.path.exists(qr_path):
        os.remove(qr_path)

    # Supprimer données de la personne
    db.execute("DELETE FROM persons WHERE uuid = ?", (uuid,))
    db.commit()

    return redirect(url_for("liste_personnes"))


from flask import send_file

@app.route("/admin/telecharger_qr/<uuid>")
@login_required
def telecharger_qr(uuid):
    qr_path = os.path.join(QR_FOLDER, f"{uuid}.png")
    if os.path.exists(qr_path):
        return send_file(qr_path, as_attachment=True)
    return "QR code introuvable", 404




# Add new route for user registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nom = request.form['nom']
        infos = request.form.get('infos', '')
        contact = request.form['contact']
        canal_alerte = request.form.get('canal_alerte', 'email')
        texte_libre = request.form.get('texte_libre', '')
        lien = request.form.get('lien', '')
        photo_file = request.files.get('photo')
        pdf_file = request.files.get('pdf')

        try:
            # Upload photo
            photo_path = None
            if photo_file and photo_file.filename:
                photo_filename = f"{uuid.uuid4()}_{photo_file.filename}"
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
                photo_file.save(photo_path)

            # Upload PDF
            pdf_path = None
            if pdf_file and pdf_file.filename:
                pdf_filename = f"{uuid.uuid4()}_{pdf_file.filename}"
                pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
                pdf_file.save(pdf_path)

            # Generate unique UUID
            uid = str(uuid.uuid4())

            # Insert into persons table
            db = get_db()
            db.execute("""
                INSERT INTO persons (uuid, nom, infos, contact, canal_alerte, photo, pdf, lien, texte_libre)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (uid, nom, infos, contact, canal_alerte, photo_path, pdf_path, lien, texte_libre))
            db.commit()

            # Fetch inserted person data
            personne = db.execute("SELECT * FROM persons WHERE uuid = ?", (uid,)).fetchone()

            # Generate QR code
            host_ip = get_local_ip()
            port = 5000
            full_url = f"https://{host_ip}:{port}/scan/{uid}"
            qr = qrcode.make(full_url)
            qr_path_relative = f"qrcodes/{uid}.png"
            qr.save(os.path.join(app.static_folder, qr_path_relative))

            return render_template("qr_created_user.html", uid=uid, qr_path=qr_path_relative, p=personne)
        except Exception as e:
            return render_template("error.html", message=f"Erreur lors de l'inscription : {str(e)}"), 500

    return render_template("register.html")


# Add new route for downloading QR code
@app.route("/download_qr/<uuid>")
def download_qr(uuid):
    qr_path = os.path.join(QR_FOLDER, f"{uuid}.png")
    if os.path.exists(qr_path):
        return send_file(qr_path, as_attachment=True)
    return "QR code not found", 404


# New /update/<uuid> route for updating user information
@app.route("/update/<uuid>", methods=["POST"])
def update(uuid):
    db = get_db()
    personne = db.execute("SELECT * FROM persons WHERE uuid = ?", (uuid,)).fetchone()
    if not personne:
        return render_template("error.html", message="Aucun utilisateur trouvé avec cet UUID."), 404

    nom = request.form['nom']
    infos = request.form.get('infos', '')
    contact = request.form['contact']
    canal_alerte = request.form.get('canal_alerte', 'email')
    texte_libre = request.form.get('texte_libre', '')
    lien = request.form.get('lien', '')
    photo_file = request.files.get('photo')
    pdf_file = request.files.get('pdf')

    try:
        # Photo
        photo_path = personne["photo"]
        if photo_file and photo_file.filename:
            photo_filename = f"{uuid.uuid4()}_{photo_file.filename}"
            photo_path = f"uploads/{photo_filename}"  # chemin relatif à static/
            photo_file.save(os.path.join(app.static_folder, photo_path))
            # Suppression ancienne photo
            if personne["photo"]:
                old_photo_path = os.path.join(app.static_folder, personne["photo"])
                if os.path.exists(old_photo_path):
                    os.remove(old_photo_path)

        # PDF
        pdf_path = personne["pdf"]
        if pdf_file and pdf_file.filename:
            pdf_filename = f"{uuid.uuid4()}_{pdf_file.filename}"
            pdf_path = f"uploads/{pdf_filename}"
            pdf_file.save(os.path.join(app.static_folder, pdf_path))
            # Suppression ancien PDF
            if personne["pdf"]:
                old_pdf_path = os.path.join(app.static_folder, personne["pdf"])
                if os.path.exists(old_pdf_path):
                    os.remove(old_pdf_path)

        # Update BDD
        db.execute("""
            UPDATE persons 
            SET nom = ?, infos = ?, contact = ?, canal_alerte = ?, photo = ?, pdf = ?, lien = ?, texte_libre = ?
            WHERE uuid = ?
        """, (nom, infos, contact, canal_alerte, photo_path, pdf_path, lien, texte_libre, uuid))
        db.commit()

        # Recharger la personne à jour
        personne = db.execute("SELECT * FROM persons WHERE uuid = ?", (uuid,)).fetchone()

        # Regenerate QR code
        host_ip = get_local_ip()
        port = 5000
        full_url = f"https://{host_ip}:{port}/scan/{uuid}"
        qr = qrcode.make(full_url)
        qr_path_relative = f"qrcodes/{uuid}.png"
        qr.save(os.path.join(app.static_folder, qr_path_relative))

        return render_template("qr_created_user.html", p=personne, uid=uuid, qr_path=qr_path_relative)
    except Exception as e:
        return render_template("error.html", message=f"Erreur lors de la mise à jour : {str(e)}"), 500




if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, ssl_context=context, port=int(os.environ.get("PORT", 5050)))
