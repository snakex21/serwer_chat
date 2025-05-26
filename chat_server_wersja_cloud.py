# chat_server.py
#http://127.0.0.1:5000/admin/
#d8f3b5f6a9c1e2d7b8f3c5a6b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
import os
from flask import Flask, request, jsonify, send_from_directory  # Dodano send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# --- NOWE ZMIANY ---
from werkzeug.utils import secure_filename  # Do bezpiecznych nazw plików
import uuid  # Do generowania unikalnych nazw plików
# --- KONIEC NOWYCH ZMIAN ---
from email_validator import validate_email, EmailNotValidError
import datetime
import logging
# --- NOWE ZMIANY (Panel Admina - Strona Webowa) ---
from flask import render_template_string  # Potrzebne do serwowania HTML jako string
# --- KONIEC NOWYCH ZMIAN --
import urllib.parse
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect as socketio_disconnect_client  # Dodaj ten import
from flask import Flask, request, jsonify, send_from_directory, make_response  # Dodaj make_response
from flask import Flask, request, jsonify, send_from_directory, session  # Dodaj 'session'
from functools import wraps  # Do tworzenia dekoratorów
from flask_migrate import Migrate
# --- NOWE ZMIANY (CHAT SERVER) ---
# Globalny słownik do mapowania SID na user_id dla śledzenia użytkowników online
connected_sids_to_user_id = {}  # Deklaracja globalna
# --- KONIEC NOWYCH ZMIAN (CHAT SERVER) ---

# --- Konfiguracja Logowania Serwera ---
logging.basicConfig(
    level=logging.INFO,
    format=
    '%(asctime)s - %(levelname)s - (%(filename)s:%(lineno)d) - %(message)s')
logger = logging.getLogger(__name__)

# --- Inicjalizacja Aplikacji Flask i SocketIO ---
app = Flask(__name__)

# --- NOWE ZMIANY: Konfiguracja folderu UPLOAD ---
UPLOAD_FOLDER = 'chat_uploads'  # Nazwa folderu na przesłane pliki
# --- NOWE ZMIANY: Poprawiona lista dozwolonych rozszerzeń ---
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'doc',
    'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'mp3', 'wav', 'ogg', 'mp4', 'webm',
    'webp'
}  # <-- DODANO 'webp'
# --- KONIEC NOWYCH ZMIAN ---
MAX_FILE_SIZE_MB = 10  # Maksymalny rozmiar pliku w MB

# Ścieżka do folderu, w którym znajduje się chat_server.py
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_file = os.path.join(BASE_DIR, 'chat.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_file
logger.info(f"Using SQLite database at: {db_file}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'twoj_sekretny_klucz_ktory_musisz_zmienic!'

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), UPLOAD_FOLDER)
app.config[
    'MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE_MB * 1024 * 1024  # Ustawienie limitu w bajtach
# --- KONIEC NOWYCH ZMIAN ---

# Inicjalizacja SQLAlchemy
db = SQLAlchemy(app)

# --- Flask-Migrate (punkt 3) ---
migrate = Migrate(app, db)

# Inicjalizacja SocketIO
# W środowisku produkcyjnym 'cors_allowed_origins' powinno być bardziej restrykcyjne.
# "*" pozwala na połączenia z dowolnego źródła.
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True,
    # --- ZMIANY Z POPRZEDNIEJ ITERACJI (ZACHOWANE) ---
    ping_interval=60,  # Wysyłaj ping co 60 sekund (domyślnie 25)
    ping_timeout=120  # Oczekuj na pong przez 120 sekund (domyślnie 60)
    # --- KONIEC ZMIAN ---
)

# --- Modele Bazy Danych ---

# --- NOWE ZMIANY (Panel Admina - Logowanie i Ochrona) ---
# Konfiguracja dla admina - W PRZYSZŁOŚCI PRZENIEŚ DO BEZPIECZNIEJSZEGO MIEJSCA (np. zmienne środowiskowe, plik konfiguracyjny)
app.config['ADMIN_USERNAME'] = os.environ.get('FLASK_ADMIN_USER',
                                              'admin')  # Domyślny admin user
ADMIN_PASSWORD_PLAIN = os.environ.get(
    'FLASK_ADMIN_PASS', 'supersecretpassword')  # Hasło w postaci jawnej
app.config['ADMIN_PASSWORD_HASH'] = generate_password_hash(
    ADMIN_PASSWORD_PLAIN)
# WAŻNE: Flask potrzebuje SECRET_KEY do używania sesji. Już go masz:
# app.config['SECRET_KEY'] = 'twoj_sekretny_klucz_ktory_musisz_zmienic!'


def admin_required(f):
    """Dekorator do ochrony endpointów administracyjnych."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin_logged_in'):
            logger.warning("Admin endpoint access denied: Not logged in.")
            return jsonify({
                "error":
                "Administrator access required. Please log in."
            }), 401  # Unauthorized
        return f(*args, **kwargs)

    return decorated_function


@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Sprawdź nazwę użytkownika i hasło
    # W bardziej zaawansowanym systemie, admin mógłby być specjalnym użytkownikiem w bazie User.
    # Tutaj używamy zahardkodowanego użytkownika i hasła z konfiguracji.
    stored_admin_username = app.config.get('ADMIN_USERNAME')
    stored_password_hash = app.config.get('ADMIN_PASSWORD_HASH')

    if username == stored_admin_username and check_password_hash(
            stored_password_hash, password):
        session['is_admin_logged_in'] = True
        logger.info(f"Administrator '{username}' logged in successfully.")
        return jsonify({"message": "Admin logged in successfully"}), 200
    else:
        logger.warning(f"Failed admin login attempt for username: {username}")
        return jsonify({"error": "Invalid admin credentials"}), 401


@app.route('/admin/logout', methods=['POST'])
@admin_required  # Tylko zalogowany admin może się wylogować przez ten endpoint
def admin_logout():
    session.pop('is_admin_logged_in', None)
    logger.info("Administrator logged out.")
    return jsonify({"message": "Admin logged out successfully"}), 200


# --- NOWE ZMIANY (Panel Admina - API dla Blacklisty E-maili) ---
@app.route('/admin/blacklist', methods=['GET'])
@admin_required
def admin_get_email_blacklist():
    try:
        blacklisted_emails = EmailBlacklist.query.order_by(
            EmailBlacklist.added_at.desc()).all()
        blacklist_data = [{
            "id": entry.id,
            "email": entry.email,
            "reason": entry.reason,
            "added_at": entry.added_at.isoformat()
        } for entry in blacklisted_emails]
        return jsonify(blacklist_data), 200
    except Exception as e:
        logger.exception("Error fetching email blacklist for admin")
        return jsonify({"error": "Server error fetching email blacklist"}), 500


@app.route('/admin/blacklist/<string:email_to_unblacklist>',
           methods=['DELETE'])
@admin_required
def admin_remove_from_email_blacklist(email_to_unblacklist):
    # Walidacja formatu email (choć powinien być poprawny, jeśli jest w bazie)
    try:
        validated_email = validate_email(email_to_unblacklist).email
    except EmailNotValidError:
        return jsonify({"error": "Invalid email format provided"}), 400

    entry_to_remove = EmailBlacklist.query.filter_by(
        email=validated_email).first()
    if not entry_to_remove:
        return jsonify({
            "error":
            f"Email '{validated_email}' not found on the blacklist."
        }), 404

    try:
        db.session.delete(entry_to_remove)
        db.session.commit()
        logger.info(f"Admin removed email '{validated_email}' from blacklist.")
        return jsonify({
            "message":
            f"Email '{validated_email}' has been removed from the blacklist."
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(
            f"Error removing email '{validated_email}' from blacklist: {e}")
        return jsonify(
            {"error":
             "Server error during email unblacklisting operation"}), 500


# --- KONIEC NOWYCH ZMIAN ---

# --- NOWE ZMIANY (Panel Admina - Strona Webowa) ---
ADMIN_PANEL_HTML = """
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel Administracyjny Czatu</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #e9e9e9; color: #333; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; padding-top: 30px; padding-bottom: 30px; }
        .container { background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 15px rgba(0,0,0,0.15); width: 100%; }
        .container.login-view { max-width: 400px; }
        .container.admin-view { max-width: 900px; }
        h1, h2 { text-align: center; color: #333; margin-top: 0; }
        h3 { margin-top: 25px; border-bottom: 1px solid #eee; padding-bottom: 8px; }
        label { display: block; margin-bottom: 6px; font-weight: 600; color: #555; }
        input[type="text"], input[type="password"], input[type="email"] {
            width: calc(100% - 24px); padding: 10px; margin-bottom: 16px; border: 1px solid #ccc; border-radius: 4px; font-size: 1em;
        }
        button { background-color: #5cb85c; color: white; padding: 12px 18px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-size: 1em; transition: background-color 0.2s ease; }
        button:hover { background-color: #4cae4c; }
        .error-message { color: #d9534f; text-align: center; margin-bottom: 12px; font-size: 0.9em;}
        .success-message { color: #5cb85c; text-align: center; margin-bottom: 12px; font-size: 0.9em;}
        #adminContent { display: none; } 
        #userInfo { margin-bottom: 15px; font-size: 0.9em; color: #666; }
        #loggedInAdminUser { font-weight: bold; color: #333; }
        .table-container { width: 100%; overflow-x: auto; margin-top: 15px; border: 1px solid #ddd; border-radius: 4px; }
        table { width: 100%; min-width: 700px; border-collapse: collapse; }
        th, td { border-bottom: 1px solid #eee; padding: 10px 12px; text-align: left; font-size: 0.95em; }
        th { background-color: #f7f7f7; font-weight: 600; white-space: nowrap; }
        td { color: #555; word-break: break-all; } 
        tr:hover { background-color: #f9f9f9; }
        .action-button { padding: 6px 10px; font-size: 0.85em; margin-right: 5px; cursor: pointer; border-radius: 3px; border: none; color: white; transition: opacity 0.2s ease; }
        .action-button:hover { opacity: 0.8; }
        .ban-btn { background-color: #d9534f; }
        .unban-btn { background-color: #5bc0de; }
        .delete-user-btn { background-color: #f0ad4e; }
        .unblacklist-btn { background-color: #5bc0de; } 
        .add-to-blacklist-btn { background-color: #d9534f; width: auto; padding: 8px 12px; font-size: 0.9em;}
        .logout-btn { background-color: #6c757d; margin-top:20px; }
        .logout-btn:hover { background-color: #5a6268; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
        .online { background-color: #5cb85c; } 
        .offline { background-color: #bbb; } 
        .banned-text { color: #d9534f; font-weight: bold; }
        .blacklist-add-form { margin-top: 15px; margin-bottom: 10px; padding: 10px; border: 1px solid #eee; border-radius: 4px; background-color: #f9f9f9;}
        .blacklist-add-form label { margin-top: 5px; }
        .blacklist-add-form input[type="email"] { margin-bottom: 10px; }
        .blacklist-add-form input[type="text"] { margin-bottom: 10px; }
        .blacklist-add-form button { margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container login-view" id="mainContainer">
        <div id="loginForm">
            <h1>Logowanie Admina</h1>
            <div id="loginError" class="error-message"></div>
            <div id="loginSuccess" class="success-message"></div>
            <div><label for="adminUser">Nazwa użytkownika:</label><input type="text" id="adminUser" value="admin" required></div>
            <div><label for="adminPass">Hasło:</label><input type="password" id="adminPass" required></div>
            <button type="button" id="loginButton">Zaloguj</button>
        </div>

        <div id="adminContent">
            <h2>Panel Zarządzania</h2>
            <div id="userInfo">Zalogowano jako: <span id="loggedInAdminUser"></span></div>
            <button type="button" class="logout-btn" onclick="handleAdminLogout()">Wyloguj</button>
            
            <h3>Lista Użytkowników</h3>
            <div class="table-container">
                <table id="usersTable">
                    <thead><tr><th>ID</th><th>Nazwa</th><th>Email</th><th>Admin?</th><th>Zbanowany?</th><th>Akcje</th></tr></thead>
                    <tbody id="usersTableBody"></tbody>
                </table>
            </div> 
            <div id="usersError" class="error-message"></div>

            <h3>Blacklista E-maili</h3>
            <div class="blacklist-add-form">
                <h4>Dodaj Email do Blacklisty</h4>
                <div>
                    <label for="blacklistEmailInput">Adres Email:</label>
                    <input type="email" id="blacklistEmailInput" placeholder="np. spammer@example.com">
                </div>
                <div>
                    <label for="blacklistReasonInput">Powód (opcjonalnie):</label>
                    <input type="text" id="blacklistReasonInput" placeholder="np. Spamowanie">
                </div>
                <button type="button" class="add-to-blacklist-btn" onclick="handleAddEmailToBlacklist()">Dodaj do Blacklisty</button>
                <div id="addBlacklistError" class="error-message" style="margin-top: 8px;"></div>
                <div id="addBlacklistSuccess" class="success-message" style="margin-top: 8px;"></div>
            </div>

            <div class="table-container">
                <table id="blacklistTable">
                    <thead>
                        <tr>
                            <th>Email</th>
                            <th>Powód</th>
                            <th>Data Dodania</th>
                            <th>Akcje</th>
                        </tr>
                    </thead>
                    <tbody id="blacklistTableBody">
                    </tbody>
                </table>
            </div>
            <div id="blacklistError" class="error-message"></div>
        </div>
    </div>

    <script>
        const mainContainer = document.getElementById('mainContainer');
        const loginForm = document.getElementById('loginForm');
        const adminContent = document.getElementById('adminContent');
        const loginErrorDiv = document.getElementById('loginError');
        const loginSuccessDiv = document.getElementById('loginSuccess');
        const usersTableBody = document.querySelector('#usersTable tbody');
        const usersErrorDiv = document.getElementById('usersError');
        const blacklistTableBody = document.getElementById('blacklistTableBody');
        const blacklistErrorDiv = document.getElementById('blacklistError');
        const blacklistEmailInput = document.getElementById('blacklistEmailInput');
        const blacklistReasonInput = document.getElementById('blacklistReasonInput');
        const addBlacklistErrorDiv = document.getElementById('addBlacklistError');
        const addBlacklistSuccessDiv = document.getElementById('addBlacklistSuccess');
        const loggedInAdminUserSpan = document.getElementById('loggedInAdminUser');
        const adminUserInput = document.getElementById('adminUser');
        const adminPassInput = document.getElementById('adminPass');
        const loginButton = document.getElementById('loginButton');
        let usersRefreshInterval = null; 

        async function checkAdminStatusOnLoad() {
            loginErrorDiv.textContent = ''; 
            loginSuccessDiv.textContent = '';
            try {
                const response = await fetch('/admin/status');
                if (response.ok) {
                    loggedInAdminUserSpan.textContent = "{{ config.ADMIN_USERNAME }}"; 
                    showAdminContent();
                    fetchAndDisplayUsers();
                    fetchAndDisplayBlacklist(); 
                    if (usersRefreshInterval) clearInterval(usersRefreshInterval);
                    usersRefreshInterval = setInterval(() => {
                        fetchAndDisplayUsers();
                        fetchAndDisplayBlacklist();
                    }, 7000); 
                } else {
                    showLoginForm();
                }
            } catch (error) { console.error('Error checking admin status:', error); showLoginForm(); }
        }
        
        async function handleAdminLogin() {
            const username = adminUserInput.value;
            const password = adminPassInput.value;
            loginErrorDiv.textContent = '';
            loginSuccessDiv.textContent = '';

            try {
                const response = await fetch('/admin/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (response.ok) {
                    loggedInAdminUserSpan.textContent = username; 
                    showAdminContent();
                    fetchAndDisplayUsers();
                    fetchAndDisplayBlacklist(); 
                    if (usersRefreshInterval) clearInterval(usersRefreshInterval);
                    usersRefreshInterval = setInterval(() => {
                        fetchAndDisplayUsers();
                        fetchAndDisplayBlacklist();
                    }, 7000);
                } else {
                    loginErrorDiv.textContent = data.error || 'Błąd logowania.';
                }
            } catch (error) {
                console.error('Login error:', error);
                loginErrorDiv.textContent = 'Błąd połączenia z serwerem.';
            }
        }

        function showLoginForm() {
            mainContainer.classList.remove('admin-view');
            mainContainer.classList.add('login-view'); 
            loginForm.style.display = 'block';
            adminContent.style.display = 'none';
            if (usersRefreshInterval) { 
                clearInterval(usersRefreshInterval);
                usersRefreshInterval = null;
            }
        }

        function showAdminContent() {
            mainContainer.classList.remove('login-view');
            mainContainer.classList.add('admin-view'); 
            loginForm.style.display = 'none';
            adminContent.style.display = 'block';
        }

        async function fetchAndDisplayUsers() {
            usersErrorDiv.textContent = ''; 
            try {
                const response = await fetch('/admin/users');
                if (!response.ok) {
                    if (response.status === 401) {
                        showLoginForm();
                        loginErrorDiv.textContent = "Sesja admina wygasła lub brak autoryzacji. Zaloguj się ponownie.";
                        return;
                    }
                    throw new Error(`HTTP error ${response.status}`);
                }
                const users = await response.json();
                
                usersTableBody.innerHTML = ''; 

                if (users && users.length > 0) {
                    users.forEach(user => {
                        const row = usersTableBody.insertRow();
                        row.insertCell().textContent = user.id;
                        
                        const usernameCell = row.insertCell();
                        const statusIndicator = document.createElement('span');
                        statusIndicator.classList.add('status-indicator');
                        statusIndicator.classList.add(user.is_online ? 'online' : 'offline');
                        statusIndicator.title = user.is_online ? 'Online' : 'Offline';
                        usernameCell.appendChild(statusIndicator);
                        usernameCell.appendChild(document.createTextNode(user.username));
                        usernameCell.style.color = user.is_online ? '#333' : '#777'; 
                        
                        row.insertCell().textContent = user.email;
                        row.insertCell().textContent = user.is_admin ? 'Tak' : 'Nie';
                        
                        const bannedCell = row.insertCell();
                        bannedCell.textContent = user.is_banned ? 'Tak' : 'Nie';
                        if (user.is_banned) {
                            bannedCell.classList.add('banned-text');
                        }
                        
                        const actionsCell = row.insertCell();
                        if (!user.is_admin) { 
                            if (user.is_banned) {
                                const unbanBtn = document.createElement('button');
                                unbanBtn.textContent = 'Odblokuj';
                                unbanBtn.classList.add('action-button', 'unban-btn');
                                unbanBtn.onclick = () => handleUnbanUser(user.id);
                                actionsCell.appendChild(unbanBtn);
                            } else {
                                const banBtn = document.createElement('button');
                                banBtn.textContent = 'Zablokuj';
                                banBtn.classList.add('action-button', 'ban-btn');
                                banBtn.onclick = () => handleBanUser(user.id);
                                actionsCell.appendChild(banBtn);
                            }
                            const deleteBtn = document.createElement('button');
                            deleteBtn.textContent = 'Usuń';
                            deleteBtn.classList.add('action-button', 'delete-user-btn');
                            deleteBtn.onclick = () => handleDeleteUser(user.id, user.username);
                            actionsCell.appendChild(deleteBtn);
                        }
                    });
                } else {
                    usersTableBody.insertRow().insertCell().textContent = 'Brak użytkowników do wyświetlenia.';
                    usersTableBody.rows[0].cells[0].colSpan = 6;
                }
            } catch (error) {
                console.error('Error fetching users:', error);
                usersErrorDiv.textContent = 'Nie udało się pobrać listy użytkowników.';
            }
        }
        
        async function fetchAndDisplayBlacklist() {
            blacklistErrorDiv.textContent = '';
            try {
                const response = await fetch('/admin/blacklist');
                if (!response.ok) {
                    if (response.status === 401) { showLoginForm(); loginErrorDiv.textContent = "Sesja wygasła."; return; }
                    throw new Error(`HTTP error ${response.status}`);
                }
                const blacklist = await response.json();
                blacklistTableBody.innerHTML = ''; 

                if (blacklist && blacklist.length > 0) {
                    blacklist.forEach(entry => {
                        const row = blacklistTableBody.insertRow();
                        row.insertCell().textContent = entry.email;
                        row.insertCell().textContent = entry.reason || '-';
                        row.insertCell().textContent = entry.added_at ? new Date(entry.added_at).toLocaleString('pl-PL') : '-';
                        
                        const actionsCell = row.insertCell();
                        const unblacklistBtn = document.createElement('button');
                        unblacklistBtn.textContent = 'Usuń z Blacklisty';
                        unblacklistBtn.classList.add('action-button', 'unblacklist-btn');
                        unblacklistBtn.onclick = () => handleUnblacklistEmail(entry.email);
                        actionsCell.appendChild(unblacklistBtn);
                    });
                } else {
                    blacklistTableBody.insertRow().insertCell().textContent = 'Blacklista e-maili jest pusta.';
                    blacklistTableBody.rows[0].cells[0].colSpan = 4;
                }
            } catch (error) {
                console.error('Error fetching email blacklist:', error);
                blacklistErrorDiv.textContent = 'Nie udało się pobrać blacklisty e-maili.';
            }
        }

        async function handleAddEmailToBlacklist() {
            const email = blacklistEmailInput.value.trim();
            const reason = blacklistReasonInput.value.trim();
            addBlacklistErrorDiv.textContent = '';
            addBlacklistSuccessDiv.textContent = '';

            if (!email) { addBlacklistErrorDiv.textContent = 'Adres email jest wymagany.'; return; }
            if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) { addBlacklistErrorDiv.textContent = 'Nieprawidłowy format adresu email.'; return; }

            try {
                const response = await fetch(`/admin/blacklist/add`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ email: email, reason: reason || null })
                });
                const data = await response.json();
                if (response.ok) {
                    addBlacklistSuccessDiv.textContent = data.message || `Email '${email}' dodany do blacklisty.`;
                    blacklistEmailInput.value = ''; 
                    blacklistReasonInput.value = '';
                    fetchAndDisplayBlacklist(); 
                    setTimeout(() => { addBlacklistSuccessDiv.textContent = ''; }, 4000);
                } else if (response.status === 401) {
                    showLoginForm(); 
                    loginErrorDiv.textContent = "Sesja admina wygasła lub brak autoryzacji.";
                } else {
                    addBlacklistErrorDiv.textContent = `Błąd: ${data.error || 'Nieznany błąd serwera.'}`;
                }
            } catch (error) {
                console.error('Error adding email to blacklist:', error);
                addBlacklistErrorDiv.textContent = 'Błąd połączenia podczas dodawania do blacklisty.';
            }
        }

        async function handleUnblacklistEmail(email) {
            if (!confirm(`Czy na pewno chcesz usunąć email '${email}' z blacklisty?\nUmożliwi to ponowną rejestrację na ten adres.`)) return;
            try {
                const response = await fetch(`/admin/blacklist/${encodeURIComponent(email)}`, { method: 'DELETE' });
                const data = await response.json();
                if (response.ok) {
                    alert(`Email '${email}' został usunięty z blacklisty.`);
                } else if (response.status === 401) {
                    showLoginForm(); loginErrorDiv.textContent = "Sesja admina wygasła."; return;
                } else {
                    alert(`Błąd: ${data.error || 'Nieznany błąd.'}`);
                }
                fetchAndDisplayBlacklist();
            } catch (error) { console.error('Error unblacklisting email:', error); alert('Błąd usuwania emaila z blacklisty.'); }
        }
        
        async function handleBanUser(userId) {
            if (!confirm(`Czy na pewno chcesz zablokować użytkownika o ID ${userId}?`)) return;
            try {
                const response = await fetch(`/admin/users/${userId}/ban`, { method: 'POST' });
                const data = await response.json();
                if (response.ok) {
                    alert(`Użytkownik z ID ${userId} został zablokowany.`);
                } else if (response.status === 401) {
                    showLoginForm(); loginErrorDiv.textContent = "Sesja admina wygasła lub brak autoryzacji."; return;
                } else {
                    alert(`Błąd: ${data.error || 'Nieznany błąd.'}`);
                }
                fetchAndDisplayUsers(); 
            } catch (error) { console.error('Error banning user:', error); alert('Błąd banowania użytkownika.'); }
        }

        async function handleUnbanUser(userId) {
            if (!confirm(`Czy na pewno chcesz odblokować użytkownika o ID ${userId}?`)) return;
            try {
                const response = await fetch(`/admin/users/${userId}/unban`, { method: 'POST' });
                const data = await response.json();
                if (response.ok) {
                    alert(`Użytkownik z ID ${userId} został odblokowany.`);
                } else if (response.status === 401) {
                    showLoginForm(); loginErrorDiv.textContent = "Sesja admina wygasła lub brak autoryzacji."; return;
                } else {
                    alert(`Błąd: ${data.error || 'Nieznany błąd.'}`);
                }
                fetchAndDisplayUsers();
            } catch (error) { console.error('Error unbanning user:', error); alert('Błąd odbanowywania użytkownika.'); }
        }
        
        async function handleAdminLogout() {
            try {
                const response = await fetch('/admin/logout', { method: 'POST' });
                if (response.ok) {
                    showLoginForm();
                    loginSuccessDiv.textContent = 'Wylogowano pomyślnie.'; 
                    setTimeout(() => { loginSuccessDiv.textContent = ''; }, 3000);
                } else {
                    const data = await response.json();
                    alert('Błąd wylogowania: ' + (data.error || 'Nieznany błąd'));
                }
            } catch (error) {
                console.error('Logout error:', error);
                alert('Błąd połączenia podczas wylogowywania.');
            }
        }
        
        async function handleDeleteUser(userId, username) {
            if (!confirm(`UWAGA: Czy na pewno chcesz TRWALE usunąć użytkownika '${username}' (ID: ${userId})?\\nTej operacji NIE MOŻNA cofnąć!`)) return;
            if (!confirm(`Ostatnie potwierdzenie: Trwałe usunięcie konta '${username}'. Kontynuować?`)) return;
            try {
                const response = await fetch(`/admin/users/${userId}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }});
                const data = await response.json();
                if (response.ok) {
                    alert(`Użytkownik '${username}' został trwale usunięty.`);
                } else if (response.status === 401) {
                    showLoginForm(); loginErrorDiv.textContent = "Sesja admina wygasła."; return;
                } else {
                    alert(`Błąd usuwania: ${data.error || 'Nieznany błąd.'}`);
                }
                fetchAndDisplayUsers(); 
                fetchAndDisplayBlacklist(); // Odśwież też blacklistę, bo email mógł tam trafić
            } catch (error) { console.error('Error deleting user:', error); alert('Błąd połączenia podczas usuwania użytkownika.'); }
        }
        
        checkAdminStatusOnLoad();

        function onLoginKeyPress(event) { if (event.key === 'Enter') { event.preventDefault(); handleAdminLogin(); } }
        adminUserInput.addEventListener('keyup', onLoginKeyPress);
        adminPassInput.addEventListener('keyup', onLoginKeyPress);
        if(loginButton) loginButton.addEventListener('click', handleAdminLogin);
    </script>
</body>
</html>
"""


@app.route('/admin/panel')
@admin_required  # Dostęp tylko po zalogowaniu jako admin (sprawdzi sesję)
def admin_panel_page():
    # Jeśli @admin_required przepuści, to znaczy, że sesja admina jest aktywna
    return render_template_string(ADMIN_PANEL_HTML)


@app.route('/admin/blacklist/add', methods=['POST'])
@admin_required
def admin_add_to_email_blacklist():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    email_to_add = data.get('email')
    reason = data.get('reason')  # Może być None

    if not email_to_add:
        return jsonify({"error": "Email is required"}), 400

    try:
        validated_email = validate_email(email_to_add).email
    except EmailNotValidError:
        return jsonify({"error": "Invalid email format"}), 400

    existing_entry = EmailBlacklist.query.filter_by(
        email=validated_email).first()
    if existing_entry:
        return jsonify({
            "error":
            f"Email '{validated_email}' is already on the blacklist."
        }), 409  # Conflict

    try:
        new_blacklist_entry = EmailBlacklist(email=validated_email,
                                             reason=reason)
        db.session.add(new_blacklist_entry)
        db.session.commit()
        logger.info(
            f"Admin added email '{validated_email}' to blacklist. Reason: {reason if reason else 'N/A'}"
        )
        return jsonify({
            "message":
            f"Email '{validated_email}' has been added to the blacklist."
        }), 201  # Created
    except Exception as e:
        db.session.rollback()
        logger.exception(
            f"Error adding email '{validated_email}' to blacklist: {e}")
        return jsonify(
            {"error": "Server error during email blacklisting operation"}), 500


# --- KONIEC NOWYCH ZMIAN ---


# Prosty sposób na przekierowanie do panelu logowania, jeśli sesja admina nie istnieje
# To jest obejście, bo @admin_required już zwraca 401. Klient (JS) powinien obsłużyć 401.
@app.route(
    '/admin/'
)  # Bez @admin_required na tym głównym, aby móc pokazać stronę logowania
def admin_index():
    if session.get('is_admin_logged_in'):
        return render_template_string(
            ADMIN_PANEL_HTML)  # Pokaż panel jeśli zalogowany
    else:
        # Zamiast renderować login tutaj, po prostu serwuj HTML, który ma logikę JS do logowania
        return render_template_string(
            ADMIN_PANEL_HTML)  # Zawsze serwuj główny HTML panelu


# --- KONIEC NOWYCH ZMIAN ---


@app.route(
    '/admin/status')  # Prosty endpoint do sprawdzania statusu logowania admina
@admin_required
def admin_status():
    return jsonify({"message": "Admin is logged in."}), 200


# --- KONIEC NOWYCH ZMIAN ---


# --- NOWE ZMIANY (Panel Admina - Endpointy API) ---
@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_all_users():
    try:
        users = User.query.order_by(User.id).all()
        users_data = []
        # --- NOWE ZMIANY: Dodanie statusu online do danych użytkownika ---
        online_user_ids = set(
            connected_sids_to_user_id.values())  # Pobierz zbiór ID online
        for user in users:
            user_dict = user.to_dict(
            )  # to_dict() już zawiera is_banned, is_admin
            user_dict[
                'is_online'] = user.id in online_user_ids  # Dodaj nowy klucz
            users_data.append(user_dict)
        # --- KONIEC NOWYCH ZMIAN ---
        return jsonify(users_data), 200
    except Exception as e:
        logger.exception("Error in admin_get_all_users")
        return jsonify({"error": "Server error fetching users"}), 500


@app.route('/admin/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def admin_ban_user(user_id):
    try:
        user_to_ban = User.query.filter_by(
            id=user_id).first()  # Lepsze niż get()
        if not user_to_ban:
            logger.warning(f"Attempt to ban non-existent user ID: {user_id}")
            return jsonify({"error": "User not found"}), 404

        # Jeśli banujesz siebie samego i jednocześnie jesteś "Userem" w bazie User
        if user_to_ban.is_admin:
            return jsonify(
                {"error":
                 "Cannot ban an admin account through this panel."}), 400

        if user_to_ban.is_banned:
            return jsonify({"message": "User is already banned"}), 200

        user_to_ban.is_banned = True
        db.session.commit()  # Zatwierdź zmiany
        logger.info(
            f"Admin banned user ID: {user_id} (Username: {user_to_ban.username})"
        )

        # Opcjonalnie: Poinformuj i rozłącz SocketIO - (Ten fragment jest poprawny)
        sids_for_banned_user = [
            sid for sid, uid in connected_sids_to_user_id.items()
            if uid == user_id
        ]
        for sid_to_disconnect in sids_for_banned_user:  # Zmieniono nazwę zmiennej
            logger.info(
                f"Notifying and disconnecting SID {sid_to_disconnect} for banned user {user_id}."
            )
            socketio.emit(
                'account_status_changed', {
                    'banned': True,
                    'reason': 'Konto zostało zablokowane przez administratora.'
                },
                room=sid_to_disconnect)
            # --- NOWE ZMIANY: Poprawne rozłączanie klienta ---
            try:
                # Użyj zaimportowanej funkcji disconnect z flask_socketio
                socketio_disconnect_client(
                    sid_to_disconnect, namespace='/',
                    silent=False)  # Użyj namespace, jeśli masz
                logger.info(
                    f"Successfully called disconnect for SID: {sid_to_disconnect}"
                )
            except Exception as e_disconnect:
                logger.error(
                    f"Error trying to disconnect SID {sid_to_disconnect}: {e_disconnect}"
                )
            # --- KONIEC NOWYCH ZMIAN ---

        return jsonify({
            "message":
            f"User '{user_to_ban.username}' has been banned and notified.",
            "user": user_to_ban.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error banning user ID: {user_id} - {e}")
        return jsonify({"error": "Server error during banning operation"}), 500


@app.route('/admin/users/<int:user_id>/unban', methods=['POST'])
@admin_required
def admin_unban_user(user_id):
    try:
        user_to_unban = User.query.filter_by(
            id=user_id).first()  # Lepsze niż get()
        if not user_to_unban:
            logger.warning(f"Attempt to unban non-existent user ID: {user_id}")
            return jsonify({"error": "User not found"}), 404

        if not user_to_unban.is_banned:
            return jsonify({"message": "User is not currently banned"}), 200

        user_to_unban.is_banned = False
        db.session.commit()  # Zatwierdź zmiany
        logger.info(
            f"Admin unbanned user ID: {user_id} (Username: {user_to_unban.username})"
        )

        sids_for_unbanned_user = [
            sid for sid, uid in connected_sids_to_user_id.items()
            if uid == user_id
        ]
        for sid in sids_for_unbanned_user:
            socketio.emit('account_status_changed', {
                'banned': False,
                'reason': 'Twoje konto zostało odblokowane.'
            },
                          room=sid)

        return jsonify({
            "message": f"User '{user_to_unban.username}' has been unbanned.",
            "user": user_to_unban.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error unbanning user ID: {user_id} - {e}")
        return jsonify({"error":
                        "Server error during unbanning operation"}), 500


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    try:
        user_to_delete = User.query.filter_by(id=user_id).first()
        if not user_to_delete:
            logger.warning(
                f"Attempt to delete non-existent user ID: {user_id}")
            return jsonify({"error": "User not found"}), 404

        if user_to_delete.is_admin:
            logger.warning(
                f"Attempt to delete admin account (ID: {user_id}, Username: {user_to_delete.username}). Denied."
            )
            return jsonify(
                {"error": "Admin account cannot be deleted this way."}), 400

        # --- POPRAWKA: Zdefiniuj username_deleted PRZED użyciem ---
        username_deleted_for_event = user_to_delete.username  # Zapamiętaj nazwę dla eventu
        # --- KONIEC POPRAWKI ---

        # Usuwanie relacji i wiadomości (bez zmian, ale upewnij się, że działa)
        BlockedRelationship.query.filter((BlockedRelationship.blocker_id == user_id) | \
                                       (BlockedRelationship.blocked_id == user_id)).delete(synchronize_session=False)
        RoomMembership.query.filter_by(user_id=user_id).delete(
            synchronize_session=False)

        messages_by_user = Message.query.filter(
            (Message.sender_id == user_id)
            | (Message.receiver_id == user_id)).all()
        for msg in messages_by_user:
            if msg.sender_id == user_id:
                msg.sender_id = None
            if msg.receiver_id == user_id:
                msg.receiver_id = None

        db.session.delete(user_to_delete)
        db.session.commit()

        sids_for_deleted_user = [
            sid for sid, uid in connected_sids_to_user_id.items()
            if uid == user_id
        ]
        for sid_to_disconnect_del in sids_for_deleted_user:
            logger.info(
                f"Notifying and disconnecting SID {sid_to_disconnect_del} for deleted user {user_id}."
            )
            # --- POPRAWKA: Użyj poprawnej nazwy zmiennej dla username ---
            socketio.emit('account_deleted', {
                'user_id': user_id,
                'username': username_deleted_for_event
            },
                          room=sid_to_disconnect_del)
            # --- KONIEC POPRAWKI ---
            # --- POPRAWKA: Użyj zaimportowanej funkcji disconnect ---
            try:
                socketio_disconnect_client(sid_to_disconnect_del,
                                           namespace='/',
                                           silent=False)
                logger.info(
                    f"Successfully called disconnect for SID: {sid_to_disconnect_del} (deleted user)"
                )
            except Exception as e_disconnect_del:
                logger.error(
                    f"Error trying to disconnect SID {sid_to_disconnect_del} (deleted user): {e_disconnect_del}"
                )
            # --- KONIEC POPRAWKI ---

        # --- POPRAWKA: Użyj poprawnej nazwy zmiennej dla username ---
        socketio.emit('user_offline', {
            'user_id': user_id,
            'username': username_deleted_for_event
        })
        logger.debug(
            f"Emitted 'user_offline' for deleted user {user_id} ({username_deleted_for_event}) to all clients."
        )
        # --- KONIEC POPRAWKI ---

        logger.info(
            f"Admin deleted user ID: {user_id} (Username: {username_deleted_for_event})."
        )
        return jsonify({
            "message":
            f"User '{username_deleted_for_event}' and associated data has been deleted."
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting user ID: {user_id} - {e}")
        return jsonify({"error": "Server error during user deletion"}), 500


# W handle_send_message - już jest sprawdzanie if sender.is_banned, to jest OK.
# Po rozłączeniu przez socketio.disconnect(sid), nowy event wysyłania wiadomości od tego SID i tak by nie doszedł,
# a przy ponownym połączeniu i tak byłoby sprawdzane 'is_banned' przy evencie 'authenticate'.


# --- NOWE ZMIANY (Blacklista E-maili - Model) ---
class EmailBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True,
                      nullable=False)  # Unikalny zablokowany email
    reason = db.Column(db.String(255),
                       nullable=True)  # Opcjonalny powód dodania do blacklisty
    added_at = db.Column(db.DateTime, default=datetime.datetime.now)

    def __repr__(self):
        return f'<EmailBlacklist {self.email}>'


# --- KONIEC NOWYCH ZMIAN ---


class User(db.Model):
    """Model użytkownika czatu."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True,
                         nullable=False)  # Nick/nazwa użytkownika
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128),
                              nullable=False)  # Hasło hashowane
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    # --- NOWE ZMIANY (Panel Admina - Model User) ---
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    # --- KONIEC NOWYCH ZMIAN ---

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

    def to_dict(self):
        # --- NOWE ZMIANY (Panel Admina - Model User to_dict) ---
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'is_banned': self.is_banned,  # Dodajemy status zbanowania
            'is_admin': self.is_admin  # Dodajemy status admina
        }
        # --- KONIEC NOWYCH ZMIAN ---


class BlockedRelationship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer,
                           db.ForeignKey('user.id', ondelete='CASCADE'),
                           nullable=False)  # Kto zablokował
    blocked_id = db.Column(db.Integer,
                           db.ForeignKey('user.id', ondelete='CASCADE'),
                           nullable=False)  # Kto został zablokowany
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)

    # Upewnij się, że para (blocker_id, blocked_id) jest unikalna
    __table_args__ = (db.UniqueConstraint('blocker_id',
                                          'blocked_id',
                                          name='_blocker_blocked_uc'), )

    blocker = db.relationship('User',
                              foreign_keys=[blocker_id],
                              backref='blocking_relationships')
    blocked_user = db.relationship('User',
                                   foreign_keys=[blocked_id],
                                   backref='blocked_by_relationships')

    def __repr__(self):
        return f'<BlockedRelationship {self.blocker_id} blocks {self.blocked_id}>'


class Message(db.Model):
    """Model wiadomości czatu."""
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer,
                          db.ForeignKey('user.id', ondelete='SET NULL'),
                          nullable=True)
    # --- NOWE ZMIANY (CHAT GRUPOWY - Etap 1/5) ---
    receiver_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='SET NULL'),
        nullable=True)  # Pozostawiamy dla prywatnych wiadomości
    room_id = db.Column(
        db.Integer, db.ForeignKey('chat_room.id'), nullable=True
    )  # Nowe pole: ID pokoju czatu (NULL dla wiadomości prywatnych)
    # --- KONIEC NOWYCH ZMIAN ---
    content = db.Column(
        db.Text, nullable=True
    )  # Wiadomość tekstowa może być teraz opcjonalna, jeśli jest załącznik
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    edited_at = db.Column(db.DateTime,
                          nullable=True)  # Data i czas ostatniej edycji

    replied_to_message_id = db.Column(db.Integer,
                                      db.ForeignKey('message.id'),
                                      nullable=True)
    replied_to_message = db.relationship('Message',
                                         remote_side=[id],
                                         backref='replies',
                                         uselist=False)

    attachment_server_filename = db.Column(db.String(255), nullable=True)
    attachment_original_filename = db.Column(db.String(255), nullable=True)
    attachment_mimetype = db.Column(db.String(100), nullable=True)
    is_read_by_receiver = db.Column(
        db.Boolean, default=False,
        nullable=False)  # Dotyczy tylko prywatnych wiadomości, nie grup

    sender = db.relationship('User',
                             foreign_keys=[sender_id],
                             backref='sent_messages')
    receiver = db.relationship('User',
                               foreign_keys=[receiver_id],
                               backref='received_messages')
    # --- NOWE ZMIANY (CHAT GRUPOWY - Etap 1/5) ---
    room = db.relationship('ChatRoom',
                           foreign_keys=[room_id],
                           backref='messages')  # Relacja do pokoju

    # --- KONIEC NOWYCH ZMIAN ---

    def to_dict(self):
        data = {
            'id': self.id,
            'sender_id': self.sender_id,
            # --- NOWE ZMIANY (CHAT GRUPOWY - Etap 1/5) ---
            'receiver_id': self.receiver_id,
            'room_id': self.room_id,  # Dodajemy room_id
            # --- KONIEC NOWYCH ZMIAN ---
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'sender_username':
            self.sender.username if self.sender else "Nieznany Nadawca",
            'attachment_server_filename': self.attachment_server_filename,
            'attachment_original_filename': self.attachment_original_filename,
            'attachment_mimetype': self.attachment_mimetype,
            'is_read_by_receiver': self.is_read_by_receiver,
            'replied_to_message_id': self.replied_to_message_id,
            'edited_at': self.edited_at.isoformat() if self.edited_at else None
        }
        # Opcjonalnie, jeśli chcesz, aby do dictu była dołączana treść cytowanej wiadomości:
        # Pamiętaj, że to zwiększy rozmiar przesyłanych danych.
        if self.replied_to_message:
            # Aby uniknąć rekurencji (wiadomość cytuje wiadomość, która cytuje...),
            # zwracamy tylko podstawowe informacje o cytowanej wiadomości.
            data['replied_to_message_preview'] = {
                'id':
                self.replied_to_message.id,
                'sender_id':
                self.replied_to_message.sender_id,
                'sender_username':
                self.replied_to_message.sender.username
                if self.replied_to_message.sender else "Nieznany",
                'content':
                self.replied_to_message.content[:50] +
                "..." if self.replied_to_message.content
                and len(self.replied_to_message.content) > 50 else
                self.replied_to_message.content,
                'attachment_original_filename':
                self.replied_to_message.attachment_original_filename
            }
        return data
        # --- KONIEC NOWYCH ZMIAN ---


# --- NOWE ZMIANY (CHAT SERVER - Zarządzanie pokojem przez admina ETAP 1/3) ---
class ChatRoom(db.Model):
    """Model pokoju czatu (dla wiadomości grupowych)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    creator_id = db.Column(db.Integer,
                           db.ForeignKey('user.id', ondelete='SET NULL'),
                           nullable=True)  # Twórca pokoju, może być adminem
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    password_hash = db.Column(db.String(128), nullable=True)

    creator = db.relationship('User',
                              foreign_keys=[creator_id])  # Relacja do twórcy

    def to_dict(self):
        member_ids = [membership.user_id for membership in self.memberships]
        return {
            'id': self.id,
            'name': self.name,
            'creator_id': self.creator_id,  # Dodaj creator_id
            'creator_username': self.creator.username
            if self.creator else "Nieznany",  # Dodaj username twórcy
            'created_at': self.created_at.isoformat(),
            'has_password': self.password_hash is not None,
            'member_ids': member_ids
        }

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# --- KONIEC NOWYCH ZMIAN (CHAT SERVER - Zarządzanie pokojem przez admina ETAP 1/3) ---


class RoomMembership(db.Model):
    """Model reprezentujący członkostwo użytkownika w pokoju czatu."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id', ondelete='CASCADE'),
                        nullable=False)
    room_id = db.Column(db.Integer,
                        db.ForeignKey('chat_room.id', ondelete='CASCADE'),
                        nullable=False)
    # ondelete='CASCADE' oznacza, że jeśli użytkownik lub pokój zostaną usunięte, członkostwo również zniknie.

    # Upewnij się, że każdy użytkownik może być tylko raz w danym pokoju
    __table_args__ = (db.UniqueConstraint('user_id',
                                          'room_id',
                                          name='_user_room_uc'), )

    user = db.relationship('User',
                           backref=db.backref('room_memberships',
                                              lazy=True,
                                              cascade="all, delete-orphan"))
    room = db.relationship('ChatRoom',
                           backref=db.backref('memberships',
                                              lazy=True,
                                              cascade="all, delete-orphan"))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'room_id': self.room_id
        }


# --- KONIEC NOWYCH ZMIAN ---


@app.route('/')
def index():
    return "Chat Server is running!"


@app.route('/users/<int:user_to_block_id>/block', methods=['POST'])
def block_user_endpoint(user_to_block_id):
    data = request.get_json()
    if not data: return jsonify({"error": "Missing JSON payload"}), 400

    blocker_id = data.get(
        'blocker_id')  # Klient musi przesłać swoje ID jako blokującego
    if blocker_id is None:
        return jsonify({"error": "Blocker ID is required"}), 400

    if blocker_id == user_to_block_id:
        return jsonify({"error": "Cannot block yourself"}), 400

    # Sprawdź, czy użytkownicy istnieją
    blocker = User.query.get(blocker_id)
    blocked = User.query.get(user_to_block_id)
    if not blocker or not blocked:
        return jsonify({"error": "Blocker or blocked user not found"}), 404

    # Sprawdź, czy relacja już nie istnieje
    existing_block = BlockedRelationship.query.filter_by(
        blocker_id=blocker_id, blocked_id=user_to_block_id).first()
    if existing_block:
        return jsonify({"message": "User already blocked"}), 200

    try:
        new_block = BlockedRelationship(blocker_id=blocker_id,
                                        blocked_id=user_to_block_id)
        db.session.add(new_block)
        db.session.commit()
        logger.info(f"User {blocker_id} blocked user {user_to_block_id}.")
        # Opcjonalnie: Poinformuj zablokowanego użytkownika (jeśli chcemy taką funkcjonalność)
        # socketio.emit('you_were_blocked_by', {'blocker_id': blocker_id, 'blocker_username': blocker.username}, room=str(user_to_block_id))
        return jsonify({"message":
                        f"User {blocked.username} is now blocked."}), 201
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error blocking user: {e}")
        return jsonify({"error": "Server error during block operation"}), 500


@app.route('/users/<int:user_to_unblock_id>/block', methods=['DELETE'])
def unblock_user_endpoint(user_to_unblock_id):
    data = request.get_json()
    if not data: return jsonify({"error": "Missing JSON payload"}), 400

    unblocker_id = data.get('unblocker_id')  # Klient przesyła swoje ID
    if unblocker_id is None:
        return jsonify({"error": "Unblocker ID is required"}), 400

    block_to_remove = BlockedRelationship.query.filter_by(
        blocker_id=unblocker_id, blocked_id=user_to_unblock_id).first()
    if not block_to_remove:
        return jsonify({
            "error":
            "Block relationship not found or user not blocked by you"
        }), 404

    try:
        db.session.delete(block_to_remove)
        db.session.commit()
        logger.info(
            f"User {unblocker_id} unblocked user {user_to_unblock_id}.")
        # Opcjonalnie: Poinformuj odblokowanego użytkownika
        # unblocked_user_obj = User.query.get(user_to_unblock_id)
        # if unblocked_user_obj:
        # socketio.emit('you_were_unblocked_by', {'unblocker_id': unblocker_id, 'unblocker_username': User.query.get(unblocker_id).username}, room=str(user_to_unblock_id))
        return jsonify({
            "message":
            f"User {User.query.get(user_to_unblock_id).username} has been unblocked."
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error unblocking user: {e}")
        return jsonify({"error": "Server error during unblock operation"}), 500


# --- NOWE ZMIANY ---
@app.route('/user/<int:user_id>', methods=['DELETE'])
def delete_user_account(user_id):
    data = request.get_json()
    password = data.get('password')  # Wymagaj hasła do potwierdzenia

    if not password:
        return jsonify({"error":
                        "Password is required to delete account"}), 400

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        return jsonify({"error": "User not found"}), 404

    # Weryfikacja hasła
    if not user_to_delete.check_password(password):
        return jsonify({"error": "Incorrect password"}), 401  # Unauthorized

    try:
        # WAŻNE: W tej implementacji usuwamy TYLKO rekord użytkownika.
        # Wiadomości wysłane/odebrane przez tego użytkownika (w tabeli Message)
        # pozostaną w bazie danych, ale ich pola sender_id/receiver_id będą
        # wskazywać na nieistniejącego użytkownika. To jest uproszczenie.
        # W bardziej zaawansowanym systemie, należałoby rozważyć:
        # a) Kaskadowe usuwanie wiadomości (np. za pomocą `db.relationship(..., cascade="all, delete-orphan")`)
        # b) Zmiana wiadomości na "Użytkownik usunięty" bez usuwania rekordu wiadomości.
        # Dla obecnych celów, to rozwiązanie jest wystarczające i minimalizuje ryzyko utraty innych danych.
        db.session.delete(user_to_delete)  # Usuń użytkownika

        # --- NOWE ZMIANY (Blacklista E-maili - Dodawanie przy usuwaniu konta) ---
        # Sprawdź, czy email już nie jest na blackliście (na wszelki wypadek)
        existing_blacklist_entry = EmailBlacklist.query.filter_by(
            email=email_to_blacklist).first()
        if not existing_blacklist_entry:
            blacklist_entry = EmailBlacklist(
                email=email_to_blacklist,
                reason=f"Account deleted by admin (User ID: {user_id})")
            db.session.add(blacklist_entry)
            logger.info(
                f"Email '{email_to_blacklist}' added to blacklist upon account deletion."
            )
        else:
            logger.info(
                f"Email '{email_to_blacklist}' was already on the blacklist.")
        # --- KONIEC NOWYCH ZMIAN ---
        db.session.commit()
        logger.info(
            f"User account deleted: User ID {user_id} (Username: {user_to_delete.username})"
        )

        # Opcjonalnie: Poinformuj innych użytkowników SocketIO, że ten użytkownik został usunięty
        # (np. poprzez specjalny event 'user_account_deleted').
        # Na razie, SocketIO disconnect już wyśle user_offline.

        return jsonify({"message": "User account deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user account {user_id}: {e}")
        return jsonify({"error": "Server error during deletion"}), 500


# --- KONIEC NOWYCH ZMIAN ---


# --- NOWE ZMIANY (CHAT GRUPOWY - Etap 2/5) ---
@app.route('/rooms', methods=['POST'])
def create_room():
    data = request.get_json()
    name = data.get('name')
    creator_id_from_request = data.get(
        'creator_id')  # Pobieramy creator_id z żądania
    password = data.get('password')

    if not name:
        return jsonify({"error": "Room name cannot be empty"}), 400
    if not (3 <= len(name) <= 100):
        return jsonify(
            {"error": "Room name must be between 3 and 100 characters"}), 400
    # --- NOWE ZMIANY (CHAT SERVER - Zarządzanie pokojem przez admina ETAP 1/3) ---
    if not creator_id_from_request:  # Sprawdź, czy creator_id zostało przesłane
        return jsonify({"error":
                        "Creator ID is required to create a room"}), 400
    # --- KONIEC NOWYCH ZMIAN (CHAT SERVER - Zarządzanie pokojem przez admina ETAP 1/3) ---

    if ChatRoom.query.filter_by(name=name).first():
        return jsonify({"error": "Room with this name already exists"}), 409

    creator = User.query.get(
        creator_id_from_request)  # Użyj creator_id_from_request
    if not creator:
        return jsonify({"error": "Creator user not found"}), 404

    try:
        # --- NOWE ZMIANY (CHAT SERVER - Zarządzanie pokojem przez admina ETAP 1/3) ---
        new_room = ChatRoom(name=name,
                            creator_id=creator.id)  # Ustaw creator_id
        # --- KONIEC NOWYCH ZMIAN (CHAT SERVER - Zarządzanie pokojem przez admina ETAP 1/3) ---
        if password:
            new_room.set_password(password)
        db.session.add(new_room)
        db.session.flush()

        membership = RoomMembership(user_id=creator.id,
                                    room_id=new_room.id)  # Użyj creator.id
        db.session.add(membership)

        db.session.commit()
        logger.info(
            f"New chat room created: '{name}' by User ID {creator.id}. Creator set to {new_room.creator_id}. Has password: {new_room.password_hash is not None}"
        )

        # --- NOWE ZMIANY ---
        # Poinformuj wszystkich klientów SocketIO o nowo utworzonym pokoju.
        # Domyślnie emit() bez argumentu `room` wysyła do wszystkich podłączonych.
        room_data_for_socket = new_room.to_dict(
        )  # Pobierz słownik danych pokoju
        socketio.emit('new_room_created',
                      room_data_for_socket)  # Emisja eventu
        logger.info(
            f"Emitted 'new_room_created' event to all clients with data: {room_data_for_socket}"
        )
        # --- KONIEC NOWYCH ZMIAN ---

        return jsonify({
            "message": "Room created successfully",
            "room": new_room.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating room: {e}")
        return jsonify({"error": "Server error during room creation"}), 500


# --- KONIEC ZMIAN w create_room ---


@app.route('/rooms', methods=['GET'])
def get_all_rooms():
    rooms = ChatRoom.query.all()
    return jsonify([room.to_dict() for room in rooms]), 200


# --- NOWE ZMIANY (CHAT GRUPOWY - Etap 3/5) ---
@app.route('/rooms/<int:room_id>/members', methods=['POST'])
def add_room_member(room_id):
    data = request.get_json()
    user_id = data.get('user_id')
    # --- NOWE ZMIANY (CHAT GRUPOWY - Bezpieczeństwo - Etap 2/5) ---
    password = data.get(
        'password')  # Hasło do pokoju (wymagane, jeśli pokój ma hasło)
    # --- KONIEC NOWYCH ZMIAN ---

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    room = ChatRoom.query.get(room_id)
    if not room:
        return jsonify({"error": "Room not found"}), 404

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # --- NOWE ZMIANY (CHAT GRUPOWY - Bezpieczeństwo - Etap 2/5) ---
    # Weryfikacja hasła, jeśli pokój jest chroniony
    if room.password_hash:  # Jeśli pokój ma ustawione hasło
        if not password:
            return jsonify({"error": "Password is required to join this room"
                            }), 401  # Unauthorized
        if not room.check_password(password):
            return jsonify({"error": "Incorrect password for this room"
                            }), 401  # Unauthorized
    # --- KONIEC NOWYCH ZMIAN ---

    if RoomMembership.query.filter_by(user_id=user_id,
                                      room_id=room_id).first():
        return jsonify({"message": "User is already a member of this room"
                        }), 200  # Już jest członkiem

    try:
        membership = RoomMembership(user_id=user_id, room_id=room_id)
        db.session.add(membership)
        db.session.commit()
        logger.info(
            f"User {user_id} added to room '{room.name}' (ID: {room_id}).")
        # Możesz wysłać event Socket.IO, aby poinformować o nowym członku pokoju.
        return jsonify({"message": "User added to room successfully"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding user {user_id} to room {room_id}: {e}")
        return jsonify({"error": "Server error adding member"}), 500


@app.route('/rooms/<int:room_id>/members/<int:user_id_to_leave>',
           methods=['DELETE'])
def remove_room_member(room_id, user_id_to_leave):
    data = request.get_json()
    admin_id_from_request = data.get('admin_id') if data else None

    room_to_manage = ChatRoom.query.get(room_id)
    if not room_to_manage:
        return jsonify({"error": "Room not found"}), 404

    # Sprawdź, czy żądający użytkownik to ten, który opuszcza, lub admin
    initiator_user_id_str = request.headers.get('X-Initiator-User-ID')
    initiator_user_id = int(
        initiator_user_id_str
    ) if initiator_user_id_str and initiator_user_id_str.isdigit() else None

    is_self_leave_action = (initiator_user_id is not None and initiator_user_id == user_id_to_leave) or \
                           (admin_id_from_request is not None and admin_id_from_request == user_id_to_leave)

    is_admin_action_on_other = (admin_id_from_request is not None
                                and room_to_manage.creator_id
                                == admin_id_from_request
                                and user_id_to_leave != admin_id_from_request)

    if not is_self_leave_action and not is_admin_action_on_other:
        if admin_id_from_request is None and not is_self_leave_action:  # Jeśli nie admin i nie self-leave
            return jsonify({"error":
                            "Admin ID or self-leave action required"}), 400
        # Jeśli admin_id podano, ale nie jest twórcą (a nie jest to self-leave)
        elif admin_id_from_request != room_to_manage.creator_id and not is_self_leave_action:
            logger.warning(
                f"User {admin_id_from_request} (not creator) tried to remove {user_id_to_leave}."
            )
            return jsonify(
                {"error":
                 "Only the room creator can remove other members"}), 403
        # Pozostałe przypadki powinny być już obsłużone przez logikę admin_id lub self_leave_action

    # --- NOWE ZMIANY (CHAT SERVER - Usuwanie pokoju przez twórcę) ---
    if is_self_leave_action and user_id_to_leave == room_to_manage.creator_id:
        # Twórca opuszcza pokój - usuwamy CAŁY pokój
        room_name_for_log = room_to_manage.name
        room_id_for_event = room_to_manage.id
        creator_username = room_to_manage.creator.username if room_to_manage.creator else "Twórca"

        # Pobierz listę ID członków PRZED usunięciem pokoju, aby ich powiadomić
        member_ids_before_delete = [
            m.user_id for m in room_to_manage.memberships
        ]

        try:
            # Usunięcie wiadomości powiązanych z pokojem (jeśli cascade nie jest ustawione)
            # Message.query.filter_by(room_id=room_to_manage.id).delete()
            # Usunięcie członkostw (jeśli cascade nie jest ustawione)
            # RoomMembership.query.filter_by(room_id=room_to_manage.id).delete()

            db.session.delete(
                room_to_manage)  # To powinno usunąć pokój i kaskadowo resztę
            db.session.commit()

            logger.info(
                f"Room '{room_name_for_log}' (ID: {room_id_for_event}) was deleted by its creator (ID: {user_id_to_leave})."
            )

            # Poinformuj wszystkich byłych członków, że pokój został usunięty
            # Używamy zebranych wcześniej member_ids
            for member_id in member_ids_before_delete:
                socketio.emit(
                    'room_deleted_by_creator', {
                        'room_id': room_id_for_event,
                        'room_name': room_name_for_log,
                        'creator_id': user_id_to_leave,
                        'creator_username': creator_username
                    },
                    room=str(member_id)
                )  # Wyślij do prywatnego pokoju każdego byłego członka

            logger.debug(
                f"Emitted 'room_deleted_by_creator' to former members of room {room_id_for_event}."
            )
            return jsonify({
                "message":
                f"Room '{room_name_for_log}' and your membership have been deleted."
            }), 200

        except Exception as e_room_delete:
            db.session.rollback()
            logger.exception(
                f"Error deleting room '{room_name_for_log}' (ID: {room_id_for_event}) by creator: {e_room_delete}"
            )
            return jsonify({"error": "Server error during room deletion"}), 500
    # --- KONIEC NOWYCH ZMIAN ---
    else:  # Standardowe opuszczanie przez nie-twórcę lub usuwanie członka przez admina
        membership = RoomMembership.query.filter_by(user_id=user_id_to_leave,
                                                    room_id=room_id).first()
        if not membership:
            return jsonify({"error": "User is not a member of this room"}), 404

        try:
            db.session.delete(membership)
            db.session.commit()

            user_left_obj = User.query.get(user_id_to_leave)
            user_left_username = user_left_obj.username if user_left_obj else f"ID {user_id_to_leave}"
            action_log_message = ""

            if is_self_leave_action:  # Nie-twórca opuszcza
                action_log_message = f"User '{user_left_username}' (ID: {user_id_to_leave}) left room '{room_to_manage.name}' (ID: {room_id})."
                socketio.emit('member_left_room', {
                    'room_id': room_id,
                    'user_id': user_id_to_leave,
                    'username': user_left_username
                },
                              room=str(room_id))
            else:  # Admin usuwa kogoś
                admin_obj = User.query.get(admin_id_from_request)
                admin_username = admin_obj.username if admin_obj else f"ID {admin_id_from_request}"
                action_log_message = (
                    f"User '{user_left_username}' (ID: {user_id_to_leave}) removed from room '{room_to_manage.name}' (ID: {room_id}) "
                    f"by admin '{admin_username}' (ID: {admin_id_from_request})."
                )
                socketio.emit('member_removed_from_room', {
                    'room_id': room_id,
                    'removed_user_id': user_id_to_leave,
                    'removed_username': user_left_username,
                    'admin_id': admin_id_from_request,
                    'admin_username': admin_username
                },
                              room=str(room_id))

            logger.info(action_log_message)
            return jsonify({"message":
                            "User removed/left room successfully"}), 200

        except Exception as e_member_remove:
            db.session.rollback()
            logger.exception(
                f"Error removing member {user_id_to_leave} from room {room_id}: {e_member_remove}"
            )
            return jsonify({"error": "Server error removing member"}), 500


# --- NOWE ZMIANY (Blokowanie użytkowników czatu - STUBY API) ---
@app.route('/users/<int:user_to_block_id>/block', methods=['POST'])
def block_user_stub(user_to_block_id):
    # W przyszłości: Wymaga uwierzytelnienia, kto blokuje
    # blocker_id = get_current_user_id_from_token_or_session()
    # Zapis do bazy danych: BlockedUsers.add(blocker_id, user_to_block_id)
    blocker_id_temp = request.json.get(
        'blocker_id', "NieznanyBlokujący")  # Dla testów, klient może to wysłać
    logger.info(
        f"[STUB] Żądanie zablokowania użytkownika ID: {user_to_block_id} przez ID: {blocker_id_temp}"
    )
    # Można dodać walidację, czy user_to_block_id istnieje
    return jsonify({
        "message":
        f"User {user_to_block_id} is now on your block list (stub)."
    }), 200


@app.route('/users/<int:user_to_unblock_id>/block',
           methods=['DELETE'])  # Zauważ, że używam /block z DELETE
def unblock_user_stub(user_to_unblock_id):
    # W przyszłości: Wymaga uwierzytelnienia
    # blocker_id = get_current_user_id_from_token_or_session()
    # Usunięcie z bazy: BlockedUsers.remove(blocker_id, user_to_unblock_id)
    unblocker_id_temp = request.json.get('unblocker_id',
                                         "NieznanyOdblokowujący")
    logger.info(
        f"[STUB] Żądanie odblokowania użytkownika ID: {user_to_unblock_id} przez ID: {unblocker_id_temp}"
    )
    return jsonify({
        "message":
        f"User {user_to_unblock_id} removed from your block list (stub)."
    }), 204  # 204 No Content jest typowe dla DELETE


# --- KONIEC NOWYCH ZMIAN ---


@app.route('/rooms/<int:room_id>/messages', methods=['GET'])
def get_room_messages(room_id):
    user_id = request.args.get('user_id', type=int)
    limit = min(request.args.get('limit', 50, type=int), 100)
    before = request.args.get('before')

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    room = ChatRoom.query.get(room_id)
    if not room:
        return jsonify({"error": "Room not found"}), 404

    # --- NOWE ZMIANY (CHAT GRUPOWY - Bezpieczeństwo - Etap 3/5) ---
    # Sprawdź, czy użytkownik jest członkiem pokoju
    membership = RoomMembership.query.filter_by(user_id=user_id,
                                                room_id=room_id).first()
    if not membership:
        # Zamiast 404, używamy 403 Forbidden, bo zasób istnieje, ale dostęp jest zabroniony.
        return jsonify({"error": "You are not a member of this room"}), 403
    # --- KONIEC NOWYCH ZMIAN ---

    q = Message.query.filter(Message.room_id == room_id)
    if before:
        before_dt = datetime.datetime.fromisoformat(before)
        q = q.filter(Message.timestamp < before_dt)

    msgs = q.order_by(Message.timestamp.desc()).limit(limit + 1).all()
    has_more = len(msgs) > limit
    msgs = msgs[:limit]
    msgs.reverse()

    next_before = msgs[0].timestamp.isoformat() if msgs else None

    return jsonify({
        "messages": [m.to_dict() for m in msgs],
        "has_more": has_more,
        "next_before": next_before
    }), 200


# --- NOWE ZMIANY ---
@app.route('/user/<int:user_id>', methods=['PUT'])
def update_username(user_id):
    data = request.get_json()
    new_username = data.get('new_username')

    if not new_username:
        return jsonify({"error": "New username cannot be empty"}), 400

    # Opcjonalnie: walidacja długości nazwy użytkownika, znaków itp.
    if not (3 <= len(new_username) <= 80):
        return jsonify(
            {"error": "Username must be between 3 and 80 characters"}), 400

    user_to_update = User.query.get(user_id)
    if not user_to_update:
        return jsonify({"error": "User not found"}), 404

    # Sprawdź, czy nowa nazwa użytkownika jest już zajęta przez INNEGO użytkownika
    existing_user_with_new_name = User.query.filter_by(
        username=new_username).first()
    if existing_user_with_new_name and existing_user_with_new_name.id != user_id:
        return jsonify({"error": "Username already taken by another user"
                        }), 409  # Conflict

    # Jeśli nazwa jest taka sama jak obecna, nic nie robimy
    if user_to_update.username == new_username:
        return jsonify({"message": "Username is already the same"}), 200

    try:
        user_to_update.username = new_username
        db.session.commit()
        logger.info(f"User {user_id} username updated to: {new_username}")
        # Możemy również poinformować SocketIO o zmianie nazwy użytkownika,
        # ale na razie klient będzie odświeżał swoją nazwę po sukcesie.
        return jsonify({
            "message": "Username updated successfully",
            "new_username": new_username
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating username for user {user_id}: {e}")
        return jsonify({"error": "Server error during update"}), 500


# --- KONIEC NOWYCH ZMIAN ---


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"error": "Missing username, email, or password"}), 400

    # --- NOWE ZMIANY ---
    # Walidacja e-maila (przeniesiona na początek)
    try:
        validated_email = validate_email(email).email
    except EmailNotValidError:
        return jsonify({"error": "Invalid email format"}), 400

    # --- NOWE ZMIANY (Blacklista E-maili - Sprawdzanie przy rejestracji) ---
    if EmailBlacklist.query.filter_by(email=validated_email).first():
        logger.warning(
            f"Registration attempt with blacklisted email: {validated_email}")
        return jsonify({
            "error":
            "This email address cannot be used for registration."
        }), 403  # Forbidden
    # --- KONIEC NOWYCH ZMIAN ---

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409
    if User.query.filter_by(email=validated_email).first():
        return jsonify({"error": "Email already registered"}), 409

    new_user = User(username=username, email=validated_email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"New user registered: {username}")
    return jsonify({
        "message": "User registered successfully",
        "user_id": new_user.id
    }), 201


@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400
    try:
        validated_email = validate_email(email).email
    except EmailNotValidError:
        return jsonify({"error": "Invalid email format"}), 400

    user = User.query.filter_by(email=validated_email).first()
    if not user:
        return jsonify({"error": "Email not registered"}), 404

    # --- NOWE ZMIANY (Panel Admina - Sprawdzanie bana przy logowaniu) ---
    if user.is_banned:
        logger.warning(
            f"Login attempt by banned user: {user.username} (ID: {user.id})")
        return jsonify({"error":
                        "Your account has been banned."}), 403  # Forbidden
    # --- KONIEC NOWYCH ZMIAN ---

    if not user.check_password(password):
        return jsonify({"error": "Incorrect password"}), 401

    logger.info(f"User logged in: {user.username}")
    return jsonify({
        "message": "Logged in successfully",
        "user_id": user.id,
        "username": user.username
    }), 200


# --- KONIEC ZMIAN ---


@app.route('/users', methods=['GET'])
def get_all_users():
    """Endpoint do pobierania listy wszystkich zarejestrowanych użytkowników."""
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200


# --- NOWE ZMIANY (CHAT SERVER) ---
@app.route('/messages/<int:user1_id>/<int:user2_id>', methods=['GET'])
def get_message_history(user1_id, user2_id):
    # Parametry paginacji
    limit = min(int(request.args.get('limit', 50)), 100)  # maks. 100 na raz
    before = request.args.get('before')  # ISO timestamp

    # Podstawowy filtr konwersacji
    q = Message.query.filter((
        (Message.sender_id == user1_id) & (Message.receiver_id == user2_id))
                             | ((Message.sender_id == user2_id)
                                & (Message.receiver_id == user1_id)))
    if before:
        before_dt = datetime.datetime.fromisoformat(before)
        q = q.filter(Message.timestamp < before_dt)

    # Pobierz limit+1 rekordów (żeby sprawdzić, czy jest więcej)
    msgs = q.order_by(Message.timestamp.desc()).limit(limit + 1).all()
    has_more = len(msgs) > limit
    msgs = msgs[:limit]  # obetnij do parametru limit
    msgs.reverse()  # odwróć, by były rosnąco po czasie

    next_before = msgs[0].timestamp.isoformat() if msgs else None

    return jsonify({
        "messages": [m.to_dict() for m in msgs],
        "has_more": has_more,
        "next_before": next_before
    }), 200


# --- KONIEC NOWYCH ZMIAN (CHAT SERVER) ---


# --- NOWE ZMIANY: Endpoint do wysyłania plików ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        # Generowanie unikalnej nazwy dla pliku na serwerze
        file_ext = original_filename.rsplit('.', 1)[1].lower()
        unique_server_filename = f"{uuid.uuid4().hex}.{file_ext}"

        upload_path = os.path.join(app.config['UPLOAD_FOLDER'],
                                   unique_server_filename)
        try:
            file.save(upload_path)
            logger.info(
                f"File {original_filename} uploaded successfully as {unique_server_filename}"
            )
            return jsonify({
                "message": "File uploaded successfully",
                "attachment_server_filename":
                unique_server_filename,  # Nazwa na serwerze
                "attachment_original_filename":
                original_filename,  # Oryginalna nazwa
                "attachment_mimetype": file.mimetype
            }), 201
        except Exception as e:
            logger.error(
                f"Could not save uploaded file {original_filename}: {e}")
            return jsonify({"error": "Could not save file on server"}), 500
    else:
        return jsonify({"error": "File type not allowed"}), 400


# --- ZMIANY w /download_file ---
@app.route('/download_file/<server_filename>', methods=['GET'])
def download_file(server_filename):
    """Serwuje plik do pobrania na podstawie jego unikalnej nazwy na serwerze,
       sugerując oryginalną nazwę pliku do zapisu."""
    try:
        # Znajdź wiadomość (lub osobną tabelę załączników w przyszłości),
        # aby pobrać oryginalną nazwę pliku powiązaną z server_filename.
        message_with_attachment = Message.query.filter_by(
            attachment_server_filename=server_filename).first()

        original_name_to_suggest = server_filename  # Domyślnie, jeśli nie znajdziemy oryginalnej
        if message_with_attachment and message_with_attachment.attachment_original_filename:
            original_name_to_suggest = message_with_attachment.attachment_original_filename

        # --- Bezpieczniejsze tworzenie nazwy do pobrania ---
        # Usuń potencjalnie niebezpieczne znaki z sugerowanej nazwy, ale zachowaj czytelność
        safe_download_name = secure_filename(original_name_to_suggest)
        if not safe_download_name:  # Jeśli secure_filename usunęło wszystko
            safe_download_name = "downloaded_file"
        # --- Koniec zmian ---

        logger.info(
            f"Attempting to send file: {server_filename} with suggested download name: {safe_download_name}"
        )

        # Użyj parametru download_name (dla nowszych Flask) LUB ustaw nagłówek ręcznie
        # send_from_directory samo w sobie próbuje ustawić Content-Disposition,
        # ale download_name daje lepszą kontrolę nad sugerowaną nazwą.
        response = send_from_directory(
            app.config['UPLOAD_FOLDER'],
            server_filename,
            as_attachment=True,
            download_name=
            safe_download_name  # Ta opcja powinna działać w nowszych Flask/Werkzeug
        )

        # Dla starszych wersji lub jako fallback, można ustawić nagłówek ręcznie:
        # response = make_response(send_from_directory(app.config['UPLOAD_FOLDER'], server_filename, as_attachment=False))
        # response.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{urllib.parse.quote(safe_download_name.encode('utf-8'))}"
        # response.headers["Content-Type"] = message_with_attachment.attachment_mimetype if message_with_attachment else 'application/octet-stream'

        return response

    except FileNotFoundError:
        logger.error(f"File not found for download: {server_filename}")
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        logger.error(f"Error downloading file {server_filename}: {e}")
        return jsonify({"error": "Could not download file"}), 500


# --- KONIEC ZMIAN ---

# --- Obsługa SocketIO (Real-time Communication) ---


@socketio.on('connect')
def handle_connect():
    """Obsługuje nowe połączenia Socket.IO."""
    logger.info(f"Client connected: {request.sid}")
    # Tu można dodać logikę uwierzytelniania, np. sprawdzić token z 'request.args'
    # if not authenticated: disconnect()


@socketio.on('disconnect')
def handle_disconnect():
    """Obsługuje rozłączenia klientów Socket.IO."""
    logger.info(f"Client disconnected: {request.sid}")
    user_id = connected_sids_to_user_id.pop(request.sid, None)
    if user_id:
        # --- NOWE ZMIANY (CHAT SERVER) ---
        # Poinformuj innych (oprócz rozłączającego się), że użytkownik jest offline.
        # Używamy argumentu `to=None` (domyślny broadcast) i `skip_sid`.
        socketio.emit('user_offline', {'user_id': user_id},
                      skip_sid=request.sid)
        # --- KONIEC NOWYCH ZMIAN (CHAT SERVER) ---
        logger.info(f"User {user_id} disconnected and went offline.")


# --- NOWY HANDLER EVENTU (CHAT GRUPOWY - Bezpieczeństwo - Etap 5/5) ---
@socketio.on('leave_specific_room')
def handle_leave_specific_room(data):
    """Obsługuje żądanie klienta o opuszczenie konkretnego pokoju Socket.IO."""
    room_id_to_leave = data.get('room_id')
    user_sid = request.sid

    if room_id_to_leave is None:
        logger.warning(
            f"Leave specific room: Brak room_id od SID: {user_sid}.")
        return

    # Pobierz ID użytkownika powiązanego z tym SID, dla logowania
    user_id_leaving = connected_sids_to_user_id.get(user_sid)
    username_leaving = "Nieznany (SID)"
    if user_id_leaving:
        user_obj = User.query.get(user_id_leaving)
        if user_obj:
            username_leaving = user_obj.username

    logger.info(
        f"Użytkownik '{username_leaving}' (ID: {user_id_leaving}, SID: {user_sid}) opuszcza pokój Socket.IO: {room_id_to_leave}"
    )
    leave_room(room_id_to_leave, sid=user_sid)
    # Opcjonalnie: emituj do pokoju, że użytkownik go opuścił,
    # ale serwer i tak nie będzie już do niego wysyłał wiadomości z tego pokoju.
    # socketio.emit('member_left_room', {'room_id': room_id_to_leave, 'user_id': user_id_leaving, 'username': username_leaving}, room=room_id_to_leave)


# --- KONIEC NOWEGO HANDLERA ---


@socketio.on('authenticate')
def handle_authentication(data):
    user_id = data.get('user_id')
    user = User.query.get(user_id)
    if user:
        connected_sids_to_user_id[request.sid] = user.id
        join_room(
            user.id)  # Użytkownik dołącza do swojego prywatnego roomu (ID)

        # --- NOWE ZMIANY (CHAT SERVER - Online Status) ---
        # 1. Zbierz aktualną listę ID wszystkich użytkowników online
        # (pamiętaj, że self.connected_sids_to_user_id to słownik SID:user_id)
        online_users_ids_at_connect = list(connected_sids_to_user_id.values())

        # 2. Poinformuj WSZYSTKICH INNYCH klientów, że ten użytkownik właśnie wszedł online.
        # Używamy skip_sid=request.sid, aby nie wysyłać do samego siebie.
        socketio.emit('user_online', {'user_id': user.id},
                      skip_sid=request.sid)
        logger.info(
            f"Emitting 'user_online' for User ID: {user.id} to others.")

        # 3. Poinformuj nowo połączonego klienta o pełnej liście użytkowników online.
        # Używamy room=request.sid, aby wysłać tylko do tego konkretnego klienta.
        emit('online_users_list',
             {'online_users': online_users_ids_at_connect},
             room=request.sid)
        logger.info(
            f"Emitting 'online_users_list' to new client ({request.sid}) with {len(online_users_ids_at_connect)} users."
        )
        # --- KONIEC NOWYCH ZMIAN ---

        # --- NOWE ZMIANY (CHAT GRUPOWY - Etap 4/5) ---
        # Dołącz do pokoi, których jest członkiem
        memberships = RoomMembership.query.filter_by(user_id=user.id).all()
        for membership in memberships:
            join_room(membership.room_id
                      )  # Dołącz do roomu grupowego (nazwa to ID pokoju)
            logger.info(
                f"User {user.username} (ID: {user.id}) joined group room {membership.room_id}."
            )
        # --- KONIEC NOWYCH ZMIAN (CHAT GRUPOWY - Etap 4/5) ---

        session_data = {
            "user_id": user.id,
            "username": user.username,
            "authenticated": True
        }

        emit('authenticated', session_data)
        logger.info(
            f"User {user.username} (ID: {user.id}) authenticated and joined room {user.id}"
        )

    else:
        emit('authentication_failed', {"message": "Invalid user_id"})
        logger.warning(f"Authentication failed for user_id: {user_id}")


@socketio.on('typing_start')
def handle_typing_start(data):
    """
    Obsługuje początek pisania wiadomości przez użytkownika.
    Wymaga: {'sender_id': <ID_nadawcy>, 'receiver_id': <ID_odbiorcy>}
    Rozgłasza do odbiorcy.
    """
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')

    sender = User.query.get(sender_id)
    if not sender:
        logger.warning(f"Typing start failed: Invalid sender_id ({sender_id})")
        return

    # Emituj do odbiorcy (do jego roomu)
    socketio.emit('typing_update', {
        'sender_id': sender_id,
        'is_typing': True
    },
                  room=receiver_id)
    logger.debug(
        f"User {sender.username} (ID: {sender_id}) started typing to {receiver_id}."
    )


# --- NOWE ZMIANY (CHAT SERVER - Edycja wiadomości) ---
@socketio.on('edit_message')
def handle_edit_message(data):
    """
    Obsługuje żądanie edycji wiadomości.
    Wymaga: {'message_id': <ID_wiadomości>, 'new_content': 'Nowa treść', 'editor_user_id': <ID_użytkownika_edytującego>}
    """
    message_id = data.get('message_id')
    new_content = data.get('new_content')
    editor_user_id = data.get('editor_user_id')

    if message_id is None or new_content is None or editor_user_id is None:
        logger.warning(
            "Edit message: Brak message_id, new_content lub editor_user_id.")
        emit('message_edit_failed', {
            'message_id': message_id,
            'error': 'Niekompletne żądanie.'
        },
             room=request.sid)
        return

    message_to_edit = Message.query.get(message_id)

    if not message_to_edit:
        logger.warning(
            f"Edit message: Wiadomość o ID {message_id} nie znaleziona.")
        emit('message_edit_failed', {
            'message_id': message_id,
            'error': 'Wiadomość nie istnieje.'
        },
             room=request.sid)
        return

    # Autoryzacja: Tylko nadawca może edytować swoją wiadomość
    if message_to_edit.sender_id != editor_user_id:
        logger.warning(
            f"Edit message: Użytkownik {editor_user_id} próbował edytować wiadomość ID {message_id}, której nie jest nadawcą (nadawca: {message_to_edit.sender_id})."
        )
        emit('message_edit_failed', {
            'message_id': message_id,
            'error': 'Nie masz uprawnień do edycji tej wiadomości.'
        },
             room=request.sid)
        return

    # Wiadomość nie może być pusta
    if not new_content.strip():
        logger.warning(
            f"Edit message: Pusta treść edycji dla wiadomości ID {message_id}."
        )
        emit('message_edit_failed', {
            'message_id': message_id,
            'error': 'Treść wiadomości nie może być pusta.'
        },
             room=request.sid)
        return

    if len(new_content) > 5000:  # Limit długości treści
        logger.warning(
            f"Edit message: Treść zbyt długa dla wiadomości ID {message_id}.")
        emit('message_edit_failed', {
            'message_id': message_id,
            'error': 'Treść wiadomości jest zbyt długa.'
        },
             room=request.sid)
        return

    # Jeśli wiadomość miała załącznik i nowa treść jest pusta, zachowaj informację o załączniku.
    # W tej implementacji, jeśli ktoś edytuje wiadomość z załącznikiem, to może zmienić tylko tekst.
    # Jeśli tekst był jedyną treścią i zostanie usunięty, a nie ma załącznika, wiadomość stanie się pusta.
    # Zabezpieczenie: jeśli to była wiadomość TYLKO z załącznikiem i nowa treść jest pusta,
    # a my nie obsługujemy "usunięcia" załącznika przez edycję.
    # Przyjmujemy, że edycja dotyczy tylko pola 'content'.
    if message_to_edit.attachment_server_filename and not new_content.strip():
        # Użytkownik może usunąć tekst, ale załącznik zostanie.
        # Możemy tu wymusić jakąś domyślną treść, np. "[Załącznik]"
        # Na razie pozwalamy na pusty tekst, jeśli jest załącznik.
        pass  # Nie zmieniamy treści, jeśli jest załącznik, a nowa treść jest pusta
    elif not new_content.strip(
    ) and not message_to_edit.attachment_server_filename:
        # Jeśli wiadomość nie ma załącznika i nowa treść jest pusta, to jest to błąd
        logger.warning(
            f"Edit message: Wiadomość bez załącznika nie może mieć pustej treści po edycji (ID: {message_id})."
        )
        emit('message_edit_failed', {
            'message_id': message_id,
            'error': 'Wiadomość tekstowa nie może być pusta.'
        },
             room=request.sid)
        return

    try:
        message_to_edit.content = new_content
        # --- NOWE ZMIANY ---
        message_to_edit.edited_at = datetime.datetime.now(
        )  # Ustaw czas edycji
        # --- KONIEC NOWYCH ZMIAN ---
        db.session.commit()
        logger.info(
            f"Edit message: Wiadomość o ID {message_id} została edytowana przez użytkownika {editor_user_id}."
        )

        # Przygotuj zaktualizowane dane wiadomości (zawiera nową treść)
        updated_message_data = message_to_edit.to_dict()

        # Poinformuj nadawcę (który edytował)
        emit('message_edited_successfully',
             updated_message_data,
             room=request.sid)

        # Poinformuj drugiego uczestnika rozmowy
        other_participant_id = None
        if message_to_edit.receiver_id == editor_user_id:  # Jeśli edytował odbiorca (rzadko)
            other_participant_id = message_to_edit.sender_id
        elif message_to_edit.sender_id == editor_user_id:  # Jeśli edytował nadawca
            other_participant_id = message_to_edit.receiver_id

        if other_participant_id:
            logger.debug(
                f"Edit message: Informowanie drugiego uczestnika (ID: {other_participant_id}) o edycji wiadomości {message_id}."
            )
            socketio.emit('message_edited_successfully',
                          updated_message_data,
                          room=other_participant_id)

    except Exception as e_db_edit:
        db.session.rollback()
        logger.error(
            f"Edit message: Błąd bazy danych podczas edycji wiadomości ID {message_id}: {e_db_edit}"
        )
        emit('message_edit_failed', {
            'message_id': message_id,
            'error': 'Błąd serwera podczas edycji wiadomości.'
        },
             room=request.sid)


# --- KONIEC NOWYCH ZMIAN (CHAT SERVER - Edycja wiadomości) ---


# --- NOWE ZMIANY: Obsługa usuwania wiadomości ---
# --- NOWE ZMIANY: Obsługa usuwania wiadomości ---
@socketio.on('delete_message')
def handle_delete_message(data):
    """
    Obsługuje żądanie usunięcia wiadomości.
    Wymaga: {'message_id': <ID_wiadomości>, 'deleter_user_id': <ID_użytkownika_żądającego_usunięcia>}
    """
    message_id = data.get('message_id')
    deleter_user_id = data.get(
        'deleter_user_id')  # ID użytkownika, który kliknął "Usuń"

    if message_id is None or deleter_user_id is None:
        logger.warning("Delete message: Brak message_id lub deleter_user_id.")
        emit('message_delete_failed', {
            'message_id': message_id,
            'error': 'Niekompletne żądanie.'
        },
             room=request.sid)
        return

    message_to_delete = Message.query.get(message_id)

    if not message_to_delete:
        logger.warning(
            f"Delete message: Wiadomość o ID {message_id} nie znaleziona.")
        emit('message_delete_failed', {
            'message_id': message_id,
            'error': 'Wiadomość nie istnieje.'
        },
             room=request.sid)
        return

    if message_to_delete.sender_id != deleter_user_id:
        logger.warning(
            f"Delete message: Użytkownik {deleter_user_id} próbował usunąć wiadomość ID {message_id}, której nie jest nadawcą (nadawca: {message_to_delete.sender_id})."
        )
        emit('message_delete_failed', {
            'message_id': message_id,
            'error': 'Nie masz uprawnień do usunięcia tej wiadomości.'
        },
             room=request.sid)
        return

    if message_to_delete.attachment_server_filename:
        try:
            file_path_on_server = os.path.join(
                app.config['UPLOAD_FOLDER'],
                message_to_delete.attachment_server_filename)
            if os.path.exists(file_path_on_server):
                os.remove(file_path_on_server)
                logger.info(
                    f"Delete message: Usunięto plik załącznika: {file_path_on_server}"
                )
            else:
                logger.warning(
                    f"Delete message: Plik załącznika {message_to_delete.attachment_server_filename} nie został znaleziony na serwerze do usunięcia."
                )
        except Exception as e_file_delete:
            logger.error(
                f"Delete message: Błąd podczas usuwania pliku załącznika {message_to_delete.attachment_server_filename}: {e_file_delete}"