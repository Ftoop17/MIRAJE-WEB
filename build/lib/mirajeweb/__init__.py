"""
MirajeWeb Framework 1.0
Самый защищенный веб-фреймворк для создания безопасных веб-приложений
Версия: 1.0.0 (Универсальная - работает на любых устройствах)
Автор: TheTemirBolatov (ВК: thetemirbolatov, GitHub: ftoop17)
Лицензия: MIRAJE | IND Proprietary License
"""

import os
import sys
import hashlib
import hmac
import base64
import json
import time
import threading
import socket
import ssl
import asyncio
import inspect
import zlib
import uuid
import logging
import sqlite3
import pickle
import functools
import weakref
import secrets
import binascii
from collections import defaultdict, OrderedDict
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, unquote
from datetime import datetime, timedelta
from email.utils import formatdate

# =============================================
# АЛЬТЕРНАТИВНЫЕ РЕАЛИЗАЦИИ КРИПТОГРАФИИ
# (для совместимости со всеми устройствами)
# =============================================

class SimpleCrypto:
    """Упрощенная реализация криптографии для максимальной совместимости"""
    
    @staticmethod
    def generate_key(password: str, salt: bytes = None, iterations: int = 100000) -> Tuple[bytes, bytes]:
        """Генерация ключа из пароля с использованием PBKDF2-HMAC-SHA256"""
        salt = salt or os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
        return key, salt
    
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Простое шифрование с использованием XOR и хеширования"""
        hash_key = hashlib.sha256(key).digest()
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ hash_key[i % len(hash_key)])
        return bytes(encrypted)
    
    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """Дешифрование (симметрично шифрованию)"""
        return SimpleCrypto.encrypt(data, key)
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Генерация безопасного токена"""
        return secrets.token_urlsafe(length)

# =============================================
# КОНСТАНТЫ И НАСТРОЙКИ БЕЗОПАСНОСТИ
# =============================================

DEFAULT_SECRET_KEY = SimpleCrypto.generate_token(32)
MAX_REQUEST_SIZE = 1024 * 1024 * 5  # 5MB
RATE_LIMIT_REQUESTS = 300  # Макс запросов в минуту
CSRF_TOKEN_LIFETIME = 3600  # 1 час
SESSION_LIFETIME = 86400 * 7  # 7 дней
AUTH_TOKEN_LIFETIME = 86400 * 30  # 30 дней
CACHE_DEFAULT_TIMEOUT = 300  # 5 минут
WEBSOCKET_MAX_SIZE = 1024 * 1024 * 2  # 2MB
MAX_DB_CONNECTIONS = 10
FRAMEWORK_SIGNATURE = "MIRAJE|IND|FRAMEWORK|v1.0|THEMIRBOLATOV"

# =============================================
# ИСКЛЮЧЕНИЯ
# =============================================

class MirajeSecurityException(Exception):
    """Базовое исключение для ошибок безопасности"""
    pass

class CSRFValidationError(MirajeSecurityException):
    """Ошибка валидации CSRF токена"""
    pass

class RateLimitExceeded(MirajeSecurityException):
    """Превышен лимит запросов"""
    pass

class RequestSizeExceeded(MirajeSecurityException):
    """Превышен максимальный размер запроса"""
    pass

class InvalidSession(MirajeSecurityException):
    """Невалидная сессия"""
    pass

class AuthenticationError(MirajeSecurityException):
    """Ошибка аутентификации"""
    pass

class AuthorizationError(MirajeSecurityException):
    """Ошибка авторизации"""
    pass

class DatabaseError(MirajeSecurityException):
    """Ошибка базы данных"""
    pass

class WebSocketError(MirajeSecurityException):
    """Ошибка WebSocket"""
    pass

# =============================================
# УТИЛИТЫ БЕЗОПАСНОСТИ (УНИВЕРСАЛЬНЫЕ)
# =============================================

class SecurityUtils:
    @staticmethod
    def generate_csrf_token(secret_key: str) -> str:
        """Генерация CSRF токена с усиленной защитой"""
        timestamp = str(int(time.time()))
        nonce = SimpleCrypto.generate_token(16)
        data = f"{timestamp}:{nonce}"
        signature = hmac.new(
            secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{signature}:{data}"

    @staticmethod
    def validate_csrf_token(token: str, secret_key: str, lifetime: int = CSRF_TOKEN_LIFETIME) -> bool:
        """Валидация CSRF токена с проверкой времени жизни и подписи"""
        try:
            signature_part, data_part = token.split(':', 1)
            timestamp, nonce = data_part.split(':', 1)
            
            # Проверка времени жизни
            if int(time.time()) - int(timestamp) > lifetime:
                return False
            
            # Проверка подписи
            expected_signature = hmac.new(
                secret_key.encode(),
                data_part.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature_part, expected_signature)
        except:
            return False

    @staticmethod
    def encrypt_data(data: str, key: str) -> str:
        """Шифрование данных с использованием упрощенного алгоритма"""
        key_bytes = hashlib.sha256(key.encode()).digest()
        encrypted = SimpleCrypto.encrypt(data.encode(), key_bytes)
        return base64.urlsafe_b64encode(encrypted).decode()

    @staticmethod
    def decrypt_data(encrypted_data: str, key: str) -> str:
        """Дешифрование данных"""
        key_bytes = hashlib.sha256(key.encode()).digest()
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = SimpleCrypto.decrypt(encrypted_bytes, key_bytes)
        return decrypted.decode()

    @staticmethod
    def generate_secure_key() -> str:
        """Генерация безопасного ключа"""
        return SimpleCrypto.generate_token(32)

    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, bytes]:
        """Хеширование пароля с солью"""
        if salt is None:
            salt = os.urandom(16)
        key, salt = SimpleCrypto.generate_key(password, salt)
        return base64.urlsafe_b64encode(key).decode(), salt

    @staticmethod
    def verify_password(password: str, hashed_password: str, salt: bytes) -> bool:
        """Проверка пароля с постоянным временем сравнения"""
        new_hash, _ = SecurityUtils.hash_password(password, salt)
        return hmac.compare_digest(new_hash, hashed_password)

    @staticmethod
    def generate_jwt_token(payload: dict, secret_key: str, expires_in: int = AUTH_TOKEN_LIFETIME) -> str:
        """Генерация JWT токена (упрощенная реализация)"""
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }
        payload['exp'] = int(time.time()) + expires_in
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = hmac.new(
            secret_key.encode(),
            f"{encoded_header}.{encoded_payload}".encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{encoded_header}.{encoded_payload}.{signature}"

    @staticmethod
    def verify_jwt_token(token: str, secret_key: str) -> dict:
        """Проверка JWT токена"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise AuthenticationError("Неверный формат токена")
            
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
            
            if header.get("alg") != "HS256":
                raise AuthenticationError("Неверный алгоритм")
            
            expected_signature = hmac.new(
                secret_key.encode(),
                f"{parts[0]}.{parts[1]}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(parts[2], expected_signature):
                raise AuthenticationError("Недействительная подпись")
            
            if payload.get('exp', 0) < time.time():
                raise AuthenticationError("Токен истек")
            
            return payload
        except Exception as e:
            raise AuthenticationError(f"Ошибка проверки токена: {str(e)}")

    @staticmethod
    def sanitize_sql(input_str: str) -> str:
        """Санитайзинг строк для SQL запросов"""
        return input_str.replace("'", "''").replace(";", "").replace("--", "")

# =============================================
# КЛАСС ЗАЩИТЫ ОТ АТАК (УНИВЕРСАЛЬНЫЙ)
# =============================================

class AttackProtection:
    def __init__(self):
        self.request_counts = defaultdict(int)
        self.last_reset = time.time()
        self.lock = threading.Lock()
        self.ip_blacklist = set()
        self.ip_whitelist = set()

    def reset_counts(self):
        """Сброс счетчиков запросов"""
        current_time = time.time()
        if current_time - self.last_reset > 60:
            with self.lock:
                self.request_counts.clear()
                self.last_reset = current_time

    def check_rate_limit(self, ip: str) -> None:
        """Проверка лимита запросов"""
        self.reset_counts()
        
        if ip in self.ip_whitelist:
            return
            
        if ip in self.ip_blacklist:
            raise RateLimitExceeded("Ваш IP заблокирован")
            
        with self.lock:
            self.request_counts[ip] += 1
            if self.request_counts[ip] > RATE_LIMIT_REQUESTS:
                if self.request_counts[ip] > RATE_LIMIT_REQUESTS * 5:
                    self.ip_blacklist.add(ip)
                raise RateLimitExceeded("Превышен лимит запросов")

    @staticmethod
    def sanitize_input(input_data: Any) -> Any:
        """Санитайзинг входных данных с защитой от XSS и инъекций"""
        if input_data is None:
            return None
            
        if isinstance(input_data, str):
            # Защита от XSS
            sanitized = input_data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            sanitized = sanitized.replace('"', '&quot;').replace("'", '&#x27;')
            # Защита от SQL инъекций
            sanitized = SecurityUtils.sanitize_sql(sanitized)
            return sanitized
        elif isinstance(input_data, dict):
            return {k: AttackProtection.sanitize_input(v) for k, v in input_data.items()}
        elif isinstance(input_data, list):
            return [AttackProtection.sanitize_input(i) for i in input_data]
        elif isinstance(input_data, (int, float, bool)):
            return input_data
        else:
            return str(input_data)

    def check_sqli_payloads(self, input_data: Any) -> bool:
        """Проверка на наличие SQL инъекций в данных"""
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 
            'union', 'truncate', 'alter', 'create', 'exec'
        ]
        
        if isinstance(input_data, str):
            lower_input = input_data.lower()
            return any(keyword in lower_input for keyword in sql_keywords)
        elif isinstance(input_data, dict):
            return any(self.check_sqli_payloads(v) for v in input_data.values())
        elif isinstance(input_data, list):
            return any(self.check_sqli_payloads(i) for i in input_data)
        return False

# =============================================
# КЛАСС СЕССИИ И АУТЕНТИФИКАЦИИ (УНИВЕРСАЛЬНЫЙ)
# =============================================

class SessionManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.sessions = {}
        self.lock = threading.Lock()

    def create_session(self, user_id: str, data: Optional[dict] = None, expires: int = SESSION_LIFETIME) -> str:
        """Создание новой сессии"""
        session_id = SimpleCrypto.generate_token(32)
        session_data = {
            'user_id': user_id,
            'data': data or {},
            'created_at': time.time(),
            'expires_at': time.time() + expires,
            'last_activity': time.time()
        }
        
        encrypted_data = SecurityUtils.encrypt_data(json.dumps(session_data), self.secret_key)
        
        with self.lock:
            self.sessions[session_id] = encrypted_data
        
        return session_id

    def get_session(self, session_id: str) -> dict:
        """Получение данных сессии"""
        encrypted_data = None
        
        with self.lock:
            encrypted_data = self.sessions.get(session_id)
        
        if not encrypted_data:
            raise InvalidSession("Сессия не найдена")
        
        try:
            session_data = json.loads(SecurityUtils.decrypt_data(encrypted_data, self.secret_key))
            
            if time.time() > session_data['expires_at']:
                self.delete_session(session_id)
                raise InvalidSession("Сессия истекла")
                
            # Обновление времени последней активности
            session_data['last_activity'] = time.time()
            self.update_session(session_id, session_data)
            
            return session_data
        except:
            raise InvalidSession("Недействительная сессия")

    def update_session(self, session_id: str, session_data: dict) -> None:
        """Обновление данных сессии"""
        encrypted_data = SecurityUtils.encrypt_data(json.dumps(session_data), self.secret_key)
        
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id] = encrypted_data

    def delete_session(self, session_id: str) -> None:
        """Удаление сессии"""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]

class AuthManager:
    def __init__(self, secret_key: str, orm):
        self.secret_key = secret_key
        self.orm = orm
        self.password_reset_tokens = {}
        self.lock = threading.Lock()
        self._create_tables()

    def _create_tables(self):
        """Создание таблиц для аутентификации"""
        self.orm.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                is_verified INTEGER DEFAULT 0,
                created_at REAL NOT NULL,
                last_login REAL,
                permissions TEXT DEFAULT '{}'
            )
        """)
        
        self.orm.execute("""
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                device_info TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

    def register_user(self, username: str, password: str, email: Optional[str] = None) -> str:
        """Регистрация нового пользователя"""
        if self.get_user_by_username(username):
            raise AuthenticationError("Пользователь с таким именем уже существует")
            
        user_id = str(uuid.uuid4())
        password_hash, salt = SecurityUtils.hash_password(password)
        created_at = time.time()
        
        self.orm.execute(
            """
            INSERT INTO users 
            (id, username, email, password_hash, salt, created_at) 
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, email, password_hash, base64.b64encode(salt).decode(), created_at)
        )
        
        return user_id

    def authenticate_user(self, username: str, password: str) -> Optional[dict]:
        """Аутентификация пользователя"""
        user = self.get_user_by_username(username)
        if not user:
            return None
            
        salt = base64.b64decode(user['salt'])
        if not SecurityUtils.verify_password(password, user['password_hash'], salt):
            return None
            
        # Обновление времени последнего входа
        self.orm.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (time.time(), user['id'])
        )
        
        return user

    def generate_auth_token(self, user_id: str, device_info: Optional[str] = None, 
                          expires_in: int = AUTH_TOKEN_LIFETIME) -> str:
        """Генерация токена аутентификации"""
        token = SecurityUtils.generate_jwt_token(
            {"user_id": user_id, "type": "auth"},
            self.secret_key,
            expires_in
        )
        
        created_at = time.time()
        expires_at = created_at + expires_in
        
        self.orm.execute(
            """
            INSERT INTO auth_tokens 
            (token, user_id, created_at, expires_at, device_info) 
            VALUES (?, ?, ?, ?, ?)
            """,
            (token, user_id, created_at, expires_at, device_info)
        )
        
        return token

    def verify_auth_token(self, token: str) -> Optional[dict]:
        """Проверка токена аутентификации"""
        try:
            payload = SecurityUtils.verify_jwt_token(token, self.secret_key)
            
            # Дополнительная проверка в базе данных
            result = self.orm.execute(
                """
                SELECT u.* FROM auth_tokens a
                JOIN users u ON a.user_id = u.id
                WHERE a.token = ? AND a.expires_at > ?
                """,
                (token, time.time()),
                fetch=True
            )
            
            if not result:
                return None
                
            user = {
                'id': result[0][0],
                'username': result[0][1],
                'email': result[0][2],
                'is_active': bool(result[0][5]),
                'is_verified': bool(result[0][6]),
                'permissions': json.loads(result[0][9] or '{}')
            }
            
            return user
        except:
            return None

    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Получение пользователя по имени"""
        result = self.orm.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            fetch=True
        )
        
        if not result:
            return None
            
        return {
            'id': result[0][0],
            'username': result[0][1],
            'email': result[0][2],
            'password_hash': result[0][3],
            'salt': result[0][4],
            'is_active': bool(result[0][5]),
            'is_verified': bool(result[0][6]),
            'permissions': json.loads(result[0][9] or '{}')
        }

    def change_password(self, user_id: str, new_password: str) -> None:
        """Изменение пароля пользователя"""
        password_hash, salt = SecurityUtils.hash_password(new_password)
        self.orm.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
            (password_hash, base64.b64encode(salt).decode(), user_id)
        )
        
        # Удаление всех токенов пользователя
        self.orm.execute(
            "DELETE FROM auth_tokens WHERE user_id = ?",
            (user_id,)
        )

    def update_user_permissions(self, user_id: str, permissions: dict) -> None:
        """Обновление прав пользователя"""
        self.orm.execute(
            "UPDATE users SET permissions = ? WHERE id = ?",
            (json.dumps(permissions), user_id)
        )

# =============================================
# КЛАСС КЕШИРОВАНИЯ (УНИВЕРСАЛЬНЫЙ)
# =============================================

class CacheManager:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()

    def get(self, key: str) -> Any:
        """Получение данных из кеша"""
        with self.lock:
            item = self.cache.get(key)
            if item and item['expires_at'] > time.time():
                return item['value']
            if item:
                del self.cache[key]
            return None

    def set(self, key: str, value: Any, timeout: int = CACHE_DEFAULT_TIMEOUT) -> None:
        """Установка данных в кеш"""
        expires_at = time.time() + timeout
        with self.lock:
            self.cache[key] = {
                'value': value,
                'expires_at': expires_at
            }

    def delete(self, key: str) -> None:
        """Удаление данных из кеша"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self) -> None:
        """Очистка всего кеша"""
        with self.lock:
            self.cache.clear()

# =============================================
# ОСНОВНОЙ КЛАСС ПРИЛОЖЕНИЯ (УНИВЕРСАЛЬНЫЙ)
# =============================================

class MirajeWeb:
    def __init__(self, name: str, secret_key: Optional[str] = None):
        self.name = name
        self.secret_key = secret_key or DEFAULT_SECRET_KEY
        self.routes = {}
        self.middlewares = []
        self.session_manager = SessionManager(self.secret_key)
        self.protection = AttackProtection()
        self.error_handlers = {}
        self.logger = self._setup_logger()
        self.cache = CacheManager()
        self.orm = self._setup_database()
        self.auth_manager = AuthManager(self.secret_key, self.orm)
        
        # Стандартные обработчики ошибок
        self.error_handler(400, self._bad_request_handler)
        self.error_handler(404, self._not_found_handler)
        self.error_handler(405, self._method_not_allowed_handler)
        self.error_handler(500, self._internal_error_handler)
        self.error_handler(RateLimitExceeded, self._rate_limit_handler)
        self.error_handler(CSRFValidationError, self._csrf_error_handler)
        self.error_handler(InvalidSession, self._invalid_session_handler)
        
        # Автоматическая защита для всех маршрутов
        self.before_request(self._security_checks)

    def _setup_logger(self):
        """Настройка системы логирования"""
        logger = logging.getLogger(self.name)
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger

    def _setup_database(self):
        """Настройка базы данных"""
        return MirajeORM(f"sqlite:{self.name}.db")

    def route(self, path: str, methods: Optional[List[str]] = None, 
             csrf_protected: bool = True, require_auth: bool = False,
             permissions: Optional[List[str]] = None) -> Callable:
        """Декоратор для регистрации маршрутов"""
        methods = methods or ['GET']
        permissions = permissions or []
        
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(request: 'Request', *args, **kwargs):
                try:
                    # Проверка CSRF для POST, PUT, DELETE, PATCH
                    if csrf_protected and request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
                        if not csrf_token or not SecurityUtils.validate_csrf_token(csrf_token, self.secret_key):
                            raise CSRFValidationError("Недействительный CSRF токен")
                    
                    # Проверка аутентификации
                    if require_auth:
                        auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
                        if not auth_token:
                            raise AuthenticationError("Требуется аутентификация")
                        
                        user = self.auth_manager.verify_auth_token(auth_token)
                        if not user:
                            raise AuthenticationError("Недействительный токен аутентификации")
                        
                        request.user = user
                    
                    # Проверка прав
                    if permissions and hasattr(request, 'user'):
                        user_permissions = request.user.get('permissions', {})
                        if not all(user_permissions.get(p, False) for p in permissions):
                            raise AuthorizationError("Недостаточно прав")
                    
                    return func(request, *args, **kwargs)
                except Exception as e:
                    # Обработка известных исключений
                    for exc_type, handler in self.error_handlers.items():
                        if isinstance(e, exc_type):
                            return handler(request, e)
                    # Если обработчик не найден, вернуть 500
                    return self.error_handlers.get(500, self._internal_error_handler)(request, e)
            
            # Регистрация маршрута
            for method in methods:
                route_key = f"{method.upper()}:{path}"
                self.routes[route_key] = wrapper
            
            return wrapper
        return decorator

    def before_request(self, func: Callable) -> Callable:
        """Добавление middleware перед запросом"""
        self.middlewares.append(func)
        return func

    def error_handler(self, code_or_exception: Union[int, Type[Exception]], func: Callable) -> Callable:
        """Регистрация обработчика ошибок"""
        self.error_handlers[code_or_exception] = func
        return func

    def _security_checks(self, request: 'Request') -> Optional['Response']:
        """Автоматические проверки безопасности"""
        # Проверка лимита запросов
        self.protection.check_rate_limit(request.remote_addr)
        
        # Проверка размера запроса
        if request.content_length and request.content_length > MAX_REQUEST_SIZE:
            raise RequestSizeExceeded(f"Максимальный размер запроса: {MAX_REQUEST_SIZE} байт")
        
        # Проверка на SQL инъекции
        if request.form and self.protection.check_sqli_payloads(request.form):
            raise MirajeSecurityException("Обнаружена попытка SQL инъекции")
        if request.args and self.protection.check_sqli_payloads(request.args):
            raise MirajeSecurityException("Обнаружена попытка SQL инъекции")
        if request.json and self.protection.check_sqli_payloads(request.json):
            raise MirajeSecurityException("Обнаружена попытка SQL инъекции")
        
        # Санитайзинг входных данных
        if request.form:
            request.form = AttackProtection.sanitize_input(request.form)
        if request.args:
            request.args = AttackProtection.sanitize_input(request.args)
        if request.json:
            request.json = AttackProtection.sanitize_input(request.json)

    # Стандартные обработчики ошибок
    def _bad_request_handler(self, request: 'Request', error: Exception) -> 'Response':
        return Response("Неверный запрос", status=400)

    def _not_found_handler(self, request: 'Request', error: Exception) -> 'Response':
        return Response("Страница не найдена", status=404)

    def _method_not_allowed_handler(self, request: 'Request', error: Exception) -> 'Response':
        return Response("Метод не разрешен", status=405)

    def _internal_error_handler(self, request: 'Request', error: Exception) -> 'Response':
        self.logger.error(f"Внутренняя ошибка сервера: {str(error)}", exc_info=error)
        return Response("Внутренняя ошибка сервера", status=500)

    def _rate_limit_handler(self, request: 'Request', error: Exception) -> 'Response':
        return Response("Превышен лимит запросов", status=429)

    def _csrf_error_handler(self, request: 'Request', error: Exception) -> 'Response':
        return Response("Недействительный CSRF токен", status=403)

    def _invalid_session_handler(self, request: 'Request', error: Exception) -> 'Response':
        return Response("Недействительная сессия", status=401)

    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False) -> None:
        """Запуск сервера"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(5)
        
        self.logger.info(f"Сервер запущен на {host}:{port}")
        
        try:
            while True:
                client_socket, addr = server_socket.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr, debug)
                ).start()
        except KeyboardInterrupt:
            self.logger.info("\nОстановка сервера...")
        finally:
            server_socket.close()

    def _handle_client(self, client_socket, addr, debug):
        """Обработка клиентского соединения"""
        try:
            request_data = client_socket.recv(MAX_REQUEST_SIZE)
            if not request_data:
                return
                
            request = Request(request_data, addr)
            response = self._process_request(request)
            
            client_socket.sendall(response.to_bytes())
        except Exception as e:
            if debug:
                error_response = self.error_handlers.get(500, self._internal_error_handler)(
                    Request(b'', addr), e)
                client_socket.sendall(error_response.to_bytes())
            else:
                client_socket.sendall(Response("Внутренняя ошибка сервера", status=500).to_bytes())
        finally:
            client_socket.close()

    def _process_request(self, request: 'Request') -> 'Response':
        """Обработка запроса"""
        try:
            # Выполнение middleware
            for middleware in self.middlewares:
                middleware_response = middleware(request)
                if middleware_response:
                    return middleware_response
            
            # Поиск обработчика маршрута
            route_key = f"{request.method}:{request.path}"
            handler = self.routes.get(route_key)
            
            if not handler:
                # Проверка на другие методы
                for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                    if method != request.method and f"{method}:{request.path}" in self.routes:
                        return self.error_handlers.get(405, self._method_not_allowed_handler)(request, None)
                return self.error_handlers.get(404, self._not_found_handler)(request, None)
            
            return handler(request)
        except Exception as e:
            # Обработка исключений
            for exc_type, handler in self.error_handlers.items():
                if isinstance(e, exc_type):
                    return handler(request, e)
            return self.error_handlers.get(500, self._internal_error_handler)(request, e)

# =============================================
# КЛАСС ЗАПРОСА
# =============================================

class Request:
    def __init__(self, raw_data: bytes, remote_addr: tuple):
        self.raw_data = raw_data
        self.remote_addr = remote_addr
        self.method = 'GET'
        self.path = '/'
        self.headers = {}
        self.form = {}
        self.args = {}
        self.json = None
        self.files = {}
        self.cookies = {}
        self.content_length = 0
        self.user = None
        self._parse_request()

    def _parse_request(self):
        """Парсинг сырых данных запроса"""
        try:
            parts = self.raw_data.split(b'\r\n\r\n', 1)
            header_part = parts[0].decode('utf-8', errors='replace')
            body = parts[1] if len(parts) > 1 else b''
            
            lines = header_part.split('\r\n')
            start_line = lines[0]
            self.method, path, _ = start_line.split(' ', 2)
            self.path = path.split('?')[0]
            
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    self.headers[key.strip()] = value.strip()
            
            if 'Cookie' in self.headers:
                for cookie in self.headers['Cookie'].split(';'):
                    if '=' in cookie:
                        name, value = cookie.split('=', 1)
                        self.cookies[name.strip()] = value.strip()
            
            if '?' in path:
                query = path.split('?')[1]
                for param in query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        self.args[key] = unquote(value)
            
            content_type = self.headers.get('Content-Type', '')
            self.content_length = int(self.headers.get('Content-Length', 0))
            
            if body and content_type.startswith('application/x-www-form-urlencoded'):
                for param in body.decode().split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        self.form[key] = unquote(value)
            elif body and content_type.startswith('application/json'):
                try:
                    self.json = json.loads(body.decode())
                except:
                    self.json = None
        except:
            pass

    def get_session(self):
        """Получение сессии из cookies"""
        session_id = self.cookies.get('session_id')
        if session_id:
            try:
                return self.session_manager.get_session(session_id)
            except InvalidSession:
                return None
        return None

# =============================================
# КЛАСС ОТВЕТА
# =============================================

class Response:
    def __init__(self, content: str = '', status: int = 200, 
                 content_type: str = 'text/html', headers: Optional[dict] = None, 
                 cookies: Optional[dict] = None):
        self.content = content
        self.status = status
        self.content_type = content_type
        self.headers = headers or {}
        self.cookies = cookies or {}
        
        self.headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        })

    def set_cookie(self, name: str, value: str, max_age: Optional[int] = None, 
                  path: str = '/', secure: bool = True, http_only: bool = True, 
                  same_site: str = 'Strict') -> None:
        """Установка cookie"""
        cookie = f"{name}={value}; Path={path}"
        if max_age:
            cookie += f"; Max-Age={max_age}"
        if secure:
            cookie += "; Secure"
        if http_only:
            cookie += "; HttpOnly"
        if same_site:
            cookie += f"; SameSite={same_site}"
        self.cookies[name] = cookie

    def to_bytes(self) -> bytes:
        """Преобразование ответа в байты"""
        status_text = {
            200: 'OK',
            201: 'Created',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            500: 'Internal Server Error',
            429: 'Too Many Requests'
        }.get(self.status, 'Unknown Status')
        
        response_lines = [
            f"HTTP/1.1 {self.status} {status_text}",
            f"Content-Type: {self.content_type}",
            f"Content-Length: {len(self.content)}"
        ]
        
        for name, value in self.headers.items():
            response_lines.append(f"{name}: {value}")
        
        for cookie in self.cookies.values():
            response_lines.append(f"Set-Cookie: {cookie}")
        
        response_lines.append('')
        response_lines.append(self.content)
        
        return '\r\n'.join(response_lines).encode()

# =============================================
# ПРОСТАЯ ORM СИСТЕМА
# =============================================

class MirajeORM:
    def __init__(self, db_url: str):
        self.db_url = db_url
        self.connections = []
        self.lock = threading.Lock()
        
        # Проверка типа базы данных
        if db_url.startswith('sqlite:'):
            self.db_type = 'sqlite'
        else:
            raise DatabaseError(f"Неподдерживаемый URL базы данных: {db_url}")

    def execute(self, query: str, params=None, fetch: bool = False):
        """Выполнение SQL запроса"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
                
            if fetch:
                result = cursor.fetchall()
                return result
            else:
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Ошибка выполнения запроса: {str(e)}")
        finally:
            if conn:
                self._release_connection(conn)

    def _get_connection(self):
        """Получение соединения из пула"""
        with self.lock:
            if self.connections:
                return self.connections.pop()
            
            if self.db_type == 'sqlite':
                db_path = self.db_url[7:]
                return sqlite3.connect(db_path)
            
            raise DatabaseError("Не удалось установить соединение")

    def _release_connection(self, conn):
        """Возвращение соединения в пул"""
        with self.lock:
            if len(self.connections) < MAX_DB_CONNECTIONS:
                self.connections.append(conn)
            else:
                conn.close()

    def close_all(self):
        """Закрытие всех соединений"""
        with self.lock:
            for conn in self.connections:
                conn.close()
            self.connections.clear()

# =============================================
# ЗАЩИТА КОДА
# =============================================

class CodeProtection:
    _SIGNATURE = "MIRAJE | IND PROPRIETARY CODE - DO NOT MODIFY"
    
    @classmethod
    def verify_integrity(cls):
        """Проверка целостности кода"""
        current_hash = cls._calculate_code_hash()
        expected_hash = cls._get_expected_hash()
        
        if current_hash != expected_hash:
            raise MirajeSecurityException("Нарушена целостность кода")
        
        if cls._SIGNATURE not in __doc__:
            raise MirajeSecurityException("Нарушено авторское право")

    @staticmethod
    def _calculate_code_hash():
        """Вычисление хеша кода"""
        import inspect
        
        frame = inspect.currentframe()
        module = inspect.getmodule(frame)
        source = inspect.getsource(module)
        
        lines = []
        for line in source.split('\n'):
            stripped = line.split('#')[0].strip()
            if stripped:
                lines.append(stripped)
        clean_code = '\n'.join(lines)
        
        h = hashlib.sha256()
        h.update(clean_code.encode())
        h.update(FRAMEWORK_SIGNATURE.encode())
        return h.hexdigest()
    
    @staticmethod
    def _get_expected_hash():
        """Получение ожидаемого хеша кода"""
        # В реальной реализации это должно получаться из защищенного источника
        return "a1b2c3d4e5f6..."  # Здесь должен быть реальный хеш

# =============================================
# ИНИЦИАЛИЗАЦИЯ И ПРОВЕРКИ
# =============================================

# Проверка целостности кода при импорте
try:
    CodeProtection.verify_integrity()
except MirajeSecurityException as e:
    print(f"Ошибка безопасности: {e}")
    sys.exit(1)

# Проверка версии Python
if sys.version_info < (3, 7):
    print("MirajeWeb требует Python 3.7 или выше")
    sys.exit(1)

# Автоматическая генерация secret_key если не установлена
if DEFAULT_SECRET_KEY == SimpleCrypto.generate_token(32):
    print("Внимание: используется временный SECRET_KEY. Установите свой SECRET_KEY в настройках приложения.")

# =============================================
# ЭКСПОРТ ОСНОВНЫХ КЛАССОВ
# =============================================

__all__ = [
    'MirajeWeb',
    'Request',
    'Response',
    'SecurityUtils',
    'SessionManager',
    'AuthManager',
    'CacheManager',
    'MirajeORM',
    
    # Исключения
    'MirajeSecurityException',
    'CSRFValidationError',
    'RateLimitExceeded',
    'RequestSizeExceeded',
    'InvalidSession',
    'AuthenticationError',
    'AuthorizationError',
    'DatabaseError',
    'WebSocketError'
]

# =============================================
# ИНФОРМАЦИЯ О ВЕРСИИ И АВТОРЕ
# =============================================

__version__ = "1.0.0"
__author__ = "TheTemirBolatov"
__license__ = "MIRAJE | IND Proprietary License"
__copyright__ = "Copyright (C) 2025 MIRAJE | IND. Все права защищены."
