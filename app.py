"""
Барбершоп «ЦЕХ» — серверное веб-приложение.

Архитектура:
    Браузер  →  Flask (этот файл)  →  база данных (PostgreSQL / SQLite)

Что внутри:
  • Публичная страница с формой записи (заявки пишутся в базу).
  • Закрытая админка с логином: список заявок + отметка «выполнено».

Реализованные меры безопасности (важно для портфолио):
  • SQL-инъекции   — исключены за счёт ORM (параметризованные запросы).
  • XSS            — шаблоны Jinja2 экранируют вывод автоматически.
  • CSRF           — токены на всех формах (Flask-WTF).
  • Пароли         — хранятся в виде хешей, не в открытом виде.
  • Брутфорс логина — ограничение частоты запросов (Flask-Limiter).
  • Заголовки      — CSP, X-Frame-Options и др. навешиваются на каждый ответ.
  • Cookie сессии  — HttpOnly + SameSite, а на проде ещё и Secure (только https).
"""
import os

from flask import (Flask, render_template, redirect, url_for,
                   flash, request, abort)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

from models import db, Admin, Booking
from forms import BookingForm, LoginForm

load_dotenv()

app = Flask(__name__)

# --- Конфигурация ------------------------------------------------------------
# Секретный ключ подписывает cookie сессии. На проде он ОБЯЗАН задаваться через
# переменную окружения и быть длинным случайным значением.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key-CHANGE-ME")

# База: если задан DATABASE_URL (прод, PostgreSQL) — берём его,
# иначе локально используем простой файловый SQLite (ничего настраивать не надо).
db_url = os.environ.get("DATABASE_URL", "sqlite:///barbershop.db")
# Некоторые хостинги выдают URL вида postgres://… , а SQLAlchemy ждёт postgresql://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Безопасные cookie сессии.
is_production = os.environ.get("FLASK_ENV") == "production"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # cookie недоступна из JavaScript → защита от кражи через XSS
    SESSION_COOKIE_SAMESITE="Lax",  # cookie не уходит на сторонние сайты → защита от CSRF
    SESSION_COOKIE_SECURE=is_production,  # на проде — только по https
)

# --- Расширения --------------------------------------------------------------
db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Сначала войдите в систему."

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))


# --- Заголовки безопасности на каждый ответ ----------------------------------
@app.after_request
def set_security_headers(response):
    # Content-Security-Policy: разрешаем грузить ресурсы только со своего домена
    # и шрифты Google. Это серьёзно ограничивает возможности XSS.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"      # запрет угадывания типа файла
    response.headers["X-Frame-Options"] = "DENY"                # запрет встраивания в iframe (защита от кликджекинга)
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# --- Публичные маршруты ------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    form = BookingForm()
    return render_template("index.html", form=form)


@app.route("/book", methods=["POST"])
@limiter.limit("10 per minute")  # защита от спама заявками
def book():
    form = BookingForm()
    if form.validate_on_submit():
        booking = Booking(
            name=form.name.data.strip(),
            phone=form.phone.data.strip(),
            service=form.service.data,
        )
        db.session.add(booking)
        db.session.commit()
        flash("Заявка принята! Мы перезвоним в ближайшее время.", "success")
        return redirect(url_for("index") + "#booking")
    # Если валидация не прошла — показываем страницу снова с ошибками.
    flash("Проверьте правильность заполнения формы.", "error")
    return render_template("index.html", form=form), 400


# --- Админка -----------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # тормозим перебор паролей
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin"))
    form = LoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin and admin.check_password(form.password.data):
            login_user(admin)
            return redirect(url_for("admin"))
        # Намеренно не уточняем, что именно неверно — логин или пароль.
        flash("Неверный логин или пароль.", "error")
    return render_template("login.html", form=form)


@app.route("/admin")
@login_required
def admin():
    bookings = Booking.query.order_by(Booking.created_at.desc()).all()
    new_count = sum(1 for b in bookings if b.status == "new")
    return render_template("admin.html", bookings=bookings, new_count=new_count)


@app.route("/admin/booking/<int:booking_id>/done", methods=["POST"])
@login_required
def mark_done(booking_id):
    booking = db.session.get(Booking, booking_id)
    if booking is None:
        abort(404)
    booking.status = "done"
    db.session.commit()
    return redirect(url_for("admin"))


@app.route("/admin/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# --- Инициализация базы и создание администратора ----------------------------
def init_database():
    """Создаёт таблицы и (если задано в окружении) первого администратора."""
    with app.app_context():
        db.create_all()
        username = os.environ.get("ADMIN_USERNAME")
        password = os.environ.get("ADMIN_PASSWORD")
        if username and password and not Admin.query.filter_by(username=username).first():
            admin = Admin(username=username)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            print(f"[init] Создан администратор: {username}")


# Создаём таблицы при импорте (нужно для запуска под gunicorn на хостинге).
init_database()


@app.cli.command("create-admin")
def create_admin_command():
    """Создать администратора вручную: flask create-admin"""
    import getpass
    username = input("Логин администратора: ").strip()
    password = getpass.getpass("Пароль: ")
    with app.app_context():
        if Admin.query.filter_by(username=username).first():
            print("Такой администратор уже есть.")
            return
        admin = Admin(username=username)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Готово. Администратор {username} создан.")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
