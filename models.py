"""
Модели базы данных.

Мы используем SQLAlchemy (ORM). Это важно с точки зрения безопасности:
ORM сам формирует параметризованные SQL-запросы, поэтому классическая
SQL-инъекция через эти модели невозможна — данные пользователя никогда
не склеиваются со строкой запроса вручную.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Admin(UserMixin, db.Model):
    """Администратор салона — единственный, кто может зайти в админку."""
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # В базе хранится НЕ пароль, а его хеш. Даже если базу украдут,
    # достать исходные пароли из хешей нельзя.
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Booking(db.Model):
    """Заявка на запись, оставленная гостем через форму на сайте."""
    __tablename__ = "bookings"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=False)
    service = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default="new", nullable=False)  # new / done
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
