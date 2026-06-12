"""
Формы на основе Flask-WTF.

Зачем это для безопасности:
1. CSRF-защита включается автоматически — каждая форма получает скрытый
   токен, и без него POST-запрос отклоняется. Это защищает от того, чтобы
   чужой сайт отправил запрос от имени залогиненного пользователя.
2. Валидация на сервере. Никогда нельзя доверять данным из браузера —
   проверку длины, формата и обязательности полей делаем здесь, на сервере,
   а не только в HTML.
"""
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp

SERVICES = [
    "Мужская стрижка",
    "Стрижка + борода",
    "Бритьё бритвой",
    "Коррекция бороды",
    "Камуфляж седины",
    "Детская стрижка",
]


class BookingForm(FlaskForm):
    name = StringField(
        "Имя",
        validators=[DataRequired(message="Укажите имя"),
                    Length(min=2, max=120, message="Имя слишком короткое")],
    )
    phone = StringField(
        "Телефон",
        validators=[
            DataRequired(message="Укажите телефон"),
            Length(min=5, max=40),
            # Разрешаем только цифры и символы телефона — отсекаем мусор и попытки
            # вставить в поле что-то постороннее.
            Regexp(r"^[\d\s\+\-\(\)]+$", message="Телефон в неверном формате"),
        ],
    )
    service = SelectField(
        "Услуга",
        choices=[(s, s) for s in SERVICES],
        validators=[DataRequired()],
    )


class LoginForm(FlaskForm):
    username = StringField("Логин", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Пароль", validators=[DataRequired()])
