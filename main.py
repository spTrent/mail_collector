import os
import smtplib
from email.message import EmailMessage
from typing import cast

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

load_dotenv()

EMAIL_LOGIN = cast(str, os.getenv('EMAIL_LOGIN'))
EMAIL_PASSWORD = cast(str, os.getenv('EMAIL_PASSWORD'))

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.yandex.ru')
SMTP_PORT = int(os.getenv('SMTP_PORT', '465'))

IMAP_HOST = os.getenv('IMAP_HOST', 'imap.yandex.ru')
IMAP_PORT = int(os.getenv('IMAP_PORT', '993'))

load_dotenv()

app = FastAPI(
    title='Email API',
    description='API для отправки и получения email',
    version='0.0.1',
)


class EmailSendRequest(BaseModel):
    to: EmailStr
    subject: str
    text: str

    class Config:
        json_schema_extra = {
            'example': {
                'to': 'Cla.07@yandex.ru',
                'subject': 'Тестовое письмо',
                'text': 'Это текстовая версия письма',
            }
        }


class EmailSendResponse(BaseModel):
    status: str
    message: str

    class Config:
        json_schema_extra = {
            'example': {
                'status': 'ok',
                'message': 'Email успешно отправлен на recipient@example.com',
            }
        }


class ErrorResponse(BaseModel):
    detail: str

    class Config:
        json_schema_extra = {
            'example': {'detail': 'Не удалось отправить email: Ошибка SMTP'}
        }


def send_email_smtp(to: str, subject: str, text: str) -> None:
    """
    Отправка email через SMTP сервер Яндекса.

    Args:
        to: Email адрес получателя
        subject: Тема письма
        text: Текстовое содержимое письма

    Raises:
        smtplib.SMTPAuthenticationError: Ошибка аутентификации
        smtplib.SMTPException: Другие SMTP ошибки
        Exception: Общие ошибки подключения
    """
    try:
        msg = EmailMessage()
        msg['From'] = EMAIL_LOGIN
        msg['To'] = to
        msg['Subject'] = subject
        msg.set_content(text)
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(EMAIL_LOGIN, EMAIL_PASSWORD)
            server.send_message(msg)

    except smtplib.SMTPAuthenticationError as e:
        raise Exception(f'Ошибка аутентификации SMTP: {str(e)}') from e

    except smtplib.SMTPException as e:
        raise Exception(f'Ошибка SMTP: {str(e)}') from e

    except Exception as e:
        raise Exception(f'Ошибка отправки email: {str(e)}') from e


@app.get('/ping')
def ping() -> dict[str, str]:
    """
    Тестовый эндпоинт для проверки, что сервер работает.
    """
    return {'message': 'pong'}


@app.post(
    '/send/',
    response_model=EmailSendResponse,
    responses={
        500: {'model': ErrorResponse, 'description': 'Ошибка отправки email'}
    },
)
def send_email(request: EmailSendRequest) -> dict[str, str]:
    """
    Отправка email письма.

    Принимает JSON с полями:
    - to: email адрес получателя
    - subject: тема письма
    - text: текст письма
    """
    try:
        send_email_smtp(request.to, request.subject, request.text)
        return {
            'status': 'ok',
            'message': f'Email успешно отправлен на {request.to}',
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f'Не удалось отправить email: {str(e)}'
        ) from e


# if __name__ == "__main__":
#     main()
