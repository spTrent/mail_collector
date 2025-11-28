import email
import imaplib
import os
import smtplib
from email.header import decode_header
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


def decode_email_header(header: str | None) -> str:
    """
    Декодирует заголовок email (может быть в разных кодировках).

    Args:
        header: Закодированный заголовок

    Returns:
        Декодированная строка
    """
    if not header:
        return ''

    decoded_parts = decode_header(header)
    decoded_string = ''

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
        else:
            decoded_string += part

    return decoded_string


def get_email_body(msg: email.message.Message) -> str:
    """
    Извлекает текстовое содержимое письма.

    Args:
        msg: Объект email.message.Message

    Returns:
        Текст письма
    """
    body = ''

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))

            if (
                content_type == 'text/plain'
                and 'attachment' not in content_disposition
            ):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        body = payload.decode(charset, errors='ignore')
                        break
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='ignore')
        except Exception:
            body = str(msg.get_payload())
    return body.strip()


def fetch_emails(offset: int = 0, limit: int = 20) -> list[dict[str, str]]:
    """
    Получение списка писем из INBOX через IMAP.

    Args:
        offset: Смещение для пагинации (с какого письма начать)
        limit: Количество писем для возврата

    Returns:
        Список словарей с полями: id, from, subject, date, snippet
    """
    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)

        mail.login(EMAIL_LOGIN, EMAIL_PASSWORD)

        mail.select('INBOX')

        status, messages = mail.search(None, 'ALL')

        if status != 'OK':
            raise Exception('Не удалось получить список писем')

        email_ids = messages[0].split()

        email_ids = email_ids[::-1]

        start = offset
        end = offset + limit
        email_ids_page = email_ids[start:end]

        emails = []

        for email_id in email_ids_page:
            status, msg_data = mail.fetch(email_id, '(RFC822)')

            if status != 'OK':
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = decode_email_header(msg.get('Subject', ''))
            from_addr = decode_email_header(msg.get('From', ''))
            date = msg.get('Date', '')

            body = get_email_body(msg)
            snippet = body[:200] if body else ''

            emails.append(
                {
                    'id': email_id.decode(),
                    'from': from_addr,
                    'subject': subject,
                    'date': date,
                    'snippet': snippet,
                }
            )

        mail.close()
        mail.logout()

        return emails

    except imaplib.IMAP4.error as e:
        raise Exception(f'Ошибка IMAP: {str(e)}') from e

    except Exception as e:
        raise Exception(f'Ошибка получения писем: {str(e)}') from e


class EmailListResponse(BaseModel):
    items: list[dict[str, str]]
    next_offset: int | None


@app.get(
    '/emails/',
    response_model=EmailListResponse,
    responses={
        500: {'model': ErrorResponse, 'description': 'Ошибка получения писем'}
    },
)
def get_emails(
    offset: int = 0,
) -> dict[str, list[dict[str, str]] | int | None]:
    """
    Получение списка писем из почтового ящика.

    Args:
        offset: Смещение для пагинации (по умолчанию 0)

    Returns:
        Список писем и смещение для следующей страницы
    """
    try:
        limit = 20
        emails = fetch_emails(offset, limit)
        next_offset = offset + limit if len(emails) == limit else None
        return {'items': emails, 'next_offset': next_offset}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f'Не удалось получить письма: {str(e)}'
        ) from e


# if __name__ == "__main__":
#     main()
