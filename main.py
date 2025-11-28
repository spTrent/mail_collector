import email
import email.utils
import imaplib
import os
import re
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


app = FastAPI(
    title='Email API',
    description='API для отправки и получения email',
    version='0.1.0',
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


class EmailItem(BaseModel):
    subject: str
    preview: str
    type: str
    sender: str
    date: str
    body: str

    class Config:
        json_schema_extra = {
            'example': {
                'subject': 'Quarterly Review Meeting - Scheduling',
                'preview': "It's time for our quarterly business review!...",
                'type': 'Corporate',
                'sender': 'Lisa Johnson (lisa.johnson@company.com)',
                'date': 'Nov 25, 2025 at 4:50 PM',
                'body': "Hi team,\n\nIt's time for our quarterly...",
            }
        }


class EmailListResponse(BaseModel):
    items: list[EmailItem]
    next_offset: int | None


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
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.login(EMAIL_LOGIN, EMAIL_PASSWORD)
            server.send_message(msg)

    except smtplib.SMTPAuthenticationError as e:
        raise Exception(f'Ошибка аутентификации SMTP: {str(e)}') from e

    except smtplib.SMTPException as e:
        raise Exception(f'Ошибка SMTP: {str(e)}') from e

    except Exception as e:
        raise Exception(f'Ошибка отправки email: {str(e)}') from e


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


def classify_email_type(subject: str, from_addr: str, body: str) -> str:
    """
    Классифицирует письмо по типу на основе содержимого.

    Args:
        subject: Тема письма
        from_addr: Адрес отправителя
        body: Текст письма

    Returns:
        Тип письма: 'Corporate', 'Personal', 'Newsletter', 'Notification'
    """
    subject_lower = subject.lower()
    body_lower = body.lower()

    corporate_keywords = [
        'meeting',
        'review',
        'team',
        'project',
        'deadline',
        'schedule',
        'conference',
        'report',
        'presentation',
        'budget',
        'quarter',
    ]
    if any(
        kw in subject_lower or kw in body_lower for kw in corporate_keywords
    ):
        return 'Corporate'

    newsletter_keywords = [
        'unsubscribe',
        'newsletter',
        'subscription',
        'mailing list',
    ]
    if any(kw in body_lower for kw in newsletter_keywords):
        return 'Newsletter'

    notification_keywords = [
        'notification',
        'alert',
        'reminder',
        'confirm',
        'verify',
    ]
    if any(kw in subject_lower for kw in notification_keywords):
        return 'Notification'

    return 'Personal'


def format_email_date(date_str: str) -> str:
    """
    Форматирует дату письма в человекочитаемый формат.

    Args:
        date_str: Дата в формате RFC 2822

    Returns:
        Дата в формате "Nov 25, 2025 at 4:50 PM"
    """
    try:
        date_tuple = email.utils.parsedate_to_datetime(date_str)
        return date_tuple.strftime('%b %d, %Y at %I:%M %p')
    except Exception:
        return date_str


def format_sender(from_addr: str) -> str:
    """
    Форматирует адрес отправителя в формат "Name (email@example.com)".

    Args:
        from_addr: Адрес в формате "Name <email>" или просто "email"

    Returns:
        Отформатированный адрес
    """
    match = re.match(r'(.+?)\s*<(.+?)>', from_addr)

    if match:
        name = match.group(1).strip().strip('"')
        email_addr = match.group(2).strip()
        return f'{name} ({email_addr})'
    else:
        return from_addr


def fetch_emails(offset: int = 0, limit: int = 20) -> list[dict]:
    """
    Получение списка писем из INBOX через IMAP.

    Args:
        offset: Смещение для пагинации (с какого письма начать)
        limit: Количество писем для возврата

    Returns:
        Список словарей с полями: subject, preview, type, sender, date, body
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

            subject = decode_email_header(msg.get('Subject', '(No Subject)'))
            from_addr = decode_email_header(msg.get('From', ''))
            date_str = msg.get('Date', '')

            body = get_email_body(msg)

            preview = body[:150] + '...' if len(body) > 150 else body
            preview = preview.replace('\n', ' ').replace('\r', ' ')

            email_type = classify_email_type(subject, from_addr, body)

            formatted_date = format_email_date(date_str)

            sender = format_sender(from_addr)

            emails.append(
                {
                    'subject': subject,
                    'preview': preview,
                    'type': email_type,
                    'sender': sender,
                    'date': formatted_date,
                    'body': body,
                }
            )

        mail.close()
        mail.logout()

        return emails

    except imaplib.IMAP4.error as e:
        raise Exception(f'Ошибка IMAP: {str(e)}') from e

    except Exception as e:
        raise Exception(f'Ошибка получения писем: {str(e)}') from e


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


@app.get(
    '/emails/',
    response_model=EmailListResponse,
    responses={
        500: {'model': ErrorResponse, 'description': 'Ошибка получения писем'}
    },
)
def get_emails(offset: int = 0) -> dict:
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
