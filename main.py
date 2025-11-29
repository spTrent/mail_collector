import base64
import email
import email.utils
import imaplib
import os
import re
import smtplib
from email.header import decode_header
from email.message import EmailMessage
from typing import cast

from bs4 import BeautifulSoup
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
    to: EmailStr | list[EmailStr]
    subject: str
    text: str
    cc: list[EmailStr] | None = None
    bcc: list[EmailStr] | None = None

    class Config:
        json_schema_extra = {
            'example': {
                'to': ['user1@example.com', 'user2@example.com'],
                'subject': 'Массовая рассылка',
                'text': 'Это письмо отправлено нескольким получателям',
                'cc': ['manager@example.com'],
                'bcc': ['archive@example.com'],
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
    html_body: str | None = None
    attachments: list[dict] = []


class EmailListResponse(BaseModel):
    items: list[EmailItem]
    next_offset: int | None


class ErrorResponse(BaseModel):
    detail: str

    class Config:
        json_schema_extra = {
            'example': {'detail': 'Не удалось отправить email: Ошибка SMTP'}
        }


def html_to_text(html: str) -> str:
    """Конвертирует HTML в чистый текст без тегов."""
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup(['script', 'style']):
            script.decompose()

        text = soup.get_text(separator=' ', strip=True)

        text = re.sub(r'\s+', ' ', text).strip()

        return text
    except Exception:
        clean = re.sub(
            r'<style[^>]*>.*?</style>',
            '',
            html,
            flags=re.DOTALL | re.IGNORECASE,
        )
        clean = re.sub(
            r'<script[^>]*>.*?</script>',
            '',
            clean,
            flags=re.DOTALL | re.IGNORECASE,
        )
        clean = re.sub(r'<[^>]+>', '', clean)
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean


def send_email_smtp(
    to: str | list[str],
    subject: str,
    text: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
) -> None:
    """
    Отправка email через SMTP сервер Яндекса.

    Args:
        to: Email адрес получателя или список адресов
        subject: Тема письма
        text: Текстовое содержимое письма
        cc: Список адресов для копии (необязательно)
        bcc: Список адресов для скрытой копии (необязательно)

    Raises:
        smtplib.SMTPAuthenticationError: Ошибка аутентификации
        smtplib.SMTPException: Другие SMTP ошибки
        Exception: Общие ошибки подключения
    """
    try:
        msg = EmailMessage()
        msg['From'] = EMAIL_LOGIN
        msg['Subject'] = subject
        msg.set_content(text)
        if isinstance(to, str):
            to = [to]
        msg['To'] = ', '.join(to)
        if cc:
            msg['Cc'] = ', '.join(cc)
        all_recipients = to.copy()
        if cc:
            all_recipients.extend(cc)
        if bcc:
            all_recipients.extend(bcc)
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.login(EMAIL_LOGIN, EMAIL_PASSWORD)
            server.send_message(msg, to_addrs=all_recipients)

    except smtplib.SMTPAuthenticationError as e:
        raise Exception(f'Ошибка аутентификации SMTP: {str(e)}') from e

    except smtplib.SMTPException as e:
        raise Exception(f'Ошибка SMTP: {str(e)}') from e

    except Exception as e:
        raise Exception(f'Ошибка отправки email: {str(e)}') from e


def classify_email_type(subject: str, from_addr: str, body: str) -> str:
    """
    Классифицирует письмо по типу на основе подсчёта ключевых слов.

    Args:
        subject: Тема письма
        from_addr: Адрес отправителя
        body: Текст письма

    Returns:
        Тип письма с максимальным количеством совпадений
    """
    subject_lower = subject.lower()
    body_lower = body.lower()
    from_lower = from_addr.lower()

    scores = {
        'regulatory_request': 0,
        'complaint': 0,
        'approval_request': 0,
        'information_request': 0,
        'partnership_proposal': 0,
        'notification': 0,
    }

    regulatory_keywords = [
        'предписание',
        'регулятор',
        'надзор',
        'проверка',
        'запрос информации',
        'в соответствии с законом',
        'предоставить сведения',
        'федеральный закон',
        'постановление',
        'контрольно-надзорный',
        'инспекция',
        'административное производство',
    ]
    for keyword in regulatory_keywords:
        if keyword in subject_lower or keyword in body_lower:
            scores['regulatory_request'] += 2

    regulatory_domains = [
        'gov.ru',
        'cbr.ru',
        'genproc.gov.ru',
        'rospotrebnadzor.ru',
        'nalog.ru',
        'rosfinnadzor.ru',
        'fsb.ru',
        'mvd.ru',
    ]
    if any(domain in from_lower for domain in regulatory_domains):
        scores['regulatory_request'] += 10

    complaint_keywords = [
        'жалоба',
        'претензия',
        'недовольство',
        'возмущен',
        'возмущена',
        'требую',
        'нарушение',
        'обман',
        'некачественно',
        'прошу разобраться',
        'прошу вернуть',
        'возврат средств',
        'безобразие',
        'ужасный сервис',
        'отвратительно',
        'неудовлетворительно',
        'требую компенсацию',
        'обратитесь к руководству',
    ]
    for keyword in complaint_keywords:
        if keyword in subject_lower:
            scores['complaint'] += 3
        if keyword in body_lower:
            scores['complaint'] += 2

    approval_keywords = [
        'согласование',
        'утверждение',
        'одобрение',
        'согласовать',
        'утвердить',
        'подпись',
        'визирование',
        'прошу согласовать',
        'прошу утвердить',
        'на согласование',
        'для утверждения',
        'подписать',
        'виза',
        'согласующий',
        'требуется согласование',
        'для визирования',
        'на подпись',
    ]
    for keyword in approval_keywords:
        if keyword in subject_lower or keyword in body_lower:
            scores['approval_request'] += 2

    info_keywords = [
        'запрос',
        'предоставьте',
        'нужна информация',
        'документы',
        'справка',
        'выписка',
        'копия',
        'подтверждение',
        'можете ли предоставить',
        'прошу выслать',
        'прошу направить',
        'можете ли',
        'могли бы',
        'когда будет',
        'где находится',
        'как получить',
        'сколько стоит',
        'прошу сообщить',
        'уточните',
        'разъясните',
    ]
    for keyword in info_keywords:
        if keyword in subject_lower or keyword in body_lower:
            scores['information_request'] += 1

    if '?' in subject or '?' in body:
        scores['information_request'] += 1

    partnership_keywords = [
        'партнёрство',
        'сотрудничество',
        'коммерческое предложение',
        'кп',
        'предлагаем сотрудничество',
        'готовы предложить',
        'взаимовыгодное',
        'совместный проект',
        'стать партнером',
        'деловое предложение',
        'рады предложить',
        'заинтересованы в сотрудничестве',
        'бизнес-предложение',
    ]
    for keyword in partnership_keywords:
        if keyword in subject_lower or keyword in body_lower:
            scores['partnership_proposal'] += 2

    notification_keywords = [
        'уведомление',
        'напоминание',
        'информируем',
        'сообщаем',
        'автоматическое письмо',
        'отписаться',
        'рассылка',
        'подписка',
        'не отвечайте на это письмо',
        'автоматическая рассылка',
    ]
    for keyword in notification_keywords:
        if keyword in subject_lower:
            scores['notification'] += 2
        if keyword in body_lower:
            scores['notification'] += 1

    if (
        'noreply' in from_lower
        or 'no-reply' in from_lower
        or 'donotreply' in from_lower
    ):
        scores['notification'] += 5

    max_score = max(scores.values())

    if max_score == 0:
        return 'information_request'

    for email_type, score in scores.items():
        if score == max_score:
            return email_type

    return 'information_request'


def parse_email_parts(msg: email.message.Message) -> dict:
    """
    Парсит все части письма: текст, HTML, вложения и изображения.
    """
    body = ''
    html_body = None
    attachments = []

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
                        body += payload.decode(charset, errors='ignore')
                except Exception:
                    continue

            elif (
                content_type == 'text/html'
                and 'attachment' not in content_disposition
            ):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        if html_body is None:
                            html_body = ''
                        html_body += payload.decode(charset, errors='ignore')
                except Exception:
                    continue

            elif content_disposition and (
                'inline' in content_disposition
                or 'attachment' in content_disposition
            ):
                try:
                    filename = part.get_filename()
                    if not filename:
                        content_id = part.get('Content-ID', '')
                        if content_id:
                            filename = f'image_{content_id.strip("<>")}.png'
                        else:
                            ext = (
                                content_type.split('/')[-1]
                                if '/' in content_type
                                else 'bin'
                            )
                            filename = f'attachment.{ext}'
                    else:
                        filename = decode_email_header(filename)

                    file_data = part.get_payload(decode=True)
                    if file_data:
                        attachments.append(
                            {
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(file_data),
                                'data': base64.b64encode(file_data).decode(
                                    'utf-8'
                                ),
                                'is_inline': 'inline' in content_disposition,
                            }
                        )
                except Exception:
                    continue
    else:
        try:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                decoded = payload.decode(charset, errors='ignore')

                if content_type == 'text/html':
                    html_body = decoded
                else:
                    body = decoded
        except Exception:
            body = str(msg.get_payload())

    if not body and html_body:
        body = html_to_text(html_body)

    return {
        'body': body.strip(),
        'html_body': html_body,
        'attachments': attachments,
    }


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
    Получение списка писем из INBOX через IMAP с вложениями.
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

            parsed_parts = parse_email_parts(msg)

            body = parsed_parts['body']
            html_body = parsed_parts['html_body']
            attachments = parsed_parts['attachments']

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
                    'html_body': html_body,
                    'attachments': attachments,
                    'attachments_count': len(attachments),
                }
            )

        mail.close()
        mail.logout()

        return emails

    except imaplib.IMAP4.error as e:
        raise Exception(f'Ошибка IMAP: {str(e)}') from e

    except Exception as e:
        raise Exception(f'Ошибка получения писем: {str(e)}') from e


@app.post(
    '/send/',
    response_model=EmailSendResponse,
    responses={
        500: {'model': ErrorResponse, 'description': 'Ошибка отправки email'}
    },
)
def send_email(request: EmailSendRequest) -> dict[str, str]:
    """
    Отправка email письма одному или нескольким получателям.

    Принимает JSON с полями:
    - to: email адрес получателя или список адресов
    - subject: тема письма
    - text: текст письма
    - cc: список адресов для копии (необязательно)
    - bcc: список адресов для скрытой копии (необязательно)
    """
    try:
        send_email_smtp(
            request.to, request.subject, request.text, request.cc, request.bcc
        )

        recipient_cnt = len(request.to) if isinstance(request.to, list) else 1
        return {
            'status': 'ok',
            'message': f'Email успешно отправлен {recipient_cnt} получателям',
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
