from celery import shared_task
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.conf import settings


@shared_task(bind=True)
def auth_send_email(self, username, email,  uid=None, token=None, valid_until=None, html_for=None, otp=None):
    print('task', valid_until)
    subject = 'Account Verification Email'
    emailcontext = {
        'username': username,
        'uid': uid,
        'token': token,
        'valid_until': valid_until,
        'domain': settings.CORS_ALLOWED_ORIGINS[0]
    }

    if html_for == 'reset-password':
        subject = 'Password Reset Request'
        message = render_to_string('reset-password.html', emailcontext)

    elif html_for == 'reset-success':
        subject = 'Confirmation of Password Change'
        message = render_to_string('reset-success.html', emailcontext)

    else:
        emailcontext['otp'] = otp
        message = render_to_string('sign-up.html', emailcontext)

    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email,]

    email = EmailMessage(subject, message, from_email, recipient_list)
    email.content_subtype = 'html'
    email.send(fail_silently=True)
