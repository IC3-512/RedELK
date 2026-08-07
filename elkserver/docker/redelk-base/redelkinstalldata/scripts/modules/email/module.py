#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This connector sends RedELK alerts via e-mail.

Reworked for v3. Three things kept this from working out of the box:

  * It always called starttls() and login(). The SMTP relay most teams point RedELK at - and the
    port 25 default in redelk.yml - offers neither, so every alarm died with an SMTPNotSupported
    or SMTPSenderRefused exception. notifications.email.smtp.tls (starttls | ssl | none) now
    decides, and login() only happens when a username is configured.
  * No timeout anywhere. smtplib blocks on connect and on every command, and the daemon holds a
    lock file while it does, so one unreachable relay stopped all alarming.
  * Every value went into the HTML unescaped. Redirector traffic is attacker controlled: whoever
    scans the redirector chooses the User-Agent, and therefore chose what RedELK rendered in the
    red team's mail client.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import logging
import os
import smtplib
from email.header import Header
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

from config import notifications, project_name
from modules.helpers import HTTP_TIMEOUT
from modules.notify_common import escape_html, more_line, summarise, truncate

info = {
    "version": 0.2,
    "name": "email connector",
    "description": "This connector sends RedELK alerts via email",
    "type": "redelk_connector",
    "submodule": "email",
}

FILEDIR = os.path.abspath(os.path.dirname(__file__))
LOGO_PATH = os.path.join(FILEDIR, "redelk_white.png")

# Mail is the one channel with no hard platform limit, but nobody reads a 40 MB table and some
# relays reject one. Keep it generous and say what was left out.
MAX_ITEMS = 200
MAX_FIELD_CHARS = 2000

TLS_MODES = ("starttls", "ssl", "none")


class Module:
    """email connector module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    # ----------------------------------------------------------------------------------------
    # Sending
    # ----------------------------------------------------------------------------------------

    def send_alarm(self, alarm):
        """Send the alarm. Raises on any delivery failure so daemon.py can retry it next run."""
        summary = summarise(
            alarm, project_name, max_items=MAX_ITEMS, max_field_chars=MAX_FIELD_CHARS
        )
        email_config = notifications.get("email", {})
        recipients = [str(address) for address in email_config.get("to", []) if address]
        if not recipients:
            raise ValueError("e-mail notifications are enabled but no recipients are configured")

        logo_cid = make_msgid(domain="redelk.local")
        logo = self.read_logo()
        html = self.render(summary, logo_cid if logo else None)

        message = self.build_message(
            recipients=recipients,
            from_address=str(email_config.get("from", "")),
            subject=summary.subject,
            html=html,
            logo=logo,
            logo_cid=logo_cid,
        )
        self.deliver(message, recipients, email_config)

    def build_message(self, recipients, from_address, subject, html, logo, logo_cid):
        """Build the multipart/related message: the HTML body plus the inline logo."""
        message = MIMEMultipart("related")
        # A newline in the subject would let alarm content inject extra headers.
        clean_subject = f"[{project_name}] {subject}".replace("\r", " ").replace("\n", " ")
        message["Subject"] = str(Header(clean_subject, "utf-8"))
        message["From"] = formataddr((str(Header(from_address, "utf-8")), from_address))
        message["To"] = ", ".join(recipients)
        message["Date"] = formatdate()
        message.attach(MIMEText(html, "html", "utf-8"))

        if logo:
            # Inline via Content-ID rather than a data: URI - most mail clients refuse to render
            # data: images, so the old layout showed a broken image everywhere.
            image = MIMEImage(logo, _subtype="png")
            image.add_header("Content-ID", logo_cid)
            image.add_header("Content-Disposition", "inline", filename="redelk.png")
            message.attach(image)
        return message

    def deliver(self, message, recipients, email_config):
        """Open the SMTP connection according to the configured TLS mode and send the message."""
        smtp_config = email_config.get("smtp", {})
        host = str(smtp_config.get("host", "localhost"))
        try:
            port = int(smtp_config.get("port", 25))
        except (TypeError, ValueError):
            port = 25

        tls_mode = str(smtp_config.get("tls", "starttls")).lower()
        if tls_mode not in TLS_MODES:
            self.logger.warning(
                "unknown smtp tls mode %r, falling back to starttls (valid: %s)",
                tls_mode,
                ", ".join(TLS_MODES),
            )
            tls_mode = "starttls"

        username = str(smtp_config.get("login", "") or "")
        password = str(smtp_config.get("pass", "") or "")
        from_address = str(email_config.get("from", ""))

        # Implicit TLS wants a different class, so pick it before connecting.
        connect = smtplib.SMTP_SSL if tls_mode == "ssl" else smtplib.SMTP
        connection = connect(host, port, timeout=HTTP_TIMEOUT)
        try:
            if tls_mode == "starttls":
                connection.starttls()
                # RFC 3207: everything the server advertised before STARTTLS is void.
                connection.ehlo()
            if username:
                connection.login(username, password)
            refused = connection.sendmail(from_address, recipients, message.as_string())
            if refused:
                # sendmail() only raises when every recipient is refused.
                self.logger.error("the relay refused some recipients: %s", sorted(refused))
        finally:
            try:
                connection.quit()
            except smtplib.SMTPException:
                # The message is already on its way; a rude close is not worth failing the alarm.
                connection.close()

    def read_logo(self):
        """Read the RedELK logo, or None. A missing logo must not cost us the notification."""
        try:
            with open(LOGO_PATH, "rb") as logo_file:
                return logo_file.read()
        except OSError as error:
            self.logger.warning("could not read the RedELK logo %s: %s", LOGO_PATH, error)
            return None

    # ----------------------------------------------------------------------------------------
    # Rendering
    # ----------------------------------------------------------------------------------------

    def render(self, summary, logo_cid):
        """Render the alarm as an HTML document. Every interpolated value is escaped."""
        logo_cell = ""
        if logo_cid:
            # make_msgid() returns <...>; the cid: URL uses the id without the angle brackets.
            logo_cell = (
                f'<img height="60px" src="cid:{escape_html(logo_cid.strip("<>"))}" alt="RedELK" />'
            )

        head = f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>Alarm from RedELK</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    </head>
<body style="margin: 0; padding: 0;">
    <table align="center" cellpadding="0" cellspacing="0" width="800" style="border-collapse: collapse; max-width:800px;">
    <tr>
        <td bgcolor="#212121" rowspan=2 width="120px" style="padding: 30px 30px 30px 30px; text-align:center;">
            {logo_cell}
        </td>
        <td bgcolor="#212121" height="30px" style="color: #FAFAFA; font-family: Arial, sans-serif; font-size: 24px; padding: 30px 30px 0px 10px;">
            RedELK alarm: <em>{escape_html(summary.name)}</em>
        </td>
    </tr>
    <tr>
        <td bgcolor="#212121" height="20px" style="color: #FAFAFA; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px; padding: 20px 30px 30px 10px;">
            Project: <em>{escape_html(summary.project)}</em><br/>Total hits: <em>{summary.total}</em>
        </td>
    </tr>
    <tr>
        <td colspan=2 style="color: #153643; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px; padding: 0px 30px 0px 10px;">
            <p>{escape_html(summary.description)}</p>
        </td>
    </tr>
"""

        parts = [head]
        if summary.group_note:
            parts.append(
                '<tr><td colspan=2 style="color: #153643; font-family: Arial, sans-serif; '
                'font-size: 12px; line-height: 16px; padding: 0px 15px 0px 15px;">'
                f"<p>{escape_html(summary.group_note)}</p></td></tr>\n"
            )

        for item in summary.items:
            parts.append(self.render_item(item))

        if summary.omitted:
            parts.append(
                '<tr><td colspan=2 style="color: #153643; font-family: Arial, sans-serif; '
                'font-size: 12px; padding: 10px 15px 10px 15px;">'
                f"<p>{escape_html(more_line(summary.omitted))}</p></td></tr>\n"
            )

        parts.append("</table>\n</body>\n</html>\n")
        return "".join(parts)

    def render_item(self, item):  # pylint: disable=no-self-use
        """One alarm item as a title row followed by one row per field."""
        title = escape_html(truncate(item.title, 300))
        if item.more_like_this:
            title += f" <small>({escape_html(item.more_like_this)})</small>"

        rows = [
            '<tr><td bgcolor="#323232" colspan=2 style="color: #FAFAFA; font-family: Arial, '
            "sans-serif; font-size: 16px; line-height: 20px; padding: 10px 10px 10px 10px; "
            f'text-align:center;"><b>{title}</b></td></tr>\n'
        ]
        for row, (name, value) in enumerate(item.fields):
            bgcolor = "#FAFAFA" if row % 2 == 0 else "#F1F1F1"
            rows.append(
                f'<tr bgcolor="{bgcolor}" style="color: #153643; font-family: Arial, sans-serif; '
                'font-size: 12px; line-height: 16px;">'
                f'<td style="padding: 10px 10px 10px 10px;"><b>{escape_html(name)}</b></td>'
                '<td style="padding: 10px 10px 10px 10px; white-space:pre-wrap; '
                f'word-wrap:break-word">{escape_html(value)}</td></tr>\n'
            )
        rows.append('<tr><td colspan=2 style="padding: 15px;">&nbsp;</td></tr>\n')
        return "".join(rows)
