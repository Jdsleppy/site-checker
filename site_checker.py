#!/usr/bin/env python3

import datetime as dt
import requests
import smtplib
import socket
import ssl


class SiteCheckException(Exception):

    def __init__(self, message):
        self.message = message


class SslCertException(SiteCheckException):
    pass


class PingException(SiteCheckException):
    pass


def ping(hostname):
    print(
        "Pinging {hostname}..."
        .format(hostname=hostname)
    )

    r = requests.get("https://{hostname}".format(hostname=hostname))
    if r.status_code != requests.codes.ok:
        raise PingException(
            "Pinged https://{hostname} but got response status {status}"
            .format(
                hostname=hostname,
                status=r.status_code,
            )
        )


def check_ssl_cert_expiry(hostname):
    print(
        "Checking SSL cert expiration for {hostname}..."
        .format(hostname=hostname)
    )

    context = ssl.create_default_context()
    connection = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname
    )
    connection.connect((hostname, 443))

    cert = connection.getpeercert()

    not_before_timestamp = ssl.cert_time_to_seconds(cert['notBefore'])
    not_before = dt.datetime.utcfromtimestamp(not_before_timestamp)

    not_after_timestamp = ssl.cert_time_to_seconds(cert['notAfter'])
    not_after = dt.datetime.utcfromtimestamp(not_after_timestamp)

    now = dt.datetime.now()

    if not_before > now:
        raise SslCertException(
            "Cert is not valid yet. NotBefore: {not_before}"
            .format(not_before=not_before)
        )

    if not_after < now:
        raise SslCertException(
            "Cert is expired. NotAfter: {not_after}"
            .format(not_after=not_after)
        )

    days_valid = (not_after - now).days
    if days_valid <= 10:
        raise SslCertException(
            "Cert will expire in {days_valid} days."
            .format(days_valid=days_valid)
        )


def notify_errors(errors):
    with smtplib.SMTP("mail.server.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login("username@domain.com", "password")
        body = "\r\n".join([
            "To: to@receiver.com",
            "From: from@sender.com",
            "Subject: Site checking errors",
            "",
            "Hi Yourname!\r\n" +
            "The following errors were found on your sites:\r\n\r\n" +
            "\r\n".join(errors),
        ])
        server.sendmail(
            "from@sender.com",
            ["to@receiver.com"],
            body
        )

if __name__ == "__main__":
    errors = []
    with open("sites") as f:
        stripped_lines = (
            line.strip()
            for line in f
        )
        hostnames = [
            line
            for line in stripped_lines
            if line
        ]
        for operation in (ping, check_ssl_cert_expiry):
            for hostname in hostnames:
                try:
                    operation(hostname)

                except Exception as e:
                    errors.append(
                        "{hostname}: {type} -- {message}"
                        .format(
                            hostname=hostname,
                            type=type(e).__name__,
                            message=(
                                e.message if hasattr(e, "message")
                                else str(e)
                            ),
                        )
                    )
    if errors:
        for error in errors:
            print(error)
        notify_errors(errors)
    else:
        print("No problems!")

